"""Base class for all platform integration clients."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from urllib.parse import quote

logger = logging.getLogger("cane_ai.integrations")


def seg(value: Any) -> str:
    """Encode a value for use as ONE URL path segment.

    Targets (machine IDs, user names, domains) come from analysts and from AI
    recommendations. Unencoded, a value such as `abc/unisolate?` or `a/../../groups/x`
    would change which API endpoint gets called."""
    return quote(str(value), safe="")


@dataclass
class NotificationEvent:
    """Something worth telling people about, in a form every notifier can render."""
    kind: str                 # incident_opened | action_pending | triage_failed | incident_escalated | incident_closed
    title: str                # one line, e.g. "Critical incident: Ransomware Activity Detected"
    summary: str              # one or two sentences of plain text
    severity: str             # critical | high | medium | low | info
    incident_id: str
    incident_url: str         # deep link into the Cane AI UI
    fields: dict[str, str] = field(default_factory=dict)   # extra label -> value pairs to show
    action_id: str | None = None                           # set for action_pending


class BaseIntegrationClient(ABC):
    """Abstract base class for platform integrations.

    A connector declares what it can do through class attributes, and the platform
    routes work to every active integration that declares the matching ability:

    actions           response actions it can execute. Maps the platform-wide action
                      type to the name of the method implementing it, for example
                      {"block_ip": "block_ip", "isolate_host": "isolate_host"}.
                      Each method takes exactly the keyword argument listed for that
                      action in app.services.action_service.ACTION_PARAM_KEYS and
                      returns {"success": bool, "message": str, ...}.
    enriches          IOC kinds `enrich()` understands: "ip", "domain", "url", "file_hash".
    provides_context  entity kinds it can describe: "user" (describe_user), "host" (describe_host).
    category          response | enrichment | notification | ticketing | source | context.
                      Used to group connectors in the UI; a notifier implements notify(),
                      a ticketing connector the *_ticket methods, a source fetch_events().

    Dry run: when self.dry_run is true, anything that would CHANGE an external system
    (response actions, sending notifications, writing tickets) must not make the call
    and returns {"success": True, "dry_run": True, "message": "[DRY RUN] Would ..."}.
    Read-only calls (enrich, describe_*, fetch_events, test_connection) run normally.

    HTTP: always go through `await self.get_http_client()` so tests can substitute
    the transport. Put caller-supplied values into URL paths with `seg()`.
    """

    platform_name: str = ""
    display_name: str = ""
    description: str = ""
    auth_type: str = ""
    category: str = "response"
    required_credentials: list[str] = []
    optional_credentials: list[str] = []   # secrets that are allowed but not needed (e.g. a key that lifts a rate limit)
    optional_config: list[str] = []
    capabilities: list[str] = []
    actions: dict[str, str] = {}
    enriches: tuple[str, ...] = ()
    provides_context: tuple[str, ...] = ()

    def __init__(self, credentials: dict[str, Any], config: dict[str, Any] | None = None, dry_run: bool = False):
        self.credentials = credentials
        self.config = config or {}
        self.dry_run = dry_run
        self._http_client: httpx.AsyncClient | None = None
        self._access_token: str | None = None
        self._token_expires_at: float = 0

    async def get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Content-Type": "application/json"},
            )
        return self._http_client

    async def close(self):
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test the connection to the platform. Returns {"success": bool, "message": str}."""
        ...

    @abstractmethod
    async def get_health(self) -> dict:
        """Check current health of the integration."""
        ...

    # ---- optional abilities; override the ones the connector declares -------------

    async def enrich(self, kind: str, value: str) -> dict | None:
        """Look up one indicator. `kind` is one of self.enriches.
        Return None when the platform has nothing on it, otherwise a dict with at least:
          verdict  "malicious" | "suspicious" | "benign" | "unknown"
          summary  one plain sentence an analyst can read at a glance
        plus any platform-specific detail (scores, tags, country, first_seen...)."""
        raise NotImplementedError

    async def describe_user(self, user_principal_name: str) -> dict | None:
        """Who is this account? e.g. {display_name, job_title, department, manager,
        account_enabled, is_admin, last_sign_in}. None if unknown."""
        raise NotImplementedError

    async def describe_host(self, hostname: str) -> dict | None:
        """What is this machine? e.g. {device_id, os, owner, last_seen, is_isolated,
        risk, compliance}. None if unknown."""
        raise NotImplementedError

    async def notify(self, event: NotificationEvent) -> dict:
        """Deliver a notification. Returns {"success": bool, "message": str}."""
        raise NotImplementedError

    async def create_ticket(self, incident: dict) -> dict:
        """Open a ticket for an incident (keys: id, title, description, severity, status,
        attack_type, url). Returns {"success", "ticket_id", "ticket_url", "message"}."""
        raise NotImplementedError

    async def add_ticket_comment(self, ticket_id: str, text: str) -> dict:
        raise NotImplementedError

    async def close_ticket(self, ticket_id: str, resolution: str) -> dict:
        raise NotImplementedError

    async def fetch_events(self, since: datetime, limit: int = 500) -> list[dict]:
        """Pull new events from a log/alert source, oldest first, as ingest envelopes:
        [{"schemaId": "<one of the supported schema ids>", "data": {...}}].
        `data` must carry TimeGenerated (ISO 8601) and should carry CorrelationId when
        the source groups related events, so they correlate into one incident."""
        raise NotImplementedError

    def _log_action(self, action: str, params: dict):
        if self.dry_run:
            logger.info("[DRY RUN] %s.%s: %s", self.platform_name, action, params)
        else:
            logger.info("%s.%s: %s", self.platform_name, action, params)

    def _dry(self, what: str) -> dict:
        """Standard dry-run reply for a call that would change an external system."""
        return {"success": True, "dry_run": True, "message": f"[DRY RUN] Would {what}"}


class OAuth2ClientCredentialsMixin:
    """Mixin for OAuth2 client credentials flow (Microsoft APIs)."""

    token_url: str = ""

    async def _acquire_token(self) -> str:
        import time
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        client = await self.get_http_client()
        response = await client.post(
            self.token_url.format(tenant_id=self.credentials.get("tenant_id", "")),
            data={
                "grant_type": "client_credentials",
                "client_id": self.credentials["client_id"],
                "client_secret": self.credentials["client_secret"],
                "scope": self.credentials.get("scope", self._default_scope),
            },
            # The shared client defaults to JSON; a token request must say it is a form,
            # or the identity provider rejects it.
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        data = response.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3600)
        return self._access_token

    async def _auth_headers(self) -> dict:
        token = await self._acquire_token()
        return {"Authorization": f"Bearer {token}"}
