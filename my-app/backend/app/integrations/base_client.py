"""Base class for all platform integration clients."""

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger("cane_ai.integrations")


class BaseIntegrationClient(ABC):
    """Abstract base class for platform integrations."""

    platform_name: str = ""
    display_name: str = ""
    description: str = ""
    auth_type: str = ""
    required_credentials: list[str] = []
    optional_config: list[str] = []
    capabilities: list[str] = []

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

    def _log_action(self, action: str, params: dict):
        if self.dry_run:
            logger.info("[DRY RUN] %s.%s: %s", self.platform_name, action, params)
        else:
            logger.info("%s.%s: %s", self.platform_name, action, params)


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
        )
        response.raise_for_status()
        data = response.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3600)
        return self._access_token

    async def _auth_headers(self) -> dict:
        token = await self._acquire_token()
        return {"Authorization": f"Bearer {token}"}
