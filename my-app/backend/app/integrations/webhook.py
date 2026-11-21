"""Generic outgoing webhook: POST each notification as JSON to an admin-supplied URL."""

import dataclasses
import hashlib
import hmac
import json
import logging
from urllib.parse import urlsplit

import httpx

from app.integrations.base_client import BaseIntegrationClient, NotificationEvent

logger = logging.getLogger("cane_ai.integrations.webhook")

SIGNATURE_HEADER = "X-Cane-Signature"
_LOCAL_HOSTS = {"localhost", "127.0.0.1"}


def webhook_url_problem(url) -> str | None:
    """Why a webhook URL cannot be used, or None when it is acceptable.
    https:// is required; http:// is allowed only for localhost and 127.0.0.1."""
    if not url or not isinstance(url, str):
        return "Webhook URL is not configured"
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "Webhook URL is not a valid URL"
    if not host:
        return "Webhook URL is not a valid URL"
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and host in _LOCAL_HOSTS:
        return None
    return "Webhook URL must use https:// (http:// is allowed only for localhost)"


def sign_body(secret: str, body: bytes) -> str:
    """Value of the X-Cane-Signature header for a raw request body."""
    return "sha256=" + hmac.new(str(secret).encode("utf-8"), body, hashlib.sha256).hexdigest()


class GenericWebhookClient(BaseIntegrationClient):
    platform_name = "webhook"
    display_name = "Webhook"
    description = "Send incident notifications as signed JSON to any HTTPS endpoint"
    auth_type = "webhook"
    category = "notification"
    required_credentials = ["url"]
    optional_config = ["secret"]
    capabilities = ["notify"]

    async def test_connection(self) -> dict:
        # Only the URL is checked: posting a test event would trigger whatever the
        # receiving system does with events.
        problem = webhook_url_problem(self.credentials.get("url"))
        if problem:
            return {"success": False, "message": problem}
        return {
            "success": True,
            "message": "Webhook URL is valid. Delivery is confirmed by the first notification.",
        }

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    @staticmethod
    def build_body(event: NotificationEvent) -> bytes:
        """The exact bytes that are sent, and that the signature is computed over."""
        return json.dumps(dataclasses.asdict(event), separators=(",", ":"), default=str).encode("utf-8")

    async def notify(self, event: NotificationEvent) -> dict:
        self._log_action("notify", {"kind": event.kind, "incident_id": event.incident_id})
        url = self.credentials.get("url")
        problem = webhook_url_problem(url)
        if problem:
            return {"success": False, "message": problem}
        if self.dry_run:
            return self._dry(f"POST '{event.kind}' event to the webhook")

        body = self.build_body(event)
        headers = {"Content-Type": "application/json", "User-Agent": "Cane-AI-Webhook/1.0"}
        secret = self.config.get("secret")
        if secret:
            headers[SIGNATURE_HEADER] = sign_body(secret, body)

        # The URL may embed a token, so errors carry the status code or error type only.
        # Redirects are not followed: a redirect could lead to a URL that was never validated.
        client = await self.get_http_client()
        try:
            response = await client.post(url.strip(), content=body, headers=headers, follow_redirects=False)
        except httpx.HTTPError as e:
            return {"success": False, "message": f"Webhook delivery failed ({type(e).__name__})"}
        if not 200 <= response.status_code < 300:
            return {"success": False, "message": f"Webhook endpoint answered HTTP {response.status_code}"}
        return {"success": True, "message": f"Webhook delivered (HTTP {response.status_code})"}
