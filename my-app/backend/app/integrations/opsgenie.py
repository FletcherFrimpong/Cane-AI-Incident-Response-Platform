"""Opsgenie integration: raise and close alerts through the Alert API.

Reference: https://docs.opsgenie.com/docs/alert-api
"""

import logging

import httpx

from app.integrations.base_client import BaseIntegrationClient, NotificationEvent, seg

logger = logging.getLogger("cane_ai.integrations.opsgenie")

_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}

_BASE_URLS = {
    "us": "https://api.opsgenie.com",
    "eu": "https://api.eu.opsgenie.com",
}


class OpsgenieClient(BaseIntegrationClient):
    platform_name = "opsgenie"
    display_name = "Opsgenie"
    description = "Raise an Opsgenie alert when an incident opens and close it when the incident closes"
    auth_type = "api_key"
    category = "notification"
    required_credentials = ["api_key"]
    optional_config = ["region"]
    capabilities = ["notify", "create_alert", "close_alert"]

    def _base_url(self) -> str:
        region = str(self.config.get("region") or "us").strip().lower()
        if region not in _BASE_URLS:
            raise ValueError("Opsgenie region must be 'us' or 'eu'")
        return _BASE_URLS[region]

    def _auth_headers(self) -> dict:
        return {"Authorization": f"GenieKey {self.credentials['api_key']}"}

    @staticmethod
    def alias(incident_id: str) -> str:
        return f"cane-{incident_id}"

    @staticmethod
    def _error(response: httpx.Response) -> str:
        try:
            message = response.json().get("message")
        except Exception:
            message = None
        return f"HTTP {response.status_code}" + (f": {message}" if message else "")

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(f"{self._base_url()}/v2/account", headers=self._auth_headers())
        except ValueError as e:
            return {"success": False, "message": str(e)}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {type(e).__name__}"}
        if response.status_code == 200:
            return {"success": True, "message": "Connected to Opsgenie"}
        if response.status_code == 403:
            return {
                "success": False,
                "message": "Opsgenie refused the account check (HTTP 403). The key may belong to "
                           "an integration that is restricted from configuration access.",
            }
        return {"success": False, "message": f"Connection failed: {self._error(response)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    def build_alert(self, event: NotificationEvent) -> dict:
        details = {"kind": event.kind, "incident_id": event.incident_id, "incident_url": event.incident_url}
        details.update({str(k): str(v) for k, v in event.fields.items()})
        if event.action_id:
            details["action_id"] = event.action_id
        description = event.summary
        if event.incident_url:
            description = f"{description}\n\nOpen in Cane AI: {event.incident_url}"
        return {
            "message": str(event.title)[:130],
            "alias": self.alias(event.incident_id),
            "description": description[:15000],
            "priority": _PRIORITY.get(str(event.severity).lower(), "P3"),
            "source": "Cane AI",
            "tags": ["cane-ai", str(event.kind)[:50]],
            "details": details,
        }

    async def notify(self, event: NotificationEvent) -> dict:
        self._log_action("notify", {"kind": event.kind, "incident_id": event.incident_id})
        if not self.credentials.get("api_key"):
            return {"success": False, "message": "Opsgenie API key is not configured"}
        try:
            base_url = self._base_url()
        except ValueError as e:
            return {"success": False, "message": str(e)}

        alias = self.alias(event.incident_id)
        closing = event.kind == "incident_closed"
        if self.dry_run:
            return self._dry(f"{'close' if closing else 'create'} Opsgenie alert {alias}")

        client = await self.get_http_client()
        try:
            if closing:
                response = await client.post(
                    f"{base_url}/v2/alerts/{seg(alias)}/close",
                    params={"identifierType": "alias"},
                    headers=self._auth_headers(),
                    json={"source": "Cane AI", "note": str(event.summary)[:25000]},
                )
            else:
                response = await client.post(
                    f"{base_url}/v2/alerts", headers=self._auth_headers(), json=self.build_alert(event),
                )
        except httpx.HTTPError as e:
            return {"success": False, "message": f"Could not reach Opsgenie ({type(e).__name__})"}

        if not 200 <= response.status_code < 300:
            return {"success": False, "message": f"Opsgenie rejected the request ({self._error(response)})"}
        try:
            request_id = response.json().get("requestId")
        except Exception:
            request_id = None
        # Opsgenie answers 202 and processes the request asynchronously.
        return {
            "success": True,
            "message": f"Opsgenie accepted the request to {'close' if closing else 'create'} alert {alias}",
            "alias": alias,
            "request_id": request_id,
        }
