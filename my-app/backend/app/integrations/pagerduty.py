"""PagerDuty integration: page the on-call through the Events API v2.

Reference: https://docs.pagerduty.com/developer/send-alert-event
"""

import logging

import httpx

from app.integrations.base_client import BaseIntegrationClient, NotificationEvent

logger = logging.getLogger("cane_ai.integrations.pagerduty")

# PagerDuty accepts exactly: critical, error, warning, info.
_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}

_EVENT_ACTION = {
    "incident_opened": "trigger",
    "incident_escalated": "trigger",
    "triage_failed": "trigger",
    "action_pending": "trigger",
    "incident_closed": "resolve",
}


class PagerDutyClient(BaseIntegrationClient):
    platform_name = "pagerduty"
    display_name = "PagerDuty"
    description = "Page the on-call engineer when an incident opens and resolve the page when it closes"
    auth_type = "api_key"
    category = "notification"
    required_credentials = ["routing_key"]
    optional_config = []
    capabilities = ["notify", "trigger_alert", "resolve_alert"]

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    async def test_connection(self) -> dict:
        # The Events API has no read-only call: the only way to exercise a routing key is
        # to send an event, which would page someone. So only the key itself is checked.
        key = self.credentials.get("routing_key")
        if not key or not isinstance(key, str) or not key.strip():
            return {"success": False, "message": "Routing key is not configured"}
        return {
            "success": True,
            "message": "Routing key is set. PagerDuty cannot verify a routing key without "
                       "sending an event, so it is confirmed by the first notification.",
        }

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    @staticmethod
    def dedup_key(incident_id: str) -> str:
        return f"cane-{incident_id}"

    def build_event(self, event: NotificationEvent) -> dict | None:
        """Events API v2 body for an event, or None when the kind is not one we send."""
        action = _EVENT_ACTION.get(event.kind)
        if action is None:
            return None
        body: dict = {
            "routing_key": self.credentials.get("routing_key", ""),
            "event_action": action,
            "dedup_key": self.dedup_key(event.incident_id),
        }
        if action == "trigger":
            details = {"kind": event.kind, "incident_id": event.incident_id, "summary": event.summary}
            details.update({str(k): str(v) for k, v in event.fields.items()})
            if event.action_id:
                details["action_id"] = event.action_id
            body["payload"] = {
                "summary": str(event.title)[:1024],
                "source": "cane-ai",
                "severity": _SEVERITY.get(str(event.severity).lower(), "warning"),
                "custom_details": details,
            }
            if event.incident_url:
                body["links"] = [{"href": event.incident_url, "text": "Open in Cane AI"}]
        return body

    async def notify(self, event: NotificationEvent) -> dict:
        self._log_action("notify", {"kind": event.kind, "incident_id": event.incident_id})
        if not self.credentials.get("routing_key"):
            return {"success": False, "message": "Routing key is not configured"}
        body = self.build_event(event)
        if body is None:
            return {"success": False, "message": f"PagerDuty does not handle '{event.kind}' events"}
        action, dedup_key = body["event_action"], body["dedup_key"]
        if self.dry_run:
            return self._dry(f"send PagerDuty {action} event for {dedup_key}")

        client = await self.get_http_client()
        try:
            response = await client.post(self.EVENTS_URL, json=body)
        except httpx.HTTPError as e:
            return {"success": False, "message": f"Could not reach PagerDuty ({type(e).__name__})"}
        if response.status_code != 202:
            detail = ""
            try:
                data = response.json()
                parts = [str(data.get("message") or "")] + [str(x) for x in data.get("errors") or []]
                detail = ": " + "; ".join(p for p in parts if p) if any(parts) else ""
            except Exception:
                pass
            return {
                "success": False,
                "message": f"PagerDuty rejected the event (HTTP {response.status_code}){detail}",
            }
        return {
            "success": True,
            "message": f"PagerDuty {action} event accepted",
            "event_action": action,
            "dedup_key": dedup_key,
        }
