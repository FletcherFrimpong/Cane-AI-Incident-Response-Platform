"""Microsoft Teams integration: incident notifications through a Workflows webhook.

Payload format: https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
"""

import logging
from urllib.parse import urlsplit

import httpx

from app.integrations.base_client import BaseIntegrationClient, NotificationEvent

logger = logging.getLogger("cane_ai.integrations.teams")

_SEVERITY_COLOR = {
    "critical": "Attention",
    "high": "Attention",
    "medium": "Warning",
    "low": "Accent",
    "info": "Default",
}


def _webhook_url_problem(url) -> str | None:
    """Why a webhook URL cannot be used, or None when it is acceptable."""
    if not url or not isinstance(url, str):
        return "Webhook URL is not configured"
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return "Webhook URL is not a valid URL"
    if parts.scheme != "https" or not parts.hostname:
        return "Webhook URL must start with https://"
    return None


class TeamsClient(BaseIntegrationClient):
    platform_name = "microsoft_teams"
    display_name = "Microsoft Teams"
    description = "Post incident notifications to a Teams channel or chat through a Workflows webhook"
    auth_type = "webhook"
    category = "notification"
    required_credentials = ["webhook_url"]
    optional_config = []
    capabilities = ["notify"]

    async def test_connection(self) -> dict:
        # A webhook can only be exercised by posting to it, which would put a message in
        # the channel, so this checks the URL and leaves delivery to the first notification.
        problem = _webhook_url_problem(self.credentials.get("webhook_url"))
        if problem:
            return {"success": False, "message": problem}
        return {
            "success": True,
            "message": "Webhook URL looks valid. Teams offers no way to check a webhook "
                       "without posting, so delivery is confirmed by the first notification.",
        }

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    def build_card(self, event: NotificationEvent) -> dict:
        """The message envelope Teams webhooks expect, carrying one Adaptive Card."""
        severity = str(event.severity).lower()
        facts = [{"title": "Severity", "value": str(event.severity).capitalize()}]
        facts += [{"title": str(k), "value": str(v)} for k, v in event.fields.items()]
        body = [
            {"type": "TextBlock", "text": event.title, "weight": "Bolder", "size": "Medium",
             "wrap": True, "color": _SEVERITY_COLOR.get(severity, "Default")},
            {"type": "TextBlock", "text": event.summary, "wrap": True},
            {"type": "FactSet", "facts": facts},
        ]
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.2",
            "body": body,
        }
        if event.incident_url:
            card["actions"] = [
                {"type": "Action.OpenUrl", "title": "Open in Cane AI", "url": event.incident_url}
            ]
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }],
        }

    async def notify(self, event: NotificationEvent) -> dict:
        self._log_action("notify", {"kind": event.kind, "incident_id": event.incident_id})
        url = self.credentials.get("webhook_url")
        problem = _webhook_url_problem(url)
        if problem:
            return {"success": False, "message": problem}
        if self.dry_run:
            return self._dry(f"post '{event.title}' to Microsoft Teams")

        # The webhook URL carries its own secret, so it must never reach a log or an
        # error message: report the status code or the error type, nothing else.
        client = await self.get_http_client()
        try:
            response = await client.post(url.strip(), json=self.build_card(event))
        except httpx.HTTPError as e:
            return {"success": False, "message": f"Could not reach Teams ({type(e).__name__})"}
        if not 200 <= response.status_code < 300:
            return {"success": False, "message": f"Teams rejected the message: HTTP {response.status_code}"}
        # Retired Office 365 connector webhooks could answer 200 with an error in the body.
        if "returned HTTP error" in response.text:
            return {"success": False, "message": "Teams reported that message delivery failed"}
        return {"success": True, "message": "Posted to Microsoft Teams"}
