"""Slack integration: incident notifications with Block Kit and approve/reject buttons.

Web API reference: https://docs.slack.dev/reference/methods/chat.postMessage
Request signing:   https://docs.slack.dev/authentication/verifying-requests-from-slack
"""

import hashlib
import hmac
import logging
import time

import httpx

from app.integrations.base_client import BaseIntegrationClient, NotificationEvent

logger = logging.getLogger("cane_ai.integrations.slack")

# action_id values the interactivity endpoint must look for.
APPROVE_ACTION_ID = "cane_approve"
REJECT_ACTION_ID = "cane_reject"
OPEN_ACTION_ID = "cane_open"

SIGNATURE_MAX_AGE_SECONDS = 60 * 5

_SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def verify_slack_signature(signing_secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    """Check that a request really came from Slack (v0 signing scheme).

    `timestamp` is the X-Slack-Request-Timestamp header, `signature` the
    X-Slack-Signature header and `body` the RAW request body, before any parsing.
    Returns False for a missing or malformed value, a timestamp more than five
    minutes away from now (replay protection) or a signature that does not match."""
    if not signing_secret or not timestamp or not signature or body is None:
        return False
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - sent_at) > SIGNATURE_MAX_AGE_SECONDS:
        return False

    if isinstance(body, str):
        body = body.encode("utf-8")
    base = b"v0:" + str(timestamp).encode("ascii", "ignore") + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected.encode("utf-8"), str(signature).encode("utf-8"))
    except Exception:
        return False


def _escape(text: str) -> str:
    """Escape the three characters Slack treats as control characters in mrkdwn, so
    text taken from logs cannot inject links or mentions (<!channel>, <http://..|x>)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clip(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


class SlackClient(BaseIntegrationClient):
    platform_name = "slack"
    display_name = "Slack"
    description = "Post incident notifications to a Slack channel and approve or reject actions from Slack"
    auth_type = "bearer_token"
    category = "notification"
    required_credentials = ["bot_token", "signing_secret"]
    optional_config = ["channel"]
    capabilities = ["notify", "approve_actions", "get_user_email"]

    BASE_URL = "https://slack.com/api"

    def _auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.credentials['bot_token']}",
            "Content-Type": "application/json; charset=utf-8",
        }

    async def _call(self, http_method: str, api_method: str, *, json: dict | None = None,
                    params: dict | None = None) -> dict:
        """Call a Web API method. Slack answers HTTP 200 with {"ok": false, "error": ...}
        when a call fails, so the result is normalised to {"ok": bool, "error": str, ...}."""
        client = await self.get_http_client()
        try:
            response = await client.request(
                http_method, f"{self.BASE_URL}/{api_method}",
                headers=self._auth_headers(), json=json, params=params,
            )
        except httpx.HTTPError as e:
            return {"ok": False, "error": f"network error ({type(e).__name__})"}
        if response.status_code == 429:
            return {"ok": False, "error": "ratelimited"}
        try:
            data = response.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return {"ok": False, "error": f"HTTP {response.status_code}"}
        if response.status_code >= 400 or not data.get("ok"):
            data["ok"] = False
            data.setdefault("error", f"HTTP {response.status_code}")
        return data

    async def test_connection(self) -> dict:
        try:
            data = await self._call("POST", "auth.test")
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {type(e).__name__}"}
        if not data["ok"]:
            return {"success": False, "message": f"Connection failed: {data['error']}"}
        return {"success": True, "message": f"Connected to Slack workspace {data.get('team', '')}".strip()}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    def build_blocks(self, event: NotificationEvent) -> list[dict]:
        """Block Kit layout for an event."""
        severity = _SEVERITY_LABEL.get(str(event.severity).lower(), str(event.severity))
        blocks: list[dict] = [
            {"type": "header",
             "text": {"type": "plain_text", "text": _clip(event.title, 150), "emoji": True}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": _clip(_escape(event.summary), 3000) or " "}},
        ]

        fields = [{"type": "mrkdwn", "text": f"*Severity*\n{_escape(severity)}"}]
        for label, value in list(event.fields.items())[:9]:  # a section holds at most 10 fields
            fields.append({"type": "mrkdwn", "text": _clip(f"*{_escape(label)}*\n{_escape(value)}", 2000)})
        blocks.append({"type": "section", "fields": fields})

        buttons: list[dict] = []
        if event.kind == "action_pending" and event.action_id:
            buttons.append({
                "type": "button", "style": "primary",
                "text": {"type": "plain_text", "text": "Approve"},
                "action_id": APPROVE_ACTION_ID, "value": str(event.action_id),
            })
            buttons.append({
                "type": "button", "style": "danger",
                "text": {"type": "plain_text", "text": "Reject"},
                "action_id": REJECT_ACTION_ID, "value": str(event.action_id),
            })
        if event.incident_url:
            buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Open in Cane AI"},
                "action_id": OPEN_ACTION_ID, "url": event.incident_url,
            })
        if buttons:
            blocks.append({"type": "actions", "block_id": "cane_actions", "elements": buttons})
        return blocks

    async def notify(self, event: NotificationEvent) -> dict:
        channel = self.config.get("channel")
        self._log_action("notify", {"kind": event.kind, "incident_id": event.incident_id, "channel": channel})
        if not channel:
            return {"success": False, "message": "Slack channel is not configured"}
        if self.dry_run:
            return self._dry(f"post '{event.title}' to Slack channel {channel}")

        data = await self._call("POST", "chat.postMessage", json={
            "channel": channel,
            "text": _clip(f"{event.title}: {event.summary}", 3000),  # fallback for notifications
            "blocks": self.build_blocks(event),
            "unfurl_links": False,
        })
        if not data["ok"]:
            return {"success": False, "message": f"Slack rejected the message: {data['error']}"}
        return {
            "success": True,
            "message": f"Posted to Slack channel {channel}",
            "channel": data.get("channel"),
            "ts": data.get("ts"),
        }

    async def get_user_email(self, slack_user_id: str) -> str | None:
        """Email address of a Slack user (needs the users:read and users:read.email scopes).
        None when the user is unknown, has no visible email or the call fails."""
        data = await self._call("GET", "users.info", params={"user": slack_user_id})
        if not data["ok"]:
            logger.warning("slack.users.info failed: %s", data["error"])
            return None
        email = ((data.get("user") or {}).get("profile") or {}).get("email")
        return email or None
