"""Jira Cloud integration: open, comment on and close issues for incidents (REST API v3).

Reference: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/
"""

import logging
from urllib.parse import urlsplit

import httpx

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.jira")


def adf(text: str, link_text: str | None = None, link_url: str | None = None) -> dict:
    """Plain text as an Atlassian Document Format document: one paragraph per non-empty
    line, optionally followed by a paragraph holding a single link."""
    content = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in str(text or "").splitlines() if line.strip()
    ]
    if link_url:
        content.append({"type": "paragraph", "content": [{
            "type": "text", "text": link_text or link_url,
            "marks": [{"type": "link", "attrs": {"href": link_url}}],
        }]})
    return {"type": "doc", "version": 1, "content": content}


class JiraClient(BaseIntegrationClient):
    platform_name = "jira"
    display_name = "Jira"
    description = "Open a Jira issue for each incident, add updates as comments and close it on resolution"
    auth_type = "basic_auth"
    category = "ticketing"
    required_credentials = ["base_url", "email", "api_token"]
    optional_config = ["project_key", "issue_type", "done_transition"]
    capabilities = ["create_ticket", "add_ticket_comment", "close_ticket"]

    def _base_url(self) -> str:
        url = str(self.credentials.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("Jira base URL must look like https://your-domain.atlassian.net")
        return url

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self.credentials["email"], self.credentials["api_token"])

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        client = await self.get_http_client()
        return await client.request(
            method, f"{self._base_url()}{path}", auth=self._auth(),
            headers={"Accept": "application/json"}, **kwargs,
        )

    @staticmethod
    def _error(response: httpx.Response) -> str:
        """Jira's own explanation of a failed call: {"errorMessages": [...], "errors": {...}}."""
        parts: list[str] = []
        try:
            data = response.json()
            parts += [str(m) for m in data.get("errorMessages") or []]
            parts += [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
        except Exception:
            pass
        return f"HTTP {response.status_code}" + (f": {'; '.join(parts)}" if parts else "")

    @staticmethod
    def _unreachable(e: Exception) -> dict:
        if isinstance(e, ValueError):
            return {"success": False, "message": str(e)}
        return {"success": False, "message": f"Could not reach Jira ({type(e).__name__})"}

    async def test_connection(self) -> dict:
        try:
            response = await self._request("GET", "/rest/api/3/myself")
        except Exception as e:
            return self._unreachable(e)
        if response.status_code != 200:
            return {"success": False, "message": f"Connection failed: {self._error(response)}"}
        try:
            name = response.json().get("displayName") or ""
        except Exception:
            name = ""
        return {"success": True, "message": f"Connected to Jira as {name}" if name else "Connected to Jira"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def create_ticket(self, incident: dict) -> dict:
        project_key = self.config.get("project_key")
        self._log_action("create_ticket", {"incident_id": incident.get("id"), "project": project_key})
        if not project_key:
            return {"success": False, "message": "Jira project key is not configured"}
        if self.dry_run:
            return self._dry(f"create a Jira issue in {project_key} for incident {incident.get('id')}")

        meta = [
            f"Severity: {incident.get('severity', 'unknown')}",
            f"Status: {incident.get('status', 'unknown')}",
        ]
        if incident.get("attack_type"):
            meta.append(f"Attack type: {incident['attack_type']}")
        meta.append(f"Cane AI incident: {incident.get('id', '')}")
        text = f"{incident.get('description') or ''}\n" + "\n".join(meta)
        summary = " ".join(str(incident.get("title") or f"Incident {incident.get('id', '')}").split())

        try:
            response = await self._request("POST", "/rest/api/3/issue", json={"fields": {
                "project": {"key": project_key},
                "issuetype": {"name": self.config.get("issue_type") or "Task"},
                "summary": summary[:255],
                "description": adf(text, "Open in Cane AI", incident.get("url")),
            }})
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 201:
            return {"success": False, "message": f"Jira did not create the issue ({self._error(response)})"}
        key = response.json().get("key")
        if not key:
            return {"success": False, "message": "Jira did not return an issue key"}
        return {
            "success": True,
            "ticket_id": key,
            "ticket_url": f"{self._base_url()}/browse/{seg(key)}",
            "message": f"Created Jira issue {key}",
        }

    async def add_ticket_comment(self, ticket_id: str, text: str) -> dict:
        self._log_action("add_ticket_comment", {"ticket_id": ticket_id})
        if self.dry_run:
            return self._dry(f"comment on Jira issue {ticket_id}")
        try:
            response = await self._request(
                "POST", f"/rest/api/3/issue/{seg(ticket_id)}/comment", json={"body": adf(text)},
            )
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 201:
            return {"success": False, "message": f"Jira did not add the comment ({self._error(response)})"}
        return {"success": True, "ticket_id": ticket_id, "message": f"Commented on Jira issue {ticket_id}"}

    async def close_ticket(self, ticket_id: str, resolution: str) -> dict:
        wanted = str(self.config.get("done_transition") or "Done")
        self._log_action("close_ticket", {"ticket_id": ticket_id, "transition": wanted})
        if self.dry_run:
            return self._dry(f"move Jira issue {ticket_id} to {wanted}")

        path = f"/rest/api/3/issue/{seg(ticket_id)}/transitions"
        try:
            response = await self._request("GET", path)
            if response.status_code != 200:
                return {"success": False,
                        "message": f"Could not read transitions of {ticket_id} ({self._error(response)})"}
            transitions = response.json().get("transitions") or []
            target = wanted.strip().lower()
            match = next((t for t in transitions if str(t.get("name", "")).lower() == target), None)
            if match is None:  # fall back to the name of the status the transition leads to
                match = next(
                    (t for t in transitions if str((t.get("to") or {}).get("name", "")).lower() == target),
                    None,
                )
            if match is None:
                available = ", ".join(str(t.get("name")) for t in transitions) or "none"
                return {
                    "success": False,
                    "message": f"Jira issue {ticket_id} has no '{wanted}' transition from its "
                               f"current status (available: {available})",
                }
            response = await self._request("POST", path, json={"transition": {"id": match["id"]}})
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 204:
            return {"success": False, "message": f"Jira did not close {ticket_id} ({self._error(response)})"}

        result = {"success": True, "ticket_id": ticket_id, "comment_added": True,
                  "message": f"Closed Jira issue {ticket_id}"}
        if resolution:
            comment = await self.add_ticket_comment(ticket_id, f"Resolution: {resolution}")
            if not comment["success"]:
                result["comment_added"] = False
                result["message"] += f", but the resolution comment failed: {comment['message']}"
        return result
