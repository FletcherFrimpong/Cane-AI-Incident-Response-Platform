"""ServiceNow integration: open, annotate and resolve records on the incident table.

Reference (Table API): https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html
"""

import logging
from urllib.parse import urlsplit

import httpx

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.servicenow")

# severity -> (urgency, impact); 1 = High, 2 = Medium, 3 = Low. ServiceNow derives the
# incident priority from the pair: 1/1 -> P1, 1/2 -> P2, 2/2 -> P3, 2/3 -> P4, 3/3 -> P5.
_URGENCY_IMPACT = {
    "critical": ("1", "1"),
    "high": ("1", "2"),
    "medium": ("2", "2"),
    "low": ("2", "3"),
    "info": ("3", "3"),
}

_STATES = {"resolved": "6", "closed": "7"}
_RETURN_FIELDS = "sys_id,number,state"


class ServiceNowClient(BaseIntegrationClient):
    platform_name = "servicenow"
    display_name = "ServiceNow"
    description = "Open a ServiceNow incident for each incident, add work notes and resolve it on closure"
    auth_type = "basic_auth"
    category = "ticketing"
    required_credentials = ["instance_url", "username", "password"]
    # close_code must be one of the instance's Resolution code choices; close_state is
    # "resolved" (default) or "closed".
    optional_config = ["close_code", "close_state"]
    capabilities = ["create_ticket", "add_ticket_comment", "close_ticket"]

    TABLE = "incident"
    DEFAULT_CLOSE_CODE = "Solution provided"

    def _base_url(self) -> str:
        url = str(self.credentials.get("instance_url") or "").strip().rstrip("/")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("ServiceNow instance URL must look like https://your-instance.service-now.com")
        return url

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self.credentials["username"], self.credentials["password"])

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        client = await self.get_http_client()
        return await client.request(
            method, f"{self._base_url()}{path}", auth=self._auth(),
            headers={"Accept": "application/json"}, **kwargs,
        )

    @staticmethod
    def _error(response: httpx.Response) -> str:
        """ServiceNow's own explanation: {"error": {"message": ..., "detail": ...}}."""
        parts: list[str] = []
        try:
            error = response.json().get("error") or {}
            parts = [str(error[k]) for k in ("message", "detail") if error.get(k)]
        except Exception:
            pass
        return f"HTTP {response.status_code}" + (f": {' - '.join(parts)}" if parts else "")

    @staticmethod
    def _unreachable(e: Exception) -> dict:
        if isinstance(e, ValueError):
            return {"success": False, "message": str(e)}
        return {"success": False, "message": f"Could not reach ServiceNow ({type(e).__name__})"}

    @staticmethod
    def _record(response: httpx.Response) -> dict:
        try:
            result = response.json().get("result")
        except Exception:
            result = None
        return result if isinstance(result, dict) else {}

    def _ticket_url(self, sys_id: str) -> str:
        return f"{self._base_url()}/nav_to.do?uri={seg(f'incident.do?sys_id={sys_id}')}"

    async def test_connection(self) -> dict:
        try:
            response = await self._request(
                "GET", f"/api/now/table/{self.TABLE}",
                params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
            )
        except Exception as e:
            return self._unreachable(e)
        if response.status_code != 200:
            return {"success": False, "message": f"Connection failed: {self._error(response)}"}
        return {"success": True, "message": "Connected to ServiceNow"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def create_ticket(self, incident: dict) -> dict:
        self._log_action("create_ticket", {"incident_id": incident.get("id")})
        if self.dry_run:
            return self._dry(f"create a ServiceNow incident for incident {incident.get('id')}")

        urgency, impact = _URGENCY_IMPACT.get(str(incident.get("severity", "")).lower(), ("2", "2"))
        lines = [str(incident.get("description") or ""), ""]
        lines.append(f"Severity: {incident.get('severity', 'unknown')}")
        if incident.get("attack_type"):
            lines.append(f"Attack type: {incident['attack_type']}")
        lines.append(f"Cane AI incident: {incident.get('id', '')}")
        if incident.get("url"):
            lines.append(f"Open in Cane AI: {incident['url']}")
        title = " ".join(str(incident.get("title") or f"Incident {incident.get('id', '')}").split())

        try:
            response = await self._request(
                "POST", f"/api/now/table/{self.TABLE}",
                params={"sysparm_fields": _RETURN_FIELDS},
                json={
                    "short_description": title[:160],
                    "description": "\n".join(lines).strip(),
                    "urgency": urgency,
                    "impact": impact,
                },
            )
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 201:
            return {"success": False,
                    "message": f"ServiceNow did not create the incident ({self._error(response)})"}
        record = self._record(response)
        sys_id = record.get("sys_id")
        if not sys_id:
            return {"success": False, "message": "ServiceNow did not return a sys_id"}
        number = record.get("number")
        return {
            "success": True,
            "ticket_id": sys_id,
            "ticket_number": number,
            "ticket_url": self._ticket_url(sys_id),
            "message": f"Created ServiceNow incident {number or sys_id}",
        }

    async def _update(self, ticket_id: str, fields: dict) -> httpx.Response:
        return await self._request(
            "PATCH", f"/api/now/table/{self.TABLE}/{seg(ticket_id)}",
            params={"sysparm_fields": _RETURN_FIELDS}, json=fields,
        )

    async def add_ticket_comment(self, ticket_id: str, text: str) -> dict:
        self._log_action("add_ticket_comment", {"ticket_id": ticket_id})
        if self.dry_run:
            return self._dry(f"add a work note to ServiceNow incident {ticket_id}")
        try:
            response = await self._update(ticket_id, {"work_notes": text})
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 200:
            return {"success": False,
                    "message": f"ServiceNow did not add the work note ({self._error(response)})"}
        number = self._record(response).get("number")
        return {"success": True, "ticket_id": ticket_id, "ticket_number": number,
                "message": f"Added a work note to ServiceNow incident {number or ticket_id}"}

    async def close_ticket(self, ticket_id: str, resolution: str) -> dict:
        state_name = str(self.config.get("close_state") or "resolved").strip().lower()
        self._log_action("close_ticket", {"ticket_id": ticket_id, "state": state_name})
        if state_name not in _STATES:
            return {"success": False, "message": "ServiceNow close_state must be 'resolved' or 'closed'"}
        if self.dry_run:
            return self._dry(f"mark ServiceNow incident {ticket_id} as {state_name}")

        state = _STATES[state_name]
        try:
            response = await self._update(ticket_id, {
                "state": state,
                "close_code": self.config.get("close_code") or self.DEFAULT_CLOSE_CODE,
                "close_notes": resolution or "Closed by Cane AI",
            })
        except (httpx.HTTPError, ValueError) as e:
            return self._unreachable(e)
        if response.status_code != 200:
            return {"success": False,
                    "message": f"ServiceNow did not close the incident ({self._error(response)})"}
        record = self._record(response)
        number = record.get("number")
        # An ACL or business rule can discard the state change while the call still answers 200.
        if str(record.get("state", state)) != state:
            return {
                "success": False,
                "ticket_id": ticket_id,
                "ticket_number": number,
                "message": f"ServiceNow accepted the update but incident {number or ticket_id} "
                           f"was not moved to {state_name}",
            }
        return {"success": True, "ticket_id": ticket_id, "ticket_number": number,
                "message": f"ServiceNow incident {number or ticket_id} marked {state_name}"}
