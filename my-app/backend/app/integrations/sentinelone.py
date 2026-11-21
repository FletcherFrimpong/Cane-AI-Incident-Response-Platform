"""SentinelOne integration: disconnect/reconnect endpoints, start a scan, describe hosts.

API shapes follow SentinelOne's published Management Console API reference (v2.1):
  GET  /web/api/v2.1/agents?computerName__like=&limit=   -> {"data": [{agent...}]}
  POST /web/api/v2.1/agents/actions/disconnect            body {"filter": {"ids": [...]}, "data": {}}
  POST /web/api/v2.1/agents/actions/connect
  POST /web/api/v2.1/agents/actions/initiate-scan         -> {"data": {"affected": N}}
Auth header: `Authorization: ApiToken <token>`.
"""

import logging
import re

import httpx

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.sentinelone")

_AGENT_ID = re.compile(r"\d{15,20}")


def _vendor_error(e: Exception) -> str:
    """A short, credential-free description of a failed call."""
    if isinstance(e, httpx.HTTPStatusError):
        detail = ""
        try:
            errors = e.response.json().get("errors") or []
            detail = "; ".join(
                str(x.get("detail") or x.get("title") or "") for x in errors if isinstance(x, dict)
            )
        except Exception:  # noqa: BLE001 - body is not JSON
            detail = e.response.text[:200]
        return f"HTTP {e.response.status_code}" + (f": {detail[:300]}" if detail else "")
    return type(e).__name__


class SentinelOneClient(BaseIntegrationClient):
    platform_name = "sentinelone"
    display_name = "SentinelOne"
    description = (
        "Disconnect endpoints from the network, reconnect them, start a full disk scan, and look up "
        "endpoint details in SentinelOne."
    )
    auth_type = "api_key"
    category = "response"
    required_credentials = ["api_token", "console_url"]
    optional_config = []
    capabilities = ["isolate_host", "release_host", "run_av_scan", "describe_host"]
    actions = {"isolate_host": "isolate_host", "release_host": "release_host", "run_av_scan": "run_av_scan"}
    provides_context = ("host",)

    API_PREFIX = "/web/api/v2.1"

    @property
    def base_url(self) -> str:
        url = str(self.credentials.get("console_url", "")).strip().rstrip("/")
        if url and "://" not in url:
            url = f"https://{url}"
        return url + self.API_PREFIX

    def _auth_headers(self) -> dict:
        return {"Authorization": f"ApiToken {self.credentials['api_token']}", "Accept": "application/json"}

    # ---- health ----------------------------------------------------------------

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(f"{self.base_url}/agents", headers=self._auth_headers(), params={"limit": 1})
            response.raise_for_status()
            return {"success": True, "message": "Connected to SentinelOne"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"Connection failed: {_vendor_error(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    # ---- host lookup -----------------------------------------------------------

    async def _find_agent(self, name_or_id: str) -> dict | None:
        """Hostname or agent ID -> the agent record. None when SentinelOne has no such endpoint."""
        value = str(name_or_id).strip()
        client = await self.get_http_client()
        if _AGENT_ID.fullmatch(value):
            response = await client.get(f"{self.base_url}/agents", headers=self._auth_headers(), params={"ids": value})
            response.raise_for_status()
            data = response.json().get("data") or []
            return data[0] if data else None

        candidates = [value]
        short = value.split(".", 1)[0]
        if short and short != value:
            candidates.append(short)
        for name in candidates:
            response = await client.get(
                f"{self.base_url}/agents",
                headers=self._auth_headers(),
                # __like is a substring match, so the exact (case-insensitive) match is picked below.
                params={"computerName__like": name, "limit": 100},
            )
            response.raise_for_status()
            matches = [
                a for a in (response.json().get("data") or [])
                if str(a.get("computerName", "")).lower() == name.lower()
            ]
            if matches:
                # Prefer a live agent over a decommissioned duplicate, then the most recently active.
                matches.sort(
                    key=lambda a: (not a.get("isDecommissioned", False), str(a.get("lastActiveDate") or "")),
                    reverse=True,
                )
                return matches[0]
        return None

    async def describe_host(self, hostname: str) -> dict | None:
        a = await self._find_agent(hostname)
        if not a:
            return None
        network_status = a.get("networkStatus")
        return {
            "device_id": a.get("id"),
            "hostname": a.get("computerName"),
            "os": a.get("osName"),
            "owner": a.get("lastLoggedInUserName"),
            "last_seen": a.get("lastActiveDate"),
            "is_isolated": network_status in ("disconnected", "disconnecting"),
            "network_status": network_status,
            "is_active": a.get("isActive"),
            "infected": a.get("infected"),
            "active_threats": a.get("activeThreats"),
            "domain": a.get("domain"),
            "site": a.get("siteName"),
            "external_ip": a.get("externalIp"),
        }

    # ---- response actions ------------------------------------------------------

    async def _agent_action(self, machine_id: str, action: str, verb: str, done: str) -> dict:
        self._log_action(action, {"machine_id": machine_id})
        if self.dry_run:
            return self._dry(f"{verb} endpoint {machine_id} in SentinelOne")
        try:
            agent = await self._find_agent(machine_id)
            if not agent or not agent.get("id"):
                return {
                    "success": False,
                    "not_found": True,
                    "message": f"SentinelOne has no endpoint named '{machine_id}'",
                }
            agent_id = str(agent["id"])
            client = await self.get_http_client()
            response = await client.post(
                f"{self.base_url}/agents/actions/{action}",
                headers=self._auth_headers(),
                json={"filter": {"ids": [agent_id]}, "data": {}},
            )
            response.raise_for_status()
            affected = int((response.json().get("data") or {}).get("affected") or 0)
            if affected < 1:
                return {"success": False, "device_id": agent_id,
                        "message": f"SentinelOne accepted the request but no endpoint was affected ({machine_id})"}
            return {"success": True, "device_id": agent_id, "message": f"Endpoint {machine_id} {done} ({agent_id})"}
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as e:
            return {"success": False, "message": f"SentinelOne could not {verb} {machine_id}: {_vendor_error(e)}"}

    async def isolate_host(self, machine_id: str) -> dict:
        """Disconnect the endpoint from the network (it can still reach the SentinelOne console)."""
        return await self._agent_action(machine_id, "disconnect", "disconnect", "disconnected from the network")

    async def release_host(self, machine_id: str) -> dict:
        """Reconnect the endpoint to the network."""
        return await self._agent_action(machine_id, "connect", "reconnect", "reconnected to the network")

    async def run_av_scan(self, machine_id: str) -> dict:
        """Start a full disk scan."""
        return await self._agent_action(machine_id, "initiate-scan", "scan", "full disk scan started")
