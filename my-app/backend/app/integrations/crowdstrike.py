"""CrowdStrike Falcon integration: network-contain hosts and describe them.

API shapes follow CrowdStrike's own SDK (falconpy endpoint definitions) and PSFalcon samples:
  POST /oauth2/token                                   form: client_id, client_secret
  GET  /devices/queries/devices/v1?filter=&sort=&limit= -> {"resources": ["<aid>", ...]}
  GET  /devices/entities/devices/v2?ids=<aid>           -> {"resources": [{device...}]}
  POST /devices/entities/devices-actions/v2?action_name=contain|lift_containment
       body {"ids": ["<aid>"]}
"""

import logging
import re
import time

import httpx

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.crowdstrike")

_AID = re.compile(r"[0-9a-fA-F]{32}")
# Anything else cannot be a hostname and could break out of the quoted FQL value.
_HOSTNAME = re.compile(r"[A-Za-z0-9._\- ]{1,255}")


def _vendor_error(e: Exception) -> str:
    """A short, credential-free description of a failed call."""
    if isinstance(e, httpx.HTTPStatusError):
        detail = ""
        try:
            errors = e.response.json().get("errors") or []
            detail = "; ".join(str(x.get("message", "")) for x in errors if isinstance(x, dict))
        except Exception:  # noqa: BLE001 - body is not JSON
            detail = e.response.text[:200]
        return f"HTTP {e.response.status_code}" + (f": {detail[:300]}" if detail else "")
    return type(e).__name__


class CrowdStrikeClient(BaseIntegrationClient):
    platform_name = "crowdstrike"
    display_name = "CrowdStrike Falcon"
    description = (
        "Network-contain and release hosts with CrowdStrike Falcon, and look up host details. "
        "Needs an API client with Hosts: Read and Hosts: Write."
    )
    auth_type = "oauth2_client_credentials"
    category = "response"
    required_credentials = ["client_id", "client_secret"]
    optional_config = ["base_url"]
    capabilities = ["isolate_host", "release_host", "describe_host"]
    actions = {"isolate_host": "isolate_host", "release_host": "release_host"}
    provides_context = ("host",)

    DEFAULT_BASE_URL = "https://api.crowdstrike.com"

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url") or self.DEFAULT_BASE_URL).rstrip("/")

    # ---- auth ------------------------------------------------------------------

    async def _acquire_token(self) -> str:
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token
        client = await self.get_http_client()
        response = await client.post(
            f"{self.base_url}/oauth2/token",
            data={
                "client_id": self.credentials["client_id"],
                "client_secret": self.credentials["client_secret"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + int(data.get("expires_in", 1799))
        return self._access_token

    async def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {await self._acquire_token()}", "Accept": "application/json"}

    # ---- health ----------------------------------------------------------------

    async def test_connection(self) -> dict:
        try:
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.get(
                f"{self.base_url}/devices/queries/devices/v1", headers=headers, params={"limit": 1},
            )
            response.raise_for_status()
            return {"success": True, "message": "Connected to CrowdStrike Falcon"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"Connection failed: {_vendor_error(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    # ---- host lookup -----------------------------------------------------------

    async def _resolve_device_id(self, name_or_id: str) -> str | None:
        """Hostname (or agent ID) -> Falcon agent ID (AID). None when Falcon has no such host."""
        value = str(name_or_id).strip()
        if _AID.fullmatch(value):
            return value.lower()
        candidates = [value]
        short = value.split(".", 1)[0]
        if short and short != value:
            candidates.append(short)

        headers = await self._auth_headers()
        client = await self.get_http_client()
        for name in candidates:
            if not _HOSTNAME.fullmatch(name):
                continue
            response = await client.get(
                f"{self.base_url}/devices/queries/devices/v1",
                headers=headers,
                # hostname:['x'] is FQL's exact match; newest first in case of re-imaged duplicates.
                params={"filter": f"hostname:['{name}']", "sort": "last_seen.desc", "limit": 1},
            )
            response.raise_for_status()
            resources = response.json().get("resources") or []
            if resources:
                return str(resources[0])
        return None

    async def describe_host(self, hostname: str) -> dict | None:
        device_id = await self._resolve_device_id(hostname)
        if not device_id:
            return None
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.base_url}/devices/entities/devices/v2", headers=headers, params={"ids": device_id},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        resources = response.json().get("resources") or []
        if not resources:
            return None
        d = resources[0]
        status = d.get("status")
        return {
            "device_id": d.get("device_id") or device_id,
            "hostname": d.get("hostname"),
            "os": d.get("os_version") or d.get("platform_name"),
            "platform": d.get("platform_name"),
            "owner": d.get("last_login_user"),
            "last_seen": d.get("last_seen"),
            "is_isolated": status in ("contained", "containment_pending"),
            "containment_status": status,
            "local_ip": d.get("local_ip"),
            "external_ip": d.get("external_ip"),
        }

    # ---- response actions ------------------------------------------------------

    async def _device_action(self, machine_id: str, action_name: str, verb: str, done: str) -> dict:
        self._log_action(action_name, {"machine_id": machine_id})
        if self.dry_run:
            return self._dry(f"{verb} host {machine_id} in CrowdStrike Falcon")
        try:
            device_id = await self._resolve_device_id(machine_id)
            if not device_id:
                return {
                    "success": False,
                    "not_found": True,
                    "message": f"CrowdStrike Falcon has no host named '{machine_id}'",
                }
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.post(
                f"{self.base_url}/devices/entities/devices-actions/v2",
                headers=headers,
                params={"action_name": action_name},
                json={"ids": [device_id]},
            )
            response.raise_for_status()
            body = response.json() if response.content else {}
            errors = body.get("errors") or []
            if errors:
                detail = "; ".join(str(x.get("message", x)) for x in errors if isinstance(x, dict))[:300]
                return {"success": False, "device_id": device_id,
                        "message": f"CrowdStrike refused to {verb} {machine_id}: {detail}"}
            return {"success": True, "device_id": device_id, "message": f"Host {machine_id} {done} ({device_id})"}
        except (httpx.HTTPError, KeyError, ValueError) as e:
            return {"success": False, "message": f"CrowdStrike could not {verb} {machine_id}: {_vendor_error(e)}"}

    async def isolate_host(self, machine_id: str) -> dict:
        """Network-contain a host (it can still reach the CrowdStrike cloud)."""
        return await self._device_action(machine_id, "contain", "contain", "network containment requested")

    async def release_host(self, machine_id: str) -> dict:
        """Lift network containment."""
        return await self._device_action(machine_id, "lift_containment", "lift containment on",
                                         "containment lift requested")
