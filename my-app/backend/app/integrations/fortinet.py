"""Fortinet FortiGate integration: block an IP by adding it to the banned-IP (quarantine) list.

Uses the FortiOS REST API monitor endpoint (takes effect at once, no policy change):
  POST https://<fortigate>/api/v2/monitor/user/banned/add_users[?vdom=<vdom>]
       body {"ip_addresses": ["203.0.113.7"], "expiry": <seconds, optional>}
  GET  https://<fortigate>/api/v2/monitor/system/status
  header Authorization: Bearer <REST API admin token>
  reply JSON carries "status": "success" | "error".
"""

import ipaddress
import logging

import httpx

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.fortinet")


def _truthy(value, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "0", "no", "off")


class FortiGateClient(BaseIntegrationClient):
    platform_name = "fortinet"
    display_name = "Fortinet FortiGate"
    description = (
        "Block an IP address on a FortiGate firewall by adding it to the banned (quarantined) IP list. "
        "Traffic from a banned source IP is dropped; set ban_seconds to make bans expire on their own."
    )
    auth_type = "bearer_token"
    category = "response"
    required_credentials = ["host", "api_token"]
    optional_config = ["vdom", "ban_seconds", "verify_tls"]
    capabilities = ["block_ip"]
    actions = {"block_ip": "block_ip"}

    @property
    def base_url(self) -> str:
        host = str(self.credentials.get("host", "")).strip()
        host = host.split("://", 1)[-1].split("/", 1)[0]
        return f"https://{host}/api/v2"

    async def get_http_client(self) -> httpx.AsyncClient:
        # Firewall management interfaces often use a private CA: verify_tls=false opts out.
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Content-Type": "application/json"},
                verify=_truthy(self.config.get("verify_tls")),
            )
        return self._http_client

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.credentials['api_token']}", "Accept": "application/json"}

    def _params(self) -> dict:
        vdom = str(self.config.get("vdom") or "").strip()
        return {"vdom": vdom} if vdom else {}

    # ---- health ----------------------------------------------------------------

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(
                f"{self.base_url}/monitor/system/status", headers=self._auth_headers(), params=self._params(),
            )
            response.raise_for_status()
            body = response.json()
            return {
                "success": True,
                "message": "Connected to FortiGate",
                "details": {"version": body.get("version"), "build": body.get("build")},
            }
        except httpx.HTTPStatusError as e:
            return {"success": False, "message": f"Connection failed: HTTP {e.response.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"Connection failed: {type(e).__name__}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    # ---- response actions ------------------------------------------------------

    async def block_ip(self, ip_address: str) -> dict:
        """Add the IP to the FortiGate banned-IP list."""
        self._log_action("block_ip", {"ip": ip_address})
        try:
            ip = str(ipaddress.ip_address(str(ip_address).strip()))
        except ValueError:
            return {"success": False, "message": f"'{ip_address}' is not a single IP address"}
        if self.dry_run:
            return self._dry(f"add IP {ip} to the FortiGate banned-IP list")

        body: dict = {"ip_addresses": [ip]}
        ban_seconds = self.config.get("ban_seconds")
        if ban_seconds not in (None, ""):
            try:
                body["expiry"] = int(ban_seconds)
            except (TypeError, ValueError):
                return {"success": False, "message": "Config 'ban_seconds' must be a whole number of seconds"}
        try:
            client = await self.get_http_client()
            response = await client.post(
                f"{self.base_url}/monitor/user/banned/add_users",
                headers=self._auth_headers(), params=self._params(), json=body,
            )
            response.raise_for_status()
            reply = response.json()
        except httpx.HTTPStatusError as e:
            return {"success": False, "message": f"FortiGate refused to ban {ip}: HTTP {e.response.status_code}"}
        except httpx.HTTPError as e:
            return {"success": False, "message": f"FortiGate could not be reached: {type(e).__name__}"}
        except ValueError:
            return {"success": False, "message": f"FortiGate gave an unreadable reply when banning {ip}"}

        if not isinstance(reply, dict) or reply.get("status") != "success":
            detail = reply.get("error") if isinstance(reply, dict) else None
            return {"success": False,
                    "message": f"FortiGate did not ban {ip}" + (f" (error {detail})" if detail is not None else "")}
        return {"success": True, "message": f"IP {ip} added to the FortiGate banned-IP list"}
