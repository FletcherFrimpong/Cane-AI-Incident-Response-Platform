"""Palo Alto Networks PAN-OS integration: block an IP by tagging it for a Dynamic Address Group.

Uses the PAN-OS XML API User-ID interface (no config commit needed):
  POST https://<firewall>/api/   form: type=user-id, cmd=<uid-message>, [vsys=<vsys>]
  header X-PAN-KEY: <api key>
  cmd:
    <uid-message><version>1.0</version><type>update</type><payload>
      <register><entry ip="203.0.113.7"><tag><member>cane-blocked</member></tag></entry></register>
    </payload></uid-message>
  reply: <response status="success">...</response> or status="error" with <msg>.
"""

import ipaddress
import logging
import xml.etree.ElementTree as ET

import httpx

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.paloalto")

_FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def _truthy(value, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("false", "0", "no", "off")


def _parse_reply(text: str) -> tuple[bool, str]:
    """PAN-OS XML reply -> (ok, message)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False, "the firewall did not return XML"
    # Details come as text (<msg><line>..) or, for User-ID replies, in a `message` attribute.
    parts = [" ".join(t.split()) for t in root.itertext() if t.strip()]
    parts += [el.get("message") for el in root.iter() if el.get("message")]
    return root.get("status") == "success", " ".join(parts)[:300]


class PaloAltoClient(BaseIntegrationClient):
    platform_name = "palo_alto"
    display_name = "Palo Alto Networks Firewall"
    description = (
        "Block an IP address on a PAN-OS firewall by registering it with a tag (default 'cane-blocked'). "
        "PREREQUISITE: the firewall must already have a Dynamic Address Group whose match criteria is "
        "that tag, used as source/destination in a deny security rule. Without that group and rule, "
        "tagging an IP blocks nothing. No commit is needed once the rule exists."
    )
    auth_type = "api_key"
    category = "response"
    required_credentials = ["host", "api_key"]
    optional_config = ["block_tag", "vsys", "verify_tls"]
    capabilities = ["block_ip"]
    actions = {"block_ip": "block_ip"}

    DEFAULT_BLOCK_TAG = "cane-blocked"

    @property
    def api_url(self) -> str:
        host = str(self.credentials.get("host", "")).strip()
        host = host.split("://", 1)[-1].split("/", 1)[0]
        return f"https://{host}/api/"

    @property
    def block_tag(self) -> str:
        return str(self.config.get("block_tag") or self.DEFAULT_BLOCK_TAG).strip()

    async def get_http_client(self) -> httpx.AsyncClient:
        # Firewall management interfaces often use a private CA: verify_tls=false opts out.
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Content-Type": "application/json"},
                verify=_truthy(self.config.get("verify_tls")),
            )
        return self._http_client

    def _headers(self) -> dict:
        return {"X-PAN-KEY": str(self.credentials["api_key"]), **_FORM}

    # ---- health ----------------------------------------------------------------

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.post(
                self.api_url,
                headers=self._headers(),
                data={"type": "op", "cmd": "<show><system><info></info></system></show>"},
            )
            response.raise_for_status()
            ok, message = _parse_reply(response.text)
            if not ok:
                return {"success": False, "message": f"Connection failed: {message}"}
            root = ET.fromstring(response.text)
            return {
                "success": True,
                "message": "Connected to PAN-OS firewall",
                "details": {
                    "hostname": root.findtext(".//hostname"),
                    "sw_version": root.findtext(".//sw-version"),
                    "model": root.findtext(".//model"),
                },
            }
        except httpx.HTTPStatusError as e:
            return {"success": False, "message": f"Connection failed: HTTP {e.response.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"Connection failed: {type(e).__name__}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    # ---- response actions ------------------------------------------------------

    def _register_message(self, ip: str) -> str:
        root = ET.Element("uid-message")
        ET.SubElement(root, "version").text = "1.0"
        ET.SubElement(root, "type").text = "update"
        register = ET.SubElement(ET.SubElement(root, "payload"), "register")
        tag = ET.SubElement(ET.SubElement(register, "entry", {"ip": ip}), "tag")
        ET.SubElement(tag, "member").text = self.block_tag
        return ET.tostring(root, encoding="unicode")

    async def block_ip(self, ip_address: str) -> dict:
        """Tag the IP so the firewall's Dynamic Address Group (and its deny rule) picks it up."""
        self._log_action("block_ip", {"ip": ip_address})
        try:
            ip = str(ipaddress.ip_address(str(ip_address).strip()))
        except ValueError:
            return {"success": False, "message": f"'{ip_address}' is not a single IP address"}
        tag = self.block_tag
        if self.dry_run:
            return self._dry(f"register IP {ip} with tag '{tag}' on the Palo Alto firewall")

        data = {"type": "user-id", "cmd": self._register_message(ip)}
        vsys = str(self.config.get("vsys") or "").strip()
        if vsys:
            data["vsys"] = vsys
        try:
            client = await self.get_http_client()
            response = await client.post(self.api_url, headers=self._headers(), data=data)
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            _, detail = _parse_reply(e.response.text)
            return {"success": False,
                    "message": f"Palo Alto firewall refused to tag {ip}: HTTP {e.response.status_code} {detail}".strip()}
        except httpx.HTTPError as e:
            return {"success": False, "message": f"Palo Alto firewall could not be reached: {type(e).__name__}"}

        ok, message = _parse_reply(response.text)
        if ok:
            return {"success": True, "tag": tag,
                    "message": f"IP {ip} registered with tag '{tag}'; blocked where a Dynamic Address Group "
                               f"matching that tag is used in a deny rule"}
        if "already exists" in message:
            # PAN-OS reports a repeated registration as an error; the IP is tagged, which is the goal.
            return {"success": True, "tag": tag, "message": f"IP {ip} already carries tag '{tag}'"}
        return {"success": False, "message": f"Palo Alto firewall refused to tag {ip}: {message}"}
