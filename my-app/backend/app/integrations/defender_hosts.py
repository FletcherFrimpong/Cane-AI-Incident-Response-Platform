"""Hostname -> machine ID lookup for Microsoft Defender for Endpoint.

A mixin for a client that provides `BASE_URL` (ending in /api), `_auth_headers()` and
`get_http_client()`. Uses the Defender machines API:
  GET {BASE_URL}/machines?$filter=computerDnsName eq '<name>'
  GET {BASE_URL}/machines?$filter=startswith(computerDnsName,'<short>.')
  GET {BASE_URL}/machines/{id}
Needs the application permission Machine.Read.All (or Machine.ReadWrite.All).
"""

import re

from app.integrations.base_client import seg

_MACHINE_ID = re.compile(r"[0-9a-fA-F]{40}")


def _odata_str(value: str) -> str:
    """Quote a value as an OData string literal (a single quote is escaped by doubling it)."""
    return "'" + value.replace("'", "''") + "'"


class DefenderHostResolver:
    """Mix into the Defender client so actions can take a hostname instead of a machine ID."""

    async def _defender_machines(self, odata_filter: str) -> list[dict]:
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/machines", headers=headers, params={"$filter": odata_filter})
        if response.status_code == 404:  # Defender answers 404 when nothing matches
            return []
        response.raise_for_status()
        return response.json().get("value") or []

    async def _find_machine(self, name_or_id: str) -> dict | None:
        value = str(name_or_id).strip()
        if not value:
            return None
        if _MACHINE_ID.fullmatch(value):
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.get(f"{self.BASE_URL}/machines/{seg(value)}", headers=headers)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()

        short = value.split(".", 1)[0]
        filters = [f"computerDnsName eq {_odata_str(value)}"]
        if short and short != value:
            filters.append(f"computerDnsName eq {_odata_str(short)}")
        # A short name from the logs may be a fully qualified name in Defender.
        filters.append(f"startswith(computerDnsName,{_odata_str(short + '.')})")
        for odata_filter in filters:
            machines = await self._defender_machines(odata_filter)
            if machines:
                # Re-imaged machines leave stale duplicates: take the one seen most recently.
                return max(machines, key=lambda m: str(m.get("lastSeen") or ""))
        return None

    async def resolve_machine_id(self, name_or_id: str) -> str | None:
        """Hostname or Defender machine ID -> Defender machine ID. None when Defender does not know the host."""
        value = str(name_or_id).strip()
        if _MACHINE_ID.fullmatch(value):
            return value
        machine = await self._find_machine(value)
        return str(machine["id"]) if machine and machine.get("id") else None

    async def describe_host(self, hostname: str) -> dict | None:
        m = await self._find_machine(hostname)
        if not m:
            return None
        os_name = " ".join(str(p) for p in (m.get("osPlatform"), m.get("version")) if p)
        return {
            "device_id": m.get("id"),
            "hostname": m.get("computerDnsName"),
            "os": os_name or None,
            "last_seen": m.get("lastSeen"),
            "risk": m.get("riskScore"),
            "exposure": m.get("exposureLevel"),
            "health": m.get("healthStatus"),
            "last_ip": m.get("lastIpAddress"),
            "external_ip": m.get("lastExternalIpAddress"),
            "tags": m.get("machineTags") or [],
            "aad_device_id": m.get("aadDeviceId"),
        }
