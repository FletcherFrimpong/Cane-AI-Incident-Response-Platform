"""Offline GeoIP lookups from a local MaxMind-format database (GeoLite2 or DB-IP Lite)."""

import logging
import os

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.geoip")


def _name(node) -> str | None:
    """English name of a MaxMind record node: {"names": {"en": "Ghana", ...}}."""
    if not isinstance(node, dict):
        return None
    names = node.get("names")
    if isinstance(names, dict):
        return names.get("en") or next(iter(names.values()), None)
    return None


class GeoIpClient(BaseIntegrationClient):
    platform_name = "geoip"
    display_name = "GeoIP (local database)"
    description = (
        "Looks up an IP's country, city and network owner in a local MaxMind-format .mmdb "
        "file (GeoLite2 or DB-IP Lite). Fully offline: no IP ever leaves the platform."
    )
    auth_type = "api_key"   # no credentials; the enum has no "none" value
    category = "enrichment"
    required_credentials: list[str] = []
    optional_config = ["database_path"]
    capabilities = ["enrich_ip"]
    enriches = ("ip",)

    def __init__(self, credentials, config=None, dry_run: bool = False):
        super().__init__(credentials, config, dry_run)
        self._reader = None

    def _open_reader(self):
        """Return (reader, None), or (None, why-not). The reader is opened once and reused."""
        if self._reader is not None:
            return self._reader, None
        path = self.config.get("database_path")
        if not path:
            return None, "No database_path configured: point it at a GeoLite2 or DB-IP Lite .mmdb file"
        try:
            import maxminddb   # optional dependency, only needed by this connector
        except ImportError:
            return None, "The 'maxminddb' Python package is not installed"
        if not os.path.isfile(path):
            return None, f"GeoIP database file not found: {path}"
        try:
            self._reader = maxminddb.open_database(path)
        except Exception as e:
            return None, f"Could not open GeoIP database {path}: {e}"
        return self._reader, None

    async def close(self):
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
        await super().close()

    async def test_connection(self) -> dict:
        reader, problem = self._open_reader()
        if reader is None:
            return {"success": False, "message": problem}
        try:
            database_type = reader.metadata().database_type
        except Exception as e:
            return {"success": False, "message": f"Could not read GeoIP database: {e}"}
        return {"success": True, "message": f"GeoIP database loaded ({database_type})"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind != "ip":
            return None
        reader, problem = self._open_reader()
        if reader is None:
            logger.warning("geoip.enrich skipped: %s", problem)
            return None
        value = str(value).strip()
        try:
            record = reader.get(value)
        except ValueError:
            return None   # not a valid IP address
        if not isinstance(record, dict) or not record:
            return None   # private or unallocated address, or not in this database

        country_node = record.get("country") or record.get("registered_country") or {}
        country = _name(country_node)
        country_code = country_node.get("iso_code") if isinstance(country_node, dict) else None
        city = _name(record.get("city"))
        # ASN databases (GeoLite2-ASN, DB-IP ASN Lite) use these two flat keys.
        asn = record.get("autonomous_system_number")
        organisation = record.get("autonomous_system_organization")

        if not (country or country_code or city or asn or organisation):
            return None

        place = ", ".join(p for p in (city, country or country_code) if p)
        network = ""
        if asn or organisation:
            network = " on the network of " + " ".join(p for p in (f"AS{asn}" if asn else None, organisation) if p)
        if place:
            summary = f"{value} is located in {place}{network}."
        else:
            summary = f"{value} is{network}."

        result = {
            "verdict": "unknown",   # location says where, never whether it is hostile
            "summary": summary,
            "country": country,
            "country_code": country_code,
        }
        if city:
            result["city"] = city
        if asn:
            result["asn"] = asn
        if organisation:
            result["organisation"] = organisation
        return result
