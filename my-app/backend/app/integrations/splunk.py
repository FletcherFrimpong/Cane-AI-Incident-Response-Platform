"""Splunk as an alert/log source: run a bounded search and hand the results to ingest."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.splunk")

# Splunk Enterprise Security's notable events, with the fields its `notable` macro adds
# (rule_title, urgency, src, dest, user...).
DEFAULT_SEARCH = "search `notable`"
DEFAULT_SCHEMA = "securityalert"


def _one(value: Any) -> Any:
    """Splunk returns multi-value fields as lists; take the first non-empty value."""
    if isinstance(value, list):
        return next((v for v in value if v not in (None, "")), None)
    return value if value != "" else None


def _first(result: dict, *names: str) -> Any:
    for name in names:
        value = _one(result.get(name))
        if value is not None:
            return value
    return None


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _parse_time(value: Any) -> datetime | None:
    value = _one(value)
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)   # epoch seconds
    except (TypeError, ValueError):
        pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _to_security_alert(result: dict) -> dict:
    src = _first(result, "src", "src_ip")
    dest = _first(result, "dest", "dest_host", "dvc", "host")
    user = _first(result, "user", "src_user")
    entities = []
    if src and _is_ip(src):
        entities.append({"Type": "ip", "Address": str(src)})
    if dest:
        entities.append({"Type": "host", "HostName": str(dest)})
    if user:
        entities.append({"Type": "account", "Name": str(user)})
    return {
        "DisplayName": _first(result, "rule_title", "rule_name", "search_name", "signature", "source") or "Splunk alert",
        "AlertSeverity": _first(result, "urgency", "severity"),
        "Description": _first(result, "rule_description", "description", "savedsearch_description", "_raw"),
        "CompromisedEntity": str(dest) if dest else None,
        "Entities": entities,
        "CorrelationId": _first(result, "CorrelationId", "correlation_id"),
        "SystemAlertId": _first(result, "event_id", "_cd"),
        "ProviderName": "Splunk",
    }


def _to_common_security_log(result: dict) -> dict:
    return {
        "DeviceVendor": _first(result, "vendor") or "",
        "DeviceProduct": _first(result, "product", "vendor_product", "sourcetype") or "",
        "DeviceAction": _first(result, "action"),
        "Activity": _first(result, "signature", "search_name", "eventtype") or "",
        "LogSeverity": _first(result, "severity", "urgency"),
        "SourceIP": _first(result, "src_ip", "src"),
        "DestinationIP": _first(result, "dest_ip", "dest"),
        "SourceUserName": _first(result, "user", "src_user"),
        "Computer": _first(result, "host", "dvc"),
        "CorrelationId": _first(result, "CorrelationId", "correlation_id"),
        "Message": _first(result, "_raw"),
    }


_MAPPERS = {
    "securityalert": _to_security_alert,
    "commonsecuritylog": _to_common_security_log,
}


class SplunkClient(BaseIntegrationClient):
    platform_name = "splunk"
    display_name = "Splunk"
    description = (
        "Pulls events from Splunk by running a search you configure (by default the "
        "Enterprise Security notable events) and ingests the results. Read-only."
    )
    auth_type = "bearer_token"
    category = "source"
    required_credentials = ["base_url", "token"]
    optional_config = ["search", "schema_id"]
    capabilities = ["fetch_events"]

    def _base(self) -> str:
        return str(self.credentials["base_url"]).rstrip("/")

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.credentials['token']}"}

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(
                f"{self._base()}/services/server/info", headers=self._headers(), params={"output_mode": "json"}
            )
            if response.status_code in (401, 403):
                return {"success": False, "message": "Splunk rejected the token"}
            response.raise_for_status()
            entries = response.json().get("entry") or [{}]
            version = (entries[0].get("content") or {}).get("version", "unknown")
            return {"success": True, "message": f"Connected to Splunk {version}"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    def _search_string(self, limit: int) -> str:
        search = str(self.config.get("search") or DEFAULT_SEARCH).strip()
        # The REST API runs the string as-is: unlike the UI it does not imply the `search` command.
        if not search.startswith("|") and not search.lower().startswith("search "):
            search = f"search {search}"
        # Oldest first, capped, so a backlog is worked through in order across polls.
        return f"{search} | sort 0 _time | head {int(limit)}"

    async def fetch_events(self, since: datetime, limit: int = 500) -> list[dict]:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        schema_id = str(self.config.get("schema_id") or DEFAULT_SCHEMA).lower().strip()
        limit = max(int(limit), 1)

        client = await self.get_http_client()
        response = await client.post(
            f"{self._base()}/services/search/jobs",
            # Splunk's REST API takes form fields, not JSON.
            headers={**self._headers(), "Content-Type": "application/x-www-form-urlencoded"},
            data={
                "search": self._search_string(limit),
                "exec_mode": "oneshot",            # run and return results in this one call
                "output_mode": "json",
                "earliest_time": f"{since.timestamp():.3f}",   # UTC epoch seconds, inclusive
                "count": "0",                      # 0 = all results (the default page is 100)
            },
        )
        response.raise_for_status()
        body = response.json()
        fatal = [
            str(m.get("text")) for m in body.get("messages") or []
            if isinstance(m, dict) and str(m.get("type", "")).upper() in ("FATAL", "ERROR")
        ]
        if fatal:
            raise RuntimeError(f"Splunk search failed: {'; '.join(fatal)}")

        mapper = _MAPPERS.get(schema_id)
        events: list[tuple[datetime, dict]] = []
        for result in body.get("results") or []:
            if not isinstance(result, dict):
                continue
            when = _parse_time(result.get("_time")) or datetime.now(timezone.utc)
            if mapper:
                data = mapper(result)
                data["SplunkEvent"] = result
            else:
                # No built-in mapping for this schema: the search itself must name its
                # fields the way the schema expects (| rename / | eval).
                data = {k: _one(v) for k, v in result.items() if not k.startswith("_")}
            data["TimeGenerated"] = when.isoformat()
            data.setdefault("SourceSystem", "Splunk")
            events.append((when, {"schemaId": schema_id, "data": data}))

        events.sort(key=lambda pair: pair[0])
        return [envelope for _, envelope in events[:limit]]
