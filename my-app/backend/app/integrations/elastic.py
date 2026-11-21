"""Elastic Security as an alert source: read detection alerts from the alerts index."""

import logging
from datetime import datetime, timezone
from typing import Any

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.elastic")

# Elastic Security writes detection alerts to .alerts-security.alerts-<kibana space id>.
DEFAULT_INDEX = ".alerts-security.alerts-default"
MAX_PAGE = 10000   # Elasticsearch's default index.max_result_window


def _field(source: Any, path: str) -> Any:
    """Read `a.b.c` from an Elasticsearch _source, whether it is stored nested
    ({"a": {"b": {"c": 1}}}), flat ({"a.b.c": 1}) or a mix ({"a.b": {"c": 1}})."""
    if not isinstance(source, dict):
        return None
    if path in source:
        return source[path]
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in source:
            found = _field(source[head], ".".join(parts[i:]))
            if found is not None:
                return found
    return None


def _one(value: Any) -> Any:
    if isinstance(value, list):
        return next((v for v in value if v not in (None, "")), None)
    return value if value != "" else None


class ElasticClient(BaseIntegrationClient):
    platform_name = "elastic"
    display_name = "Elastic Security"
    description = (
        "Pulls detection alerts from Elastic Security's alerts index and ingests them. "
        "Read-only; needs an API key with read access to the alerts index."
    )
    auth_type = "api_key"
    category = "source"
    required_credentials = ["base_url", "api_key"]
    optional_config = ["index"]
    capabilities = ["fetch_events"]

    def _search_url(self) -> str:
        index = str(self.config.get("index") or DEFAULT_INDEX).strip()
        return f"{str(self.credentials['base_url']).rstrip('/')}/{seg(index)}/_search"

    def _headers(self) -> dict:
        # The encoded form of the key (base64 of id:api_key), as shown when the key is created.
        return {"Authorization": f"ApiKey {self.credentials['api_key']}"}

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.post(
                self._search_url(), headers=self._headers(), json={"size": 0, "query": {"match_all": {}}}
            )
            if response.status_code == 401:
                return {"success": False, "message": "Elasticsearch rejected the API key"}
            if response.status_code == 403:
                return {"success": False, "message": "The API key is not allowed to read the alerts index"}
            if response.status_code == 404:
                return {"success": False, "message": "Alerts index not found: check the index setting and Kibana space"}
            response.raise_for_status()
            return {"success": True, "message": "Connected to Elasticsearch; alerts index is readable"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    @staticmethod
    def _to_envelope(hit: dict) -> dict:
        source = hit.get("_source") or {}
        host = _one(_field(source, "host.name"))
        source_ip = _one(_field(source, "source.ip"))
        user = _one(_field(source, "user.name"))

        entities = []
        if source_ip:
            entities.append({"Type": "ip", "Address": str(source_ip)})
        if host:
            entities.append({"Type": "host", "HostName": str(host)})
        if user:
            entities.append({"Type": "account", "Name": str(user)})

        data = {
            "TimeGenerated": _one(_field(source, "@timestamp")),
            "DisplayName": _one(_field(source, "kibana.alert.rule.name")) or "Elastic Security alert",
            "AlertSeverity": _one(_field(source, "kibana.alert.severity")),
            "Description": _one(_field(source, "kibana.alert.reason")) or _one(_field(source, "kibana.alert.rule.description")),
            "CompromisedEntity": str(host) if host else None,
            "Entities": entities,
            # EQL sequence alerts and their building-block alerts share one group id.
            "CorrelationId": _one(_field(source, "kibana.alert.group.id")),
            "SystemAlertId": _one(_field(source, "kibana.alert.uuid")) or hit.get("_id"),
            "ProviderName": "Elastic Security",
            "SourceSystem": "Elastic Security",
            "ExtendedProperties": {
                "risk_score": _one(_field(source, "kibana.alert.risk_score")),
                "rule_id": _one(_field(source, "kibana.alert.rule.uuid")),
                "workflow_status": _one(_field(source, "kibana.alert.workflow_status")),
                "original_time": _one(_field(source, "kibana.alert.original_time")),
                "index": hit.get("_index"),
            },
        }
        return {"schemaId": "securityalert", "data": data}

    async def fetch_events(self, since: datetime, limit: int = 500) -> list[dict]:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        client = await self.get_http_client()
        response = await client.post(
            self._search_url(),
            headers=self._headers(),
            json={
                "size": max(1, min(int(limit), MAX_PAGE)),
                "sort": [{"@timestamp": {"order": "asc"}}],
                "query": {"bool": {"filter": [{"range": {"@timestamp": {"gt": since.isoformat()}}}]}},
            },
        )
        response.raise_for_status()
        hits = ((response.json().get("hits") or {}).get("hits")) or []
        return [self._to_envelope(hit) for hit in hits if isinstance(hit, dict)]
