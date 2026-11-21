"""MISP threat-sharing platform: is this indicator in any event our community has shared?"""

import logging

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.misp")


class MispClient(BaseIntegrationClient):
    platform_name = "misp"
    display_name = "MISP"
    description = (
        "Searches your MISP instance for attributes matching an IP, domain, URL or file "
        "hash and reports the events and tags they belong to. Read-only."
    )
    auth_type = "api_key"
    category = "enrichment"
    required_credentials = ["base_url", "api_key"]
    optional_config: list[str] = []
    capabilities = ["enrich_ip", "enrich_domain", "enrich_url", "enrich_file_hash"]
    enriches = ("ip", "domain", "url", "file_hash")

    SEARCH_LIMIT = 100

    def _base(self) -> str:
        return str(self.credentials["base_url"]).rstrip("/")

    def _headers(self) -> dict:
        # MISP takes the automation key as the bare Authorization value (no "Bearer").
        return {"Authorization": self.credentials["api_key"], "Accept": "application/json"}

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(f"{self._base()}/servers/getVersion", headers=self._headers())
            if response.status_code in (401, 403):
                return {"success": False, "message": "MISP rejected the API key"}
            response.raise_for_status()
            version = response.json().get("version", "unknown")
            return {"success": True, "message": f"Connected to MISP {version}"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind not in self.enriches:
            return None
        client = await self.get_http_client()
        response = await client.post(
            f"{self._base()}/attributes/restSearch",
            headers=self._headers(),
            json={
                "returnFormat": "json",
                "value": value,
                "limit": self.SEARCH_LIMIT,
                "includeEventTags": True,
            },
        )
        response.raise_for_status()   # 403 bad key / 5xx: an error, never "no matches"
        attributes = ((response.json().get("response") or {}).get("Attribute")) or []
        attributes = [a for a in attributes if isinstance(a, dict)]
        if not attributes:
            return None

        events: dict[str, str] = {}
        tags: list[str] = []
        types: list[str] = []
        ids_hits = 0
        for attribute in attributes:
            if attribute.get("to_ids") in (True, 1, "1"):
                ids_hits += 1
            event = attribute.get("Event") if isinstance(attribute.get("Event"), dict) else {}
            event_id = str(attribute.get("event_id") or event.get("id") or "")
            if event_id:
                events.setdefault(event_id, event.get("info") or "")
            if attribute.get("type") and attribute["type"] not in types:
                types.append(attribute["type"])
            for tag in attribute.get("Tag") or []:
                name = tag.get("name") if isinstance(tag, dict) else None
                if name and name not in tags:
                    tags.append(name)

        event_count = len(events)
        event_text = f"{event_count} MISP event{'s' if event_count != 1 else ''}"
        if ids_hits:
            verdict = "malicious"
            summary = f"Found in {event_text} and flagged for detection (to_ids) on {ids_hits} matching attribute(s)."
        else:
            verdict = "suspicious"
            summary = f"Found in {event_text} as context only: no matching attribute is flagged for detection (to_ids)."

        return {
            "verdict": verdict,
            "summary": summary,
            "event_count": event_count,
            "attribute_count": len(attributes),
            "to_ids_count": ids_hits,
            "tags": tags,
            "attribute_types": types,
            "events": [{"id": event_id, "info": info} for event_id, info in list(events.items())[:10]],
        }
