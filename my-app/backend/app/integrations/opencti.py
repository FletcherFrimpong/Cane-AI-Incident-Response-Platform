"""OpenCTI threat-intelligence platform: score and labels for an observable or indicator."""

import logging

from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.opencti")

_INDICATOR_FIELDS = "id name pattern x_opencti_score valid_until revoked objectLabel { value }"

LOOKUP_QUERY = """
query CaneAiLookup($search: String!, $first: Int!) {
  stixCyberObservables(search: $search, first: $first) {
    edges { node {
      id
      entity_type
      observable_value
      x_opencti_score
      x_opencti_description
      created_at
      objectLabel { value }
      indicators(first: 10) { edges { node { %(indicator)s } } }
      ... on StixFile { hashes { algorithm hash } }
    } }
  }
  indicators(search: $search, first: $first) {
    edges { node { %(indicator)s } }
  }
}
""" % {"indicator": _INDICATOR_FIELDS}

ABOUT_QUERY = "query CaneAiAbout { about { version } }"


def _nodes(connection) -> list[dict]:
    edges = (connection or {}).get("edges") or []
    return [e["node"] for e in edges if isinstance(e, dict) and isinstance(e.get("node"), dict)]


def _labels(node: dict) -> list[str]:
    return [l["value"] for l in node.get("objectLabel") or [] if isinstance(l, dict) and l.get("value")]


class OpenCtiClient(BaseIntegrationClient):
    platform_name = "opencti"
    display_name = "OpenCTI"
    description = (
        "Looks up an IP, domain, URL or file hash in your OpenCTI knowledge base and "
        "returns the score and labels of the matching observable and its indicators. Read-only."
    )
    auth_type = "bearer_token"
    category = "enrichment"
    required_credentials = ["base_url", "api_token"]
    optional_config: list[str] = []
    capabilities = ["enrich_ip", "enrich_domain", "enrich_url", "enrich_file_hash"]
    enriches = ("ip", "domain", "url", "file_hash")

    MALICIOUS_SCORE = 70
    SUSPICIOUS_SCORE = 40
    SEARCH_FIRST = 25

    async def _graphql(self, query: str, variables: dict | None = None) -> dict:
        client = await self.get_http_client()
        response = await client.post(
            f"{str(self.credentials['base_url']).rstrip('/')}/graphql",
            headers={"Authorization": f"Bearer {self.credentials['api_token']}"},
            json={"query": query, "variables": variables or {}},
        )
        response.raise_for_status()
        body = response.json()
        # GraphQL reports failures (bad token, missing capability) with HTTP 200 and an errors list.
        if body.get("errors"):
            messages = "; ".join(str(e.get("message", "unknown error")) for e in body["errors"] if isinstance(e, dict))
            raise RuntimeError(f"OpenCTI GraphQL error: {messages or 'unknown error'}")
        return body.get("data") or {}

    async def test_connection(self) -> dict:
        try:
            data = await self._graphql(ABOUT_QUERY)
            version = (data.get("about") or {}).get("version", "unknown")
            return {"success": True, "message": f"Connected to OpenCTI {version}"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind not in self.enriches:
            return None
        wanted = str(value).strip().lower()
        if not wanted:
            return None
        data = await self._graphql(LOOKUP_QUERY, {"search": value, "first": self.SEARCH_FIRST})

        # `search` is full text, so keep only exact matches on the value (or one of a file's hashes).
        observable = None
        for node in _nodes(data.get("stixCyberObservables")):
            hashes = [str(h.get("hash", "")).lower() for h in node.get("hashes") or [] if isinstance(h, dict)]
            if str(node.get("observable_value", "")).lower() == wanted or wanted in hashes:
                observable = node
                break

        indicators: dict[str, dict] = {}
        for node in _nodes((observable or {}).get("indicators")):
            indicators[node.get("id") or node.get("name")] = node
        for node in _nodes(data.get("indicators")):
            pattern = str(node.get("pattern") or "").lower()
            if f"'{wanted}'" in pattern or str(node.get("name") or "").lower() == wanted:
                indicators.setdefault(node.get("id") or node.get("name"), node)
        active = [i for i in indicators.values() if not i.get("revoked")]

        if observable is None and not indicators:
            return None

        scores = [n.get("x_opencti_score") for n in ([observable] if observable else []) + active]
        scores = [s for s in scores if isinstance(s, (int, float))]
        score = max(scores) if scores else None

        labels: list[str] = []
        for node in ([observable] if observable else []) + list(indicators.values()):
            for label in _labels(node):
                if label not in labels:
                    labels.append(label)

        if score is not None and score >= self.MALICIOUS_SCORE:
            verdict = "malicious"
        elif score is not None and score >= self.SUSPICIOUS_SCORE:
            verdict = "suspicious"
        else:
            verdict = "unknown"

        score_text = f"score {score}/100" if score is not None else "no score"
        label_text = f", labelled {', '.join(labels[:5])}" if labels else ""
        indicator_text = f" and {len(active)} active indicator(s)" if active else ""
        known_as = "an observable" if observable else "an indicator"
        summary = f"Known to OpenCTI as {known_as}{indicator_text if observable else ''} with {score_text}{label_text}."

        return {
            "verdict": verdict,
            "summary": summary,
            "score": score,
            "labels": labels,
            "observable_id": observable.get("id") if observable else None,
            "observable_type": observable.get("entity_type") if observable else None,
            "observable_description": observable.get("x_opencti_description") if observable else None,
            "first_seen_in_platform": observable.get("created_at") if observable else None,
            "indicator_count": len(indicators),
            "active_indicator_count": len(active),
            "indicators": [
                {
                    "name": i.get("name"),
                    "pattern": i.get("pattern"),
                    "score": i.get("x_opencti_score"),
                    "valid_until": i.get("valid_until"),
                    "revoked": bool(i.get("revoked")),
                }
                for i in list(indicators.values())[:10]
            ],
        }
