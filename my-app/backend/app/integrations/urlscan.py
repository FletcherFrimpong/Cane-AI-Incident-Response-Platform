"""urlscan.io: read the verdict of the most recent EXISTING scan of a URL or domain."""

import logging

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.urlscan")


def _quote(value: str) -> str:
    """Quote a value as one phrase in urlscan's (Elasticsearch query-string) search syntax."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


class UrlscanClient(BaseIntegrationClient):
    platform_name = "urlscan"
    display_name = "urlscan.io"
    description = (
        "Finds the most recent existing urlscan.io scan of a URL or domain and reads its "
        "verdict. It only searches scans other people already ran and never submits a new "
        "scan: submitting a URL from an incident would publish it and tip off the attacker. "
        "An API key is optional for searching but needed to read verdict details."
    )
    auth_type = "api_key"
    category = "enrichment"
    required_credentials: list[str] = []   # api_key is optional
    optional_credentials = ["api_key"]
    optional_config: list[str] = []
    capabilities = ["enrich_url", "enrich_domain"]
    enriches = ("url", "domain")

    BASE_URL = "https://urlscan.io/api/v1"

    def _headers(self) -> dict:
        api_key = self.credentials.get("api_key")
        return {"api-key": api_key} if api_key else {}

    async def _search(self, query: str):
        client = await self.get_http_client()
        # Results come back newest first, so size=1 is the most recent scan.
        return await client.get(f"{self.BASE_URL}/search/", headers=self._headers(), params={"q": query, "size": 1})

    async def test_connection(self) -> dict:
        try:
            response = await self._search('page.domain:"example.com"')
            if response.status_code in (401, 403):
                return {"success": False, "message": "urlscan.io rejected the API key"}
            if response.status_code == 429:
                return {"success": False, "message": "urlscan.io rate limit reached; add an API key or try later"}
            response.raise_for_status()
            return {"success": True, "message": "Connected to urlscan.io search API"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind == "domain":
            # page.domain is the scanned page itself; plain `domain:` would also match
            # every unrelated page that merely loaded a resource from this domain.
            query = f"page.domain:{_quote(str(value).strip().lower())}"
        elif kind == "url":
            query = f"page.url:{_quote(value)} OR task.url:{_quote(value)}"
        else:
            return None

        response = await self._search(query)
        response.raise_for_status()   # 429 / 4xx / 5xx: an error, never "no scans"
        results = response.json().get("results") or []
        if not results:
            return None
        hit = results[0]
        task = hit.get("task") or {}
        page = hit.get("page") or {}
        scan_id = hit.get("_id") or task.get("uuid")
        scanned_at = task.get("time")

        detail = {
            "scan_id": scan_id,
            "scanned_at": scanned_at,
            "scanned_url": task.get("url"),
            "final_url": page.get("url"),
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "page_country": page.get("country"),
            "page_asn": page.get("asn"),
            "page_asn_name": page.get("asnname"),
            "page_title": page.get("title"),
            "report_url": f"https://urlscan.io/result/{seg(scan_id)}/" if scan_id else None,
            "screenshot_url": hit.get("screenshot"),
        }

        # Search hits carry no verdict; it lives in the scan's result document (a read, not a submission).
        overall = None
        if scan_id:
            client = await self.get_http_client()
            result = await client.get(f"{self.BASE_URL}/result/{seg(scan_id)}/", headers=self._headers())
            if result.status_code in (401, 403, 404, 410):
                # No API key (the result API refuses anonymous callers), or the scan was deleted.
                reason = "the scan was deleted" if result.status_code in (404, 410) else "reading verdicts needs a urlscan API key"
                return {
                    "verdict": "unknown",
                    "summary": f"urlscan.io scanned this {kind} on {scanned_at}, but its verdict could not be read ({reason}).",
                    "verdict_available": False,
                    **detail,
                }
            result.raise_for_status()
            overall = ((result.json().get("verdicts") or {}).get("overall")) or {}

        overall = overall or {}
        score = overall.get("score")
        if overall.get("malicious"):
            verdict = "malicious"
            summary = f"urlscan.io judged the most recent scan of this {kind} ({scanned_at}) malicious (score {score})."
        elif isinstance(score, (int, float)) and score > 0:
            verdict = "suspicious"
            summary = f"urlscan.io gave the most recent scan of this {kind} ({scanned_at}) a risk score of {score} without calling it malicious."
        else:
            verdict = "unknown"
            summary = f"urlscan.io found nothing malicious in the most recent scan of this {kind} ({scanned_at}); that is not proof it is safe."

        return {
            "verdict": verdict,
            "summary": summary,
            "verdict_available": True,
            "score": score,
            "categories": overall.get("categories") or [],
            "brands": overall.get("brands") or [],
            "tags": overall.get("tags") or [],
            **detail,
        }
