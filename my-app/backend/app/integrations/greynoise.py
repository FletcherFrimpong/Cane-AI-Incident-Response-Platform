"""GreyNoise Community API: is this IP internet background noise or a known benign service?"""

import logging

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.greynoise")


class GreyNoiseClient(BaseIntegrationClient):
    platform_name = "greynoise"
    display_name = "GreyNoise"
    description = (
        "Tells you whether an IP is internet background noise (mass scanners) or a known "
        "benign service, which is what lets an analyst close a false positive. Uses the "
        "Community API; an API key is optional and only raises the rate limit."
    )
    auth_type = "api_key"
    category = "enrichment"
    required_credentials: list[str] = []   # api_key is optional
    optional_credentials = ["api_key"]
    optional_config: list[str] = []
    capabilities = ["enrich_ip"]
    enriches = ("ip",)

    BASE_URL = "https://api.greynoise.io/v3/community"
    TEST_IP = "8.8.8.8"

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        api_key = self.credentials.get("api_key")
        if api_key:
            headers["key"] = api_key
        return headers

    async def _lookup(self, ip: str):
        client = await self.get_http_client()
        return await client.get(f"{self.BASE_URL}/{seg(ip)}", headers=self._headers())

    async def test_connection(self) -> dict:
        try:
            response = await self._lookup(self.TEST_IP)
            # 404 is the API's normal "we have nothing on this IP" answer, so it proves the call works.
            if response.status_code == 404:
                return {"success": True, "message": "Connected to GreyNoise Community API"}
            if response.status_code == 429:
                return {"success": False, "message": "GreyNoise rate limit reached; add an API key or try later"}
            if response.status_code in (401, 403):
                return {"success": False, "message": "GreyNoise rejected the API key"}
            response.raise_for_status()
            return {"success": True, "message": "Connected to GreyNoise Community API"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind != "ip":
            return None
        response = await self._lookup(value)
        if response.status_code == 404:
            return None   # not observed scanning and not in the benign-service (RIOT) set
        response.raise_for_status()   # 429 rate limit, 401 bad key, 5xx: an error, never "clean"
        data = response.json()

        noise = bool(data.get("noise"))
        riot = bool(data.get("riot"))
        if not noise and not riot:
            return None
        classification = str(data.get("classification") or "unknown").lower()
        name = data.get("name") if data.get("name") not in (None, "", "unknown") else None

        if riot:
            verdict = "benign"
            summary = (
                f"{value} belongs to a known benign service ({name or 'common business service'}): "
                "traffic to or from it is almost certainly not an attack, so an alert on it alone is likely a false positive."
            )
        elif classification == "malicious":
            verdict = "malicious"
            summary = (
                f"{value} is an internet-wide scanner GreyNoise classifies as malicious: "
                "it attacks everyone opportunistically, so this is background noise rather than something aimed at you."
            )
        elif classification == "benign":
            verdict = "benign"
            summary = (
                f"{value} is a known benign internet scanner ({name or 'research or search engine'}): "
                "background noise that hits everyone, so an alert on it alone is likely a false positive."
            )
        else:
            verdict = "unknown"
            summary = (
                f"{value} is internet background noise: it scans the whole internet rather than targeting you, "
                "but GreyNoise has not classified its intent."
            )

        return {
            "verdict": verdict,
            "summary": summary,
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "name": name,
            "last_seen": data.get("last_seen"),
            "link": data.get("link"),
        }
