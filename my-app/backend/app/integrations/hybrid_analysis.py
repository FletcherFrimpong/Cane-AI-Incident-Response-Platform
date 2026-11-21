"""Hybrid Analysis (Falcon Sandbox public service): existing sandbox verdict for a file hash."""

import logging
import re

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.hybrid_analysis")

_HEX = re.compile(r"^[0-9a-fA-F]+$")

# Hybrid Analysis verdict strings -> platform verdicts. "no specific threat" means the
# sandbox saw nothing notable, which is not the same as a vendor vouching for the file.
_VERDICTS = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "whitelisted": "benign",
    "no specific threat": "unknown",
    "no verdict": "unknown",
}


class HybridAnalysisClient(BaseIntegrationClient):
    platform_name = "hybrid_analysis"
    display_name = "Hybrid Analysis"
    description = (
        "Looks up an existing Hybrid Analysis sandbox report for a file hash and returns "
        "its verdict, threat score and malware family. Never uploads files."
    )
    auth_type = "api_key"
    category = "enrichment"
    required_credentials = ["api_key"]
    optional_config: list[str] = []
    capabilities = ["enrich_file_hash"]
    enriches = ("file_hash",)

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    def _headers(self) -> dict:
        # The API rejects requests without a recognised User-Agent; "Falcon Sandbox" is the documented one.
        return {
            "api-key": self.credentials["api_key"],
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(f"{self.BASE_URL}/key/current", headers=self._headers())
            if response.status_code in (401, 403):
                return {"success": False, "message": "Hybrid Analysis rejected the API key"}
            response.raise_for_status()
            return {"success": True, "message": "Connected to Hybrid Analysis"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def _sha256_for(self, file_hash: str) -> str | None:
        """Resolve an MD5 or SHA-1 to the SHA-256 the overview endpoint needs."""
        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/search/hash", headers=self._headers(), params={"hash": file_hash})
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        # Tolerate both known shapes: a bare list of reports, or {"sha256s": [...], "reports": [...]}.
        if isinstance(data, dict):
            for sha256 in data.get("sha256s") or []:
                if sha256:
                    return str(sha256)
            data = data.get("reports") or data.get("result") or []
        for report in data if isinstance(data, list) else []:
            if isinstance(report, dict) and report.get("sha256"):
                return str(report["sha256"])
        return None

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind != "file_hash":
            return None
        file_hash = str(value).strip().lower()
        if not _HEX.match(file_hash) or len(file_hash) not in (32, 40, 64):
            return None
        sha256 = file_hash if len(file_hash) == 64 else await self._sha256_for(file_hash)
        if not sha256:
            return None

        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/overview/{seg(sha256)}", headers=self._headers())
        if response.status_code == 404:
            return None   # never analysed
        response.raise_for_status()   # 401 / 429 / 5xx: an error, never "clean"
        data = response.json()
        if not isinstance(data, dict) or not data.get("sha256"):
            return None

        raw_verdict = str(data.get("verdict") or "no verdict").lower()
        verdict = _VERDICTS.get(raw_verdict, "unknown")
        threat_score = data.get("threat_score")
        family = data.get("vx_family")
        file_name = data.get("last_file_name")

        subject = f"file {file_name}" if file_name else "this file"
        score_text = f" with threat score {threat_score}/100" if threat_score is not None else ""
        family_text = f", malware family {family}" if family else ""
        if verdict in ("malicious", "suspicious"):
            summary = f"Hybrid Analysis sandboxed {subject} and rated it {raw_verdict}{score_text}{family_text}."
        elif verdict == "benign":
            summary = f"Hybrid Analysis has {subject} on its whitelist of known good files."
        else:
            summary = f"Hybrid Analysis sandboxed {subject} and found no specific threat{score_text}; that is not proof it is safe."

        return {
            "verdict": verdict,
            "summary": summary,
            "sandbox_verdict": raw_verdict,
            "threat_score": threat_score,
            "malware_family": family,
            "av_detection_percent": data.get("multiscan_result"),
            "sha256": data.get("sha256"),
            "file_name": file_name,
            "file_type": data.get("type"),
            "size": data.get("size"),
            "tags": data.get("tags") or [],
            "analysed_at": data.get("analysis_start_time"),
            "report_url": f"https://www.hybrid-analysis.com/sample/{seg(data.get('sha256'))}",
        }
