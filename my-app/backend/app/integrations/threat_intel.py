"""Threat intelligence integrations: VirusTotal, AbuseIPDB."""

import logging
from app.integrations.base_client import BaseIntegrationClient

logger = logging.getLogger("cane_ai.integrations.threat_intel")


class VirusTotalClient(BaseIntegrationClient):
    platform_name = "virustotal"
    display_name = "VirusTotal"
    description = "Lookup file hashes, URLs, IPs, and domains for threat intelligence"
    auth_type = "api_key"
    required_credentials = ["api_key"]
    optional_config = []
    capabilities = ["lookup_hash", "lookup_url", "lookup_ip", "lookup_domain"]

    BASE_URL = "https://www.virustotal.com/api/v3"

    async def _auth_headers(self) -> dict:
        return {"x-apikey": self.credentials["api_key"]}

    async def test_connection(self) -> dict:
        try:
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.get(f"{self.BASE_URL}/users/current", headers=headers)
            response.raise_for_status()
            return {"success": True, "message": "Connected to VirusTotal"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def lookup_hash(self, file_hash: str) -> dict:
        """Lookup a file hash on VirusTotal."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/files/{file_hash}", headers=headers)
        if response.status_code == 404:
            return {"found": False, "hash": file_hash}
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", 0),
            "popular_threat_names": data.get("popular_threat_classification", {}).get("suggested_threat_label"),
        }

    async def lookup_ip(self, ip_address: str) -> dict:
        """Lookup an IP address on VirusTotal."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/ip_addresses/{ip_address}", headers=headers)
        if response.status_code == 404:
            return {"found": False, "ip": ip_address}
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "ip": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country": data.get("country"),
            "as_owner": data.get("as_owner"),
            "reputation": data.get("reputation", 0),
        }

    async def lookup_domain(self, domain: str) -> dict:
        """Lookup a domain on VirusTotal."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(f"{self.BASE_URL}/domains/{domain}", headers=headers)
        if response.status_code == 404:
            return {"found": False, "domain": domain}
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": data.get("reputation", 0),
        }


class AbuseIPDBClient(BaseIntegrationClient):
    platform_name = "abuseipdb"
    display_name = "AbuseIPDB"
    description = "Check and report malicious IP addresses"
    auth_type = "api_key"
    required_credentials = ["api_key"]
    optional_config = []
    capabilities = ["check_ip", "report_ip"]

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    async def _auth_headers(self) -> dict:
        return {"Key": self.credentials["api_key"], "Accept": "application/json"}

    async def test_connection(self) -> dict:
        try:
            result = await self.check_ip("8.8.8.8")
            return {"success": True, "message": "Connected to AbuseIPDB"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def check_ip(self, ip_address: str, max_age_days: int = 90) -> dict:
        """Check an IP address against AbuseIPDB."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/check",
            headers=headers,
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": ""},
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip": ip_address,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
        }

    async def report_ip(self, ip_address: str, categories: list[int], comment: str = "") -> dict:
        """Report an IP address to AbuseIPDB."""
        self._log_action("report_ip", {"ip": ip_address})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would report IP {ip_address}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/report",
            headers=headers,
            json={
                "ip": ip_address,
                "categories": ",".join(str(c) for c in categories),
                "comment": comment or "Reported by Cane AI Incident Response Platform",
            },
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}
