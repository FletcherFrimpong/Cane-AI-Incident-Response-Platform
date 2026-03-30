"""Microsoft Defender for Endpoint integration."""

import logging
from typing import Any
from app.integrations.base_client import BaseIntegrationClient, OAuth2ClientCredentialsMixin

logger = logging.getLogger("cane_ai.integrations.defender")


class MicrosoftDefenderClient(BaseIntegrationClient, OAuth2ClientCredentialsMixin):
    platform_name = "microsoft_defender"
    display_name = "Microsoft Defender for Endpoint"
    description = "Isolate machines, run AV scans, block indicators, and collect investigation packages"
    auth_type = "oauth2_client_credentials"
    required_credentials = ["tenant_id", "client_id", "client_secret"]
    optional_config = []
    capabilities = [
        "isolate_machine",
        "release_machine",
        "run_av_scan",
        "block_ip",
        "block_url",
        "block_file_hash",
        "collect_investigation_package",
        "list_alerts",
        "get_machine_info",
    ]

    token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _default_scope = "https://api.securitycenter.microsoft.com/.default"
    BASE_URL = "https://api.securitycenter.microsoft.com/api"

    async def test_connection(self) -> dict:
        try:
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.get(f"{self.BASE_URL}/alerts?$top=1", headers=headers)
            response.raise_for_status()
            return {"success": True, "message": "Connected to Microsoft Defender for Endpoint"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def isolate_machine(self, machine_id: str, comment: str = "Isolated by Cane AI") -> dict:
        """Isolate a machine from the network."""
        self._log_action("isolate_machine", {"machine_id": machine_id})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would isolate machine {machine_id}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/machines/{machine_id}/isolate",
            headers=headers,
            json={"Comment": comment, "IsolationType": "Full"},
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def release_machine(self, machine_id: str, comment: str = "Released by Cane AI") -> dict:
        """Release a machine from isolation."""
        self._log_action("release_machine", {"machine_id": machine_id})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would release machine {machine_id}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/machines/{machine_id}/unisolate",
            headers=headers,
            json={"Comment": comment},
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def run_av_scan(self, machine_id: str, scan_type: str = "Quick") -> dict:
        """Run an antivirus scan on a machine."""
        self._log_action("run_av_scan", {"machine_id": machine_id, "scan_type": scan_type})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would run {scan_type} AV scan on {machine_id}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/machines/{machine_id}/runAntiVirusScan",
            headers=headers,
            json={"Comment": "Scan initiated by Cane AI", "ScanType": scan_type},
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def block_ip(self, ip_address: str, title: str = "Blocked by Cane AI", description: str = "") -> dict:
        """Add an IP indicator to block list."""
        self._log_action("block_ip", {"ip": ip_address})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would block IP {ip_address}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/indicators",
            headers=headers,
            json={
                "indicatorValue": ip_address,
                "indicatorType": "IpAddress",
                "action": "AlertAndBlock",
                "title": title,
                "description": description or f"IP blocked by Cane AI incident response",
                "severity": "High",
                "generateAlert": True,
            },
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def block_url(self, url: str, title: str = "Blocked by Cane AI") -> dict:
        """Add a URL indicator to block list."""
        self._log_action("block_url", {"url": url})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would block URL {url}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/indicators",
            headers=headers,
            json={
                "indicatorValue": url,
                "indicatorType": "Url",
                "action": "AlertAndBlock",
                "title": title,
                "severity": "High",
                "generateAlert": True,
            },
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def block_file_hash(self, file_hash: str, hash_type: str = "Sha256", title: str = "Blocked by Cane AI") -> dict:
        """Block a file by hash."""
        self._log_action("block_file_hash", {"hash": file_hash})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would block file hash {file_hash}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/indicators",
            headers=headers,
            json={
                "indicatorValue": file_hash,
                "indicatorType": "FileSha256" if hash_type.lower() == "sha256" else "FileSha1",
                "action": "AlertAndBlock",
                "title": title,
                "severity": "High",
                "generateAlert": True,
            },
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def collect_investigation_package(self, machine_id: str) -> dict:
        """Collect investigation package from a machine."""
        self._log_action("collect_investigation_package", {"machine_id": machine_id})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would collect investigation package from {machine_id}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/machines/{machine_id}/collectInvestigationPackage",
            headers=headers,
            json={"Comment": "Package collected by Cane AI"},
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def list_alerts(self, top: int = 50) -> dict:
        """List recent alerts."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/alerts?$top={top}&$orderby=alertCreationTime desc",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    async def get_machine_info(self, machine_id: str) -> dict:
        """Get detailed information about a machine."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/machines/{machine_id}",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
