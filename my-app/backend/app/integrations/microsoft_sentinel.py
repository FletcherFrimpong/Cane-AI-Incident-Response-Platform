"""Microsoft Sentinel integration for log analytics, incidents, and watchlists."""

import logging
from typing import Any
from app.integrations.base_client import BaseIntegrationClient, OAuth2ClientCredentialsMixin

logger = logging.getLogger("cane_ai.integrations.sentinel")


class MicrosoftSentinelClient(BaseIntegrationClient, OAuth2ClientCredentialsMixin):
    platform_name = "microsoft_sentinel"
    display_name = "Microsoft Sentinel"
    description = "Query logs, manage incidents, and create watchlists in Microsoft Sentinel"
    auth_type = "oauth2_client_credentials"
    required_credentials = ["tenant_id", "client_id", "client_secret"]
    optional_config = ["subscription_id", "resource_group", "workspace_name", "workspace_id"]
    capabilities = [
        "run_kql_query",
        "list_incidents",
        "update_incident",
        "create_watchlist",
        "list_alert_rules",
    ]

    token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _default_scope = "https://management.azure.com/.default"
    LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

    @property
    def _arm_base_url(self) -> str:
        sub = self.config.get("subscription_id", "")
        rg = self.config.get("resource_group", "")
        ws = self.config.get("workspace_name", "")
        return (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        )

    @property
    def _sentinel_base_url(self) -> str:
        return f"{self._arm_base_url}/providers/Microsoft.SecurityInsights"

    async def test_connection(self) -> dict:
        try:
            headers = await self._auth_headers()
            client = await self.get_http_client()

            workspace_id = self.config.get("workspace_id")
            if workspace_id:
                # Test with Log Analytics query
                response = await client.post(
                    f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
                    headers={**headers, "Authorization": f"Bearer {await self._get_log_analytics_token()}"},
                    json={"query": "Heartbeat | take 1"},
                )
                if response.status_code == 200:
                    return {"success": True, "message": "Connected to Sentinel workspace"}

            # Fallback: test ARM access
            response = await client.get(
                f"{self._arm_base_url}?api-version=2022-10-01",
                headers=headers,
            )
            response.raise_for_status()
            return {"success": True, "message": "Connected to Azure Resource Manager"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def _get_log_analytics_token(self) -> str:
        """Get a separate token scoped to Log Analytics."""
        import time
        client = await self.get_http_client()
        response = await client.post(
            self.token_url.format(tenant_id=self.credentials.get("tenant_id", "")),
            data={
                "grant_type": "client_credentials",
                "client_id": self.credentials["client_id"],
                "client_secret": self.credentials["client_secret"],
                "scope": self.LOG_ANALYTICS_SCOPE,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def run_kql_query(self, query: str, timespan: str = "P1D") -> dict:
        """Run a KQL query against the Log Analytics workspace."""
        self._log_action("run_kql_query", {"query": query[:100]})
        if self.dry_run:
            return {"success": True, "message": "[DRY RUN] Would execute KQL query", "results": []}

        workspace_id = self.config.get("workspace_id")
        if not workspace_id:
            return {"success": False, "message": "workspace_id not configured"}

        token = await self._get_log_analytics_token()
        client = await self.get_http_client()
        response = await client.post(
            f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "timespan": timespan},
        )
        response.raise_for_status()
        return {"success": True, "results": response.json()}

    async def list_incidents(self, top: int = 50) -> dict:
        """List Sentinel incidents."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self._sentinel_base_url}/incidents?api-version=2023-11-01&$top={top}&$orderby=properties/createdTimeUtc desc",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    async def update_incident(self, incident_id: str, updates: dict) -> dict:
        """Update a Sentinel incident."""
        self._log_action("update_incident", {"incident_id": incident_id, "updates": updates})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would update incident {incident_id}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.put(
            f"{self._sentinel_base_url}/incidents/{incident_id}?api-version=2023-11-01",
            headers=headers,
            json={"properties": updates},
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}

    async def create_watchlist(self, name: str, items: list[dict]) -> dict:
        """Create a watchlist in Sentinel."""
        self._log_action("create_watchlist", {"name": name, "item_count": len(items)})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would create watchlist '{name}'"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.put(
            f"{self._sentinel_base_url}/watchlists/{name}?api-version=2023-11-01",
            headers=headers,
            json={
                "properties": {
                    "displayName": name,
                    "provider": "Cane AI",
                    "source": "Local",
                    "itemsSearchKey": "key",
                },
            },
        )
        response.raise_for_status()
        return {"success": True, "data": response.json()}
