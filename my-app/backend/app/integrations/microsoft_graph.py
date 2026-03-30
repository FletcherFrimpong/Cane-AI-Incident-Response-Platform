"""Microsoft Graph API integration for user management and security alerts."""

import logging
from typing import Any
from app.integrations.base_client import BaseIntegrationClient, OAuth2ClientCredentialsMixin

logger = logging.getLogger("cane_ai.integrations.graph")


class MicrosoftGraphClient(BaseIntegrationClient, OAuth2ClientCredentialsMixin):
    platform_name = "microsoft_graph"
    display_name = "Microsoft Graph Security"
    description = "Manage users, security alerts, and identity via Microsoft Graph API"
    auth_type = "oauth2_client_credentials"
    required_credentials = ["tenant_id", "client_id", "client_secret"]
    optional_config = []
    capabilities = [
        "disable_user",
        "enable_user",
        "revoke_sessions",
        "force_password_reset",
        "read_security_alerts",
        "update_security_alert",
        "read_risky_users",
    ]

    token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _default_scope = "https://graph.microsoft.com/.default"
    BASE_URL = "https://graph.microsoft.com/v1.0"

    async def test_connection(self) -> dict:
        try:
            headers = await self._auth_headers()
            client = await self.get_http_client()
            response = await client.get(f"{self.BASE_URL}/organization", headers=headers)
            response.raise_for_status()
            org = response.json().get("value", [{}])[0]
            return {
                "success": True,
                "message": f"Connected to {org.get('displayName', 'Microsoft Graph')}",
                "details": {"tenant": org.get("id"), "name": org.get("displayName")},
            }
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {
            "status": "healthy" if result["success"] else "error",
            "message": result["message"],
        }

    async def disable_user(self, user_principal_name: str) -> dict:
        """Disable a user account in Azure AD."""
        self._log_action("disable_user", {"user": user_principal_name})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would disable user {user_principal_name}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.patch(
            f"{self.BASE_URL}/users/{user_principal_name}",
            headers=headers,
            json={"accountEnabled": False},
        )
        response.raise_for_status()
        return {"success": True, "message": f"User {user_principal_name} disabled"}

    async def enable_user(self, user_principal_name: str) -> dict:
        """Enable a user account."""
        self._log_action("enable_user", {"user": user_principal_name})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would enable user {user_principal_name}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.patch(
            f"{self.BASE_URL}/users/{user_principal_name}",
            headers=headers,
            json={"accountEnabled": True},
        )
        response.raise_for_status()
        return {"success": True, "message": f"User {user_principal_name} enabled"}

    async def revoke_sessions(self, user_principal_name: str) -> dict:
        """Revoke all sign-in sessions for a user."""
        self._log_action("revoke_sessions", {"user": user_principal_name})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would revoke sessions for {user_principal_name}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.post(
            f"{self.BASE_URL}/users/{user_principal_name}/revokeSignInSessions",
            headers=headers,
        )
        response.raise_for_status()
        return {"success": True, "message": f"All sessions revoked for {user_principal_name}"}

    async def force_password_reset(self, user_principal_name: str) -> dict:
        """Force user to change password on next sign-in."""
        self._log_action("force_password_reset", {"user": user_principal_name})
        if self.dry_run:
            return {"success": True, "message": f"[DRY RUN] Would force password reset for {user_principal_name}"}

        headers = await self._auth_headers()
        client = await self.get_http_client()
        # Set forceChangePasswordNextSignIn
        response = await client.patch(
            f"{self.BASE_URL}/users/{user_principal_name}",
            headers=headers,
            json={"passwordProfile": {"forceChangePasswordNextSignIn": True}},
        )
        response.raise_for_status()
        return {"success": True, "message": f"Password reset forced for {user_principal_name}"}

    async def read_security_alerts(self, top: int = 50) -> dict:
        """Read security alerts from Microsoft Graph Security API."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/security/alerts_v2",
            headers=headers,
            params={"$top": top, "$orderby": "createdDateTime desc"},
        )
        response.raise_for_status()
        return response.json()

    async def read_risky_users(self) -> dict:
        """Read risky users from Identity Protection."""
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/identityProtection/riskyUsers",
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
