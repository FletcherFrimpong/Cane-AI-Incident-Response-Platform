"""Okta integration: suspend/unsuspend users, clear sessions, expire passwords, describe users.

API shapes follow Okta's published management OpenAPI spec:
  GET    /api/v1/users?search=profile.login eq "<login>"   -> [ {user...} ]
  GET    /api/v1/users/{id}
  POST   /api/v1/users/{id}/lifecycle/suspend              (only for ACTIVE users)
  POST   /api/v1/users/{id}/lifecycle/unsuspend            (only for SUSPENDED users)
  DELETE /api/v1/users/{id}/sessions?oauthTokens=true      -> 204
  POST   /api/v1/users/{id}/lifecycle/expire_password
  GET    /api/v1/users/{id}/roles                          -> [ {role...} ]
Auth header: `Authorization: SSWS <api token>`.

Users are always looked up through the list endpoint and then addressed by ID: Okta
cannot fetch a login containing "/" through the URL path.
"""

import logging
import re

import httpx

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.okta")

_USER_ID = re.compile(r"00u[A-Za-z0-9]{17}")


def _vendor_error(e: Exception) -> str:
    """A short, credential-free description of a failed call."""
    if isinstance(e, httpx.HTTPStatusError):
        detail = ""
        try:
            body = e.response.json()
            detail = str(body.get("errorSummary") or "")
            causes = [str(c.get("errorSummary", "")) for c in body.get("errorCauses") or [] if isinstance(c, dict)]
            if causes:
                detail = f"{detail} ({'; '.join(causes)})"
        except Exception:  # noqa: BLE001 - body is not JSON
            detail = e.response.text[:200]
        return f"HTTP {e.response.status_code}" + (f": {detail[:300]}" if detail else "")
    return type(e).__name__


class OktaClient(BaseIntegrationClient):
    platform_name = "okta"
    display_name = "Okta"
    description = (
        "Suspend and unsuspend Okta users, clear their sessions, expire their password, and look up "
        "who an account belongs to."
    )
    auth_type = "api_key"
    category = "response"
    required_credentials = ["domain", "api_token"]
    optional_config = []
    capabilities = [
        "disable_account", "enable_account", "revoke_sessions", "force_password_reset", "describe_user",
    ]
    actions = {
        "disable_account": "disable_account",
        "enable_account": "enable_account",
        "revoke_sessions": "revoke_sessions",
        "force_password_reset": "force_password_reset",
    }
    provides_context = ("user",)

    @property
    def base_url(self) -> str:
        domain = str(self.credentials.get("domain", "")).strip()
        domain = domain.split("://", 1)[-1].split("/", 1)[0]
        return f"https://{domain}/api/v1"

    def _auth_headers(self) -> dict:
        return {"Authorization": f"SSWS {self.credentials['api_token']}", "Accept": "application/json"}

    # ---- health ----------------------------------------------------------------

    async def test_connection(self) -> dict:
        try:
            client = await self.get_http_client()
            response = await client.get(f"{self.base_url}/users", headers=self._auth_headers(), params={"limit": 1})
            response.raise_for_status()
            return {"success": True, "message": "Connected to Okta"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "message": f"Connection failed: {_vendor_error(e)}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    # ---- user lookup -----------------------------------------------------------

    async def _find_user(self, login_or_id: str) -> dict | None:
        """Login, email or Okta user ID -> the user record. None when Okta has no such user."""
        value = str(login_or_id).strip()
        client = await self.get_http_client()
        if _USER_ID.fullmatch(value):
            response = await client.get(f"{self.base_url}/users/{seg(value)}", headers=self._auth_headers())
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()

        # A quote or backslash cannot be part of a login and would break out of the quoted value.
        if not value or '"' in value or "\\" in value:
            return None
        for attribute in ("profile.login", "profile.email"):
            response = await client.get(
                f"{self.base_url}/users",
                headers=self._auth_headers(),
                params={"search": f'{attribute} eq "{value}"', "limit": 5},
            )
            response.raise_for_status()
            users = response.json()
            if not isinstance(users, list) or not users:
                continue
            key = attribute.split(".", 1)[1]
            exact = [u for u in users if str((u.get("profile") or {}).get(key, "")).lower() == value.lower()]
            if len(exact) == 1:
                return exact[0]
            if len(exact) > 1:
                # Several accounts share this email: refuse to guess which one to act on.
                return None
        return None

    async def describe_user(self, user_principal_name: str) -> dict | None:
        user = await self._find_user(user_principal_name)
        if not user:
            return None
        profile = user.get("profile") or {}
        status = user.get("status")
        display_name = profile.get("displayName") or " ".join(
            p for p in (profile.get("firstName"), profile.get("lastName")) if p
        )

        is_admin: bool | None = None
        admin_roles: list[str] = []
        try:
            client = await self.get_http_client()
            response = await client.get(
                f"{self.base_url}/users/{seg(user.get('id'))}/roles", headers=self._auth_headers(),
            )
            response.raise_for_status()
            roles = response.json()
            admin_roles = [str(r.get("label") or r.get("type")) for r in roles if isinstance(r, dict)]
            is_admin = bool(admin_roles)
        except (httpx.HTTPError, ValueError):
            pass  # the token may not be allowed to read role assignments; leave is_admin unknown

        return {
            "user_id": user.get("id"),
            "login": profile.get("login"),
            "email": profile.get("email"),
            "display_name": display_name or None,
            "job_title": profile.get("title"),
            "department": profile.get("department"),
            "manager": profile.get("manager") or profile.get("managerId"),
            "account_enabled": status not in ("SUSPENDED", "DEPROVISIONED"),
            "status": status,
            "is_admin": is_admin,
            "admin_roles": admin_roles,
            "last_sign_in": user.get("lastLogin"),
        }

    # ---- response actions ------------------------------------------------------

    async def _user_action(
        self, user: str, name: str, method: str, suffix: str, verb: str, done: str,
        params: dict | None = None, already_when: str | None = None,
    ) -> dict:
        self._log_action(name, {"user": user})
        if self.dry_run:
            return self._dry(f"{verb} Okta user {user}")
        try:
            record = await self._find_user(user)
            if not record or not record.get("id"):
                return {"success": False, "not_found": True, "message": f"Okta has no user '{user}'"}
            user_id = str(record["id"])
            if already_when and record.get("status") == already_when:
                return {"success": True, "user_id": user_id,
                        "message": f"Okta user {user} is already {already_when.lower()}; nothing to do"}
            client = await self.get_http_client()
            response = await client.request(
                method, f"{self.base_url}/users/{seg(user_id)}/{suffix}",
                headers=self._auth_headers(), params=params,
            )
            response.raise_for_status()
            return {"success": True, "user_id": user_id, "message": f"Okta user {user} {done}"}
        except (httpx.HTTPError, KeyError, ValueError) as e:
            return {"success": False, "message": f"Okta could not {verb} {user}: {_vendor_error(e)}"}

    async def disable_account(self, user_principal_name: str) -> dict:
        """Suspend the user: they cannot sign in, group and app assignments are kept."""
        return await self._user_action(
            user_principal_name, "disable_account", "POST", "lifecycle/suspend", "suspend", "suspended",
            already_when="SUSPENDED",
        )

    async def enable_account(self, user_principal_name: str) -> dict:
        """Unsuspend the user (back to ACTIVE)."""
        return await self._user_action(
            user_principal_name, "enable_account", "POST", "lifecycle/unsuspend", "unsuspend", "unsuspended",
            already_when="ACTIVE",
        )

    async def revoke_sessions(self, user_principal_name: str) -> dict:
        """End all the user's Okta sessions and revoke their OAuth/OIDC tokens."""
        return await self._user_action(
            user_principal_name, "revoke_sessions", "DELETE", "sessions", "revoke sessions for",
            "sessions and tokens revoked", params={"oauthTokens": "true"},
        )

    async def force_password_reset(self, user_principal_name: str) -> dict:
        """Expire the password: the user must change it at next sign-in."""
        return await self._user_action(
            user_principal_name, "force_password_reset", "POST", "lifecycle/expire_password",
            "expire the password of", "must change their password at next sign-in",
        )
