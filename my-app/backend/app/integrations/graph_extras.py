"""Extra Microsoft Graph abilities: describe users and devices, purge an email from mailboxes.

A mixin for a client that provides `BASE_URL` (https://graph.microsoft.com/v1.0),
`_auth_headers()`, `get_http_client()`, `dry_run`, `_dry()` and `_log_action()`.

Graph application permissions needed:
  describe_user  User.Read.All (covers the user, the manager and directory-role membership)
  describe_host  DeviceManagementManagedDevices.Read.All (tenant needs an Intune licence)
  purge_email    Mail.ReadWrite
"""

import re

import httpx

from app.integrations.base_client import seg

_USER_FIELDS = "id,displayName,jobTitle,department,accountEnabled,userPrincipalName,mail"
_DEVICE_FIELDS = (
    "id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,complianceState,"
    "lastSyncDateTime,managedDeviceOwnerType,isEncrypted,model,manufacturer,serialNumber,azureADDeviceId"
)


def _odata_str(value: str) -> str:
    """Quote a value as an OData string literal (a single quote is escaped by doubling it)."""
    return "'" + value.replace("'", "''") + "'"


def _graph_error(e: Exception) -> str:
    """A short, credential-free description of a failed call."""
    if isinstance(e, httpx.HTTPStatusError):
        detail = ""
        try:
            error = e.response.json().get("error") or {}
            detail = ": ".join(str(p) for p in (error.get("code"), error.get("message")) if p)
        except Exception:  # noqa: BLE001 - body is not JSON
            detail = e.response.text[:200]
        return f"HTTP {e.response.status_code}" + (f": {detail[:300]}" if detail else "")
    return type(e).__name__


class GraphExtras:
    """Mix into the Microsoft Graph client."""

    # ---- context ---------------------------------------------------------------

    async def describe_user(self, user_principal_name: str) -> dict | None:
        """Who is this account? None when the directory has no such user."""
        upn = str(user_principal_name).strip()
        if not upn:
            return None
        headers = await self._auth_headers()
        client = await self.get_http_client()
        response = await client.get(
            f"{self.BASE_URL}/users/{seg(upn)}", headers=headers, params={"$select": _USER_FIELDS},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        user = response.json()
        user_ref = seg(user.get("id") or upn)

        manager = None
        try:
            r = await client.get(
                f"{self.BASE_URL}/users/{user_ref}/manager",
                headers=headers, params={"$select": "displayName,userPrincipalName"},
            )
            if r.status_code != 404:  # 404 = no manager set
                r.raise_for_status()
                m = r.json()
                manager = m.get("displayName") or m.get("userPrincipalName")
        except (httpx.HTTPError, ValueError):
            pass

        is_admin: bool | None = None
        admin_roles: list[str] = []
        try:
            r = await client.get(
                f"{self.BASE_URL}/users/{user_ref}/transitiveMemberOf/microsoft.graph.directoryRole",
                # An OData cast on this relationship is an "advanced query": Graph requires both of these.
                headers={**headers, "ConsistencyLevel": "eventual"},
                params={"$count": "true", "$select": "id,displayName"},
            )
            r.raise_for_status()
            roles = r.json().get("value") or []
            admin_roles = [str(x.get("displayName") or x.get("id")) for x in roles]
            is_admin = bool(roles)
        except (httpx.HTTPError, ValueError):
            pass  # unknown rather than a wrong "not an admin"

        return {
            "user_id": user.get("id"),
            "user_principal_name": user.get("userPrincipalName"),
            "display_name": user.get("displayName"),
            "job_title": user.get("jobTitle"),
            "department": user.get("department"),
            "account_enabled": user.get("accountEnabled"),
            "manager": manager,
            "is_admin": is_admin,
            "admin_roles": admin_roles,
        }

    async def describe_host(self, hostname: str) -> dict | None:
        """What is this machine, according to Intune? None when Intune does not manage it."""
        value = str(hostname).strip()
        if not value:
            return None
        candidates = [value]
        short = value.split(".", 1)[0]
        if short and short != value:
            candidates.append(short)

        headers = await self._auth_headers()
        client = await self.get_http_client()
        for name in candidates:
            response = await client.get(
                f"{self.BASE_URL}/deviceManagement/managedDevices",
                headers=headers,
                params={"$filter": f"deviceName eq {_odata_str(name)}", "$select": _DEVICE_FIELDS},
            )
            response.raise_for_status()
            devices = response.json().get("value") or []
            if not devices:
                continue
            d = max(devices, key=lambda x: str(x.get("lastSyncDateTime") or ""))
            os_name = " ".join(str(p) for p in (d.get("operatingSystem"), d.get("osVersion")) if p)
            return {
                "device_id": d.get("id"),
                "hostname": d.get("deviceName"),
                "owner": d.get("userPrincipalName") or d.get("userDisplayName"),
                "owner_name": d.get("userDisplayName"),
                "os": os_name or None,
                "compliance": d.get("complianceState"),
                "last_seen": d.get("lastSyncDateTime"),
                "ownership": d.get("managedDeviceOwnerType"),
                "is_encrypted": d.get("isEncrypted"),
                "model": " ".join(str(p) for p in (d.get("manufacturer"), d.get("model")) if p) or None,
                "serial_number": d.get("serialNumber"),
                "aad_device_id": d.get("azureADDeviceId"),
            }
        return None

    # ---- response action -------------------------------------------------------

    async def purge_email(self, internet_message_id: str, recipients: str) -> dict:
        """Soft-delete one email (by its Internet Message-ID) from each listed mailbox by moving
        it to Deleted Items. `recipients` is a comma-separated list of mailbox addresses."""
        message_id = str(internet_message_id or "").strip()
        mailboxes = list(dict.fromkeys(m.strip() for m in re.split(r"[,;]", str(recipients or "")) if m.strip()))
        self._log_action("purge_email", {"internet_message_id": message_id, "mailboxes": len(mailboxes)})
        if not message_id:
            return {"success": False, "message": "purge_email needs the email's internet_message_id"}
        if not mailboxes:
            return {"success": False, "message": "purge_email needs at least one recipient mailbox"}
        if not (message_id.startswith("<") and message_id.endswith(">")):
            message_id = f"<{message_id}>"  # Graph stores the ID with its angle brackets
        if self.dry_run:
            reply = self._dry(f"move email {message_id} to Deleted Items in {len(mailboxes)} mailbox(es)")
            reply["mailboxes"] = mailboxes
            return reply

        headers = await self._auth_headers()
        client = await self.get_http_client()
        results: list[dict] = []
        for mailbox in mailboxes:
            entry: dict = {"mailbox": mailbox, "removed": 0}
            try:
                found = await client.get(
                    f"{self.BASE_URL}/users/{seg(mailbox)}/messages",
                    headers=headers,
                    params={"$filter": f"internetMessageId eq {_odata_str(message_id)}", "$select": "id"},
                )
                found.raise_for_status()
                messages = found.json().get("value") or []
                if not messages:
                    entry.update(status="not_found", message="No such email in this mailbox")
                    results.append(entry)
                    continue
                failures = 0
                for msg in messages:
                    try:
                        moved = await client.post(
                            f"{self.BASE_URL}/users/{seg(mailbox)}/messages/{seg(msg['id'])}/move",
                            headers=headers,
                            json={"destinationId": "deleteditems"},
                        )
                        moved.raise_for_status()
                        entry["removed"] += 1
                    except (httpx.HTTPError, KeyError) as e:
                        failures += 1
                        entry["message"] = _graph_error(e)
                if entry["removed"]:
                    entry["status"] = "removed" if not failures else "partial"
                    entry.setdefault("message", "Moved to Deleted Items")
                else:
                    entry["status"] = "error"
            except (httpx.HTTPError, ValueError) as e:
                entry.update(status="error", message=_graph_error(e))
            results.append(entry)

        removed = sum(1 for r in results if r["removed"])
        not_found = sum(1 for r in results if r["status"] == "not_found")
        failed = sum(1 for r in results if r["status"] in ("error", "partial"))
        return {
            "success": removed > 0,
            "message": (
                f"Email {message_id} removed from {removed} of {len(mailboxes)} mailbox(es)"
                f" ({not_found} did not have it, {failed} failed)"
            ),
            "removed_count": removed,
            "not_found_count": not_found,
            "failed_count": failed,
            "messages_removed": sum(r["removed"] for r in results),
            "results": results,
        }
