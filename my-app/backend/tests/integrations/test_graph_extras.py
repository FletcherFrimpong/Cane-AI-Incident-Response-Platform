"""Contract tests for the GraphExtras mixin."""

import httpx
import pytest

from app.integrations.base_client import BaseIntegrationClient
from app.integrations.graph_extras import GraphExtras
from tests.integrations.helpers import Recorder

V1 = "/v1.0"
MSG_ID = "<abc123@mail.evil.example>"


class Host(GraphExtras, BaseIntegrationClient):
    platform_name = "microsoft_graph"
    BASE_URL = "https://graph.microsoft.com/v1.0"

    async def _auth_headers(self) -> dict:
        return {"Authorization": "Bearer test-token"}

    async def test_connection(self) -> dict:
        return {"success": True, "message": "ok"}

    async def get_health(self) -> dict:
        return {"status": "healthy"}


def make(handler, dry_run=False):
    client = Host(credentials={}, dry_run=dry_run)
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


# ---- describe_user ---------------------------------------------------------------

def directory(roles: list[dict] | None = None, manager: dict | None = None, roles_status: int = 200):
    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == f"{V1}/users/jane@contoso.com":
            return httpx.Response(200, json={
                "id": "u-1", "displayName": "Jane Doe", "jobTitle": "Controller", "department": "Finance",
                "accountEnabled": True, "userPrincipalName": "jane@contoso.com"})
        if path == f"{V1}/users/u-1/manager":
            return httpx.Response(200, json=manager) if manager else httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})
        if path == f"{V1}/users/u-1/transitiveMemberOf/microsoft.graph.directoryRole":
            return httpx.Response(roles_status, json={"value": roles or []})
        return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})

    return handler


async def test_describe_user_requests_and_result():
    client, rec = make(directory(
        roles=[{"id": "r1", "displayName": "Global Administrator"}],
        manager={"displayName": "Bob Boss", "userPrincipalName": "bob@contoso.com"},
    ))
    info = await client.describe_user("jane@contoso.com")

    assert rec.paths() == [
        f"GET {V1}/users/jane@contoso.com",
        f"GET {V1}/users/u-1/manager",
        f"GET {V1}/users/u-1/transitiveMemberOf/microsoft.graph.directoryRole",
    ]
    assert all(r.headers["authorization"] == "Bearer test-token" for r in rec.requests)
    assert "accountEnabled" in rec.requests[0].url.params["$select"]
    roles_req = rec.last
    assert roles_req.headers["consistencylevel"] == "eventual" and roles_req.url.params["$count"] == "true"
    assert info == {
        "user_id": "u-1", "user_principal_name": "jane@contoso.com", "display_name": "Jane Doe",
        "job_title": "Controller", "department": "Finance", "account_enabled": True,
        "manager": "Bob Boss", "is_admin": True, "admin_roles": ["Global Administrator"],
    }


async def test_describe_user_without_manager_or_roles():
    client, _ = make(directory())
    info = await client.describe_user("jane@contoso.com")
    assert info["manager"] is None and info["is_admin"] is False and info["admin_roles"] == []


async def test_describe_user_admin_unknown_when_roles_unreadable():
    client, _ = make(directory(roles_status=403))
    assert (await client.describe_user("jane@contoso.com"))["is_admin"] is None


async def test_describe_user_unknown_and_hostile():
    client, rec = make(directory())
    assert await client.describe_user("ghost@contoso.com") is None
    assert await client.describe_user("jane@contoso.com/revokeSignInSessions?x=1") is None
    assert rec.last.url.raw_path.startswith(b"/v1.0/users/jane%40contoso.com%2FrevokeSignInSessions%3Fx%3D1")
    assert all(r.method == "GET" for r in rec.requests)


async def test_describe_user_vendor_error_is_raised():
    client, _ = make(lambda req: httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}}))
    with pytest.raises(httpx.HTTPStatusError):
        await client.describe_user("jane@contoso.com")


# ---- describe_host ---------------------------------------------------------------

def intune(devices: list[dict]):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == f"{V1}/deviceManagement/managedDevices":
            flt = req.url.params["$filter"]
            return httpx.Response(200, json={"value": [d for d in devices if flt == f"deviceName eq '{d['deviceName']}'"]})
        return httpx.Response(404, json={"error": {"code": "NotFound"}})

    return handler


DEVICE = {"id": "dev-1", "deviceName": "LAPTOP-7", "userPrincipalName": "jane@contoso.com", "userDisplayName": "Jane Doe",
          "operatingSystem": "Windows", "osVersion": "10.0.22631", "complianceState": "noncompliant",
          "lastSyncDateTime": "2026-11-20T09:00:00Z", "managedDeviceOwnerType": "company", "isEncrypted": True,
          "manufacturer": "Dell", "model": "Latitude 7440", "serialNumber": "SN1", "azureADDeviceId": "aad-1"}


async def test_describe_host_from_intune():
    client, rec = make(intune([DEVICE, {**DEVICE, "id": "old", "lastSyncDateTime": "2024-01-01T00:00:00Z"}]))
    info = await client.describe_host("LAPTOP-7.contoso.com")

    assert rec.paths() == [f"GET {V1}/deviceManagement/managedDevices"] * 2
    assert [r.url.params["$filter"] for r in rec.requests] == [
        "deviceName eq 'LAPTOP-7.contoso.com'", "deviceName eq 'LAPTOP-7'"]
    assert rec.last.headers["authorization"] == "Bearer test-token"
    assert info["device_id"] == "dev-1" and info["owner"] == "jane@contoso.com"
    assert info["os"] == "Windows 10.0.22631" and info["compliance"] == "noncompliant"
    assert info["last_seen"] == "2026-11-20T09:00:00Z"


async def test_describe_host_unknown_and_hostile():
    client, rec = make(intune([DEVICE]))
    assert await client.describe_host("ghost") is None
    assert await client.describe_host("x' or deviceName eq 'LAPTOP-7") is None
    assert rec.last.url.params["$filter"] == "deviceName eq 'x'' or deviceName eq ''LAPTOP-7'"
    assert await client.describe_host("LAPTOP-7/wipe?x=1") is None
    assert {r.url.path for r in rec.requests} == {f"{V1}/deviceManagement/managedDevices"}


# ---- purge_email -----------------------------------------------------------------

def exchange(mailboxes: dict[str, list[str]], move_status: int = 201):
    """`mailboxes` maps mailbox -> IDs of messages carrying MSG_ID. Unknown mailboxes answer 404."""
    def handler(req: httpx.Request) -> httpx.Response:
        parts = req.url.path.split("/")          # '', 'v1.0', 'users', mailbox, 'messages', [id, 'move']
        mailbox = parts[3] if len(parts) > 4 and parts[2] == "users" and parts[4] == "messages" else None
        if mailbox not in mailboxes:
            return httpx.Response(404, json={"error": {"code": "ErrorInvalidUser", "message": "mailbox not found"}})
        if req.method == "GET" and len(parts) == 5:
            hit = req.url.params["$filter"] == f"internetMessageId eq '{MSG_ID}'"
            return httpx.Response(200, json={"value": [{"id": i} for i in mailboxes[mailbox]] if hit else []})
        if req.method == "POST" and len(parts) == 7 and parts[6] == "move":
            if move_status != 201:
                return httpx.Response(move_status, json={"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}})
            return httpx.Response(201, json={"id": "new-id"})
        return httpx.Response(400, json={"error": {"code": "BadRequest"}})

    return handler


async def test_purge_email_moves_message_in_each_mailbox():
    client, rec = make(exchange({"a@contoso.com": ["m1"], "b@contoso.com": ["m2", "m3"], "c@contoso.com": []}))
    result = await client.purge_email(
        internet_message_id=MSG_ID, recipients="a@contoso.com, b@contoso.com,c@contoso.com, a@contoso.com,ghost@contoso.com")

    assert rec.paths() == [
        f"GET {V1}/users/a@contoso.com/messages",
        f"POST {V1}/users/a@contoso.com/messages/m1/move",
        f"GET {V1}/users/b@contoso.com/messages",
        f"POST {V1}/users/b@contoso.com/messages/m2/move",
        f"POST {V1}/users/b@contoso.com/messages/m3/move",
        f"GET {V1}/users/c@contoso.com/messages",
        f"GET {V1}/users/ghost@contoso.com/messages",
    ]
    assert all(r.headers["authorization"] == "Bearer test-token" for r in rec.requests)
    assert rec.requests[0].url.params["$filter"] == f"internetMessageId eq '{MSG_ID}'"
    assert rec.json(rec.requests[1]) == {"destinationId": "deleteditems"}

    assert result["success"] is True
    assert (result["removed_count"], result["not_found_count"], result["failed_count"]) == (2, 1, 1)
    assert result["messages_removed"] == 3
    by_mailbox = {r["mailbox"]: r for r in result["results"]}
    assert list(by_mailbox) == ["a@contoso.com", "b@contoso.com", "c@contoso.com", "ghost@contoso.com"]
    assert by_mailbox["a@contoso.com"]["status"] == "removed" and by_mailbox["b@contoso.com"]["removed"] == 2
    assert by_mailbox["c@contoso.com"]["status"] == "not_found"
    assert by_mailbox["ghost@contoso.com"]["status"] == "error" and "404" in by_mailbox["ghost@contoso.com"]["message"]


async def test_purge_email_adds_missing_angle_brackets():
    client, rec = make(exchange({"a@contoso.com": ["m1"]}))
    result = await client.purge_email(internet_message_id="abc123@mail.evil.example", recipients="a@contoso.com")
    assert result["success"] is True
    assert rec.requests[0].url.params["$filter"] == f"internetMessageId eq '{MSG_ID}'"


async def test_purge_email_found_nowhere_is_not_success():
    client, rec = make(exchange({"a@contoso.com": [], "b@contoso.com": []}))
    result = await client.purge_email(internet_message_id=MSG_ID, recipients="a@contoso.com,b@contoso.com")
    assert result["success"] is False and result["removed_count"] == 0 and result["not_found_count"] == 2
    assert all(r.method == "GET" for r in rec.requests)


async def test_purge_email_vendor_error_is_not_success():
    client, _ = make(exchange({"a@contoso.com": ["m1"]}, move_status=403))
    result = await client.purge_email(internet_message_id=MSG_ID, recipients="a@contoso.com")
    assert result["success"] is False and result["failed_count"] == 1
    assert result["results"][0]["status"] == "error" and "ErrorAccessDenied" in result["results"][0]["message"]


async def test_purge_email_dry_run_makes_no_request():
    client, rec = make(exchange({"a@contoso.com": ["m1"]}), dry_run=True)
    result = await client.purge_email(internet_message_id=MSG_ID, recipients="a@contoso.com,b@contoso.com")
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")
    assert result["mailboxes"] == ["a@contoso.com", "b@contoso.com"]
    assert rec.requests == []


async def test_purge_email_requires_inputs():
    client, rec = make(exchange({}))
    assert (await client.purge_email(internet_message_id="", recipients="a@contoso.com"))["success"] is False
    assert (await client.purge_email(internet_message_id=MSG_ID, recipients=" , "))["success"] is False
    assert rec.requests == []


async def test_purge_email_hostile_values_are_encoded():
    seen_ids = {"a@contoso.com": ["AAMk/x?y=1+z="]}
    client, rec = make(exchange(seen_ids))
    # Message ID with a quote stays inside the OData string; mailbox and message id stay one path segment each.
    await client.purge_email(internet_message_id="<a'b@x>", recipients="a@contoso.com/mailFolders?x=1")
    assert rec.last.url.raw_path.startswith(b"/v1.0/users/a%40contoso.com%2FmailFolders%3Fx%3D1/messages?")
    assert rec.last.url.params["$filter"] == "internetMessageId eq '<a''b@x>'"

    await client.purge_email(internet_message_id=MSG_ID, recipients="a@contoso.com")
    assert rec.last.method == "POST"
    assert rec.last.url.raw_path == b"/v1.0/users/a%40contoso.com/messages/AAMk%2Fx%3Fy%3D1%2Bz%3D/move"
