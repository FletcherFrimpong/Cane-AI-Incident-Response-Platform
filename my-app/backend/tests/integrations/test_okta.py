"""Contract tests for the Okta connector."""

import httpx
import pytest

from app.integrations.okta import OktaClient
from tests.integrations.helpers import Recorder

UID = "00u1ero7vZFVEIYLWPBN"
CREDS = {"domain": "acme.okta.com", "api_token": "okta-secret-token"}


def user(login="jane.doe@acme.com", status="ACTIVE", uid=UID) -> dict:
    return {"id": uid, "status": status, "lastLogin": "2026-11-20T08:00:00.000Z",
            "profile": {"login": login, "email": login, "firstName": "Jane", "lastName": "Doe",
                        "title": "Controller", "department": "Finance", "manager": "Bob Boss"}}


def okta(users: list[dict] | None = None, action_status: int = 200, roles: list[dict] | None = None):
    users = users or []

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/api/v1/users" and req.method == "GET":
            search = req.url.params.get("search", "")
            hits = [u for u in users
                    if search.lower() in (f'profile.login eq "{u["profile"]["login"]}"'.lower(),
                                          f'profile.email eq "{u["profile"]["email"]}"'.lower())]
            return httpx.Response(200, json=hits if search else users[:1])
        if path == f"/api/v1/users/{UID}" and req.method == "GET":
            found = [u for u in users if u["id"] == UID]
            return httpx.Response(200, json=found[0]) if found else httpx.Response(404, json={"errorSummary": "Not found"})
        if path == f"/api/v1/users/{UID}/roles":
            return httpx.Response(200, json=roles or [])
        if path.startswith(f"/api/v1/users/{UID}/") and req.method in ("POST", "DELETE"):
            if action_status >= 400:
                return httpx.Response(action_status, json={
                    "errorCode": "E0000001", "errorSummary": "Api validation failed: suspendUser",
                    "errorCauses": [{"errorSummary": "Cannot suspend a user that is not active"}]})
            return httpx.Response(204) if req.method == "DELETE" else httpx.Response(200, json={})
        return httpx.Response(404, json={"errorSummary": "Not found"})

    return handler


def make(handler, dry_run=False, creds=None):
    client = OktaClient(credentials=dict(creds or CREDS), dry_run=dry_run)
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert OktaClient.platform_name == "okta"
    assert OktaClient.category == "response"
    assert OktaClient.auth_type == "api_key"
    assert OktaClient.required_credentials == ["domain", "api_token"]
    assert set(OktaClient.actions) == {"disable_account", "enable_account", "revoke_sessions", "force_password_reset"}
    assert OktaClient.provides_context == ("user",)
    for method in OktaClient.actions.values():
        assert callable(getattr(OktaClient, method))


@pytest.mark.parametrize("method,http_method,suffix,status", [
    ("disable_account", "POST", "lifecycle/suspend", "ACTIVE"),
    ("enable_account", "POST", "lifecycle/unsuspend", "SUSPENDED"),
    ("revoke_sessions", "DELETE", "sessions", "ACTIVE"),
    ("force_password_reset", "POST", "lifecycle/expire_password", "ACTIVE"),
])
async def test_action_resolves_login_to_id_then_acts(method, http_method, suffix, status):
    client, rec = make(okta([user(status=status)]))
    result = await getattr(client, method)(user_principal_name="Jane.Doe@acme.com")

    assert result["success"] is True and result["user_id"] == UID
    assert rec.paths() == ["GET /api/v1/users", f"{http_method} /api/v1/users/{UID}/{suffix}"]
    lookup, action = rec.requests
    assert lookup.url.host == "acme.okta.com"
    assert lookup.url.params["search"] == 'profile.login eq "Jane.Doe@acme.com"'
    assert lookup.headers["authorization"] == "SSWS okta-secret-token"
    assert action.headers["authorization"] == "SSWS okta-secret-token"
    if method == "revoke_sessions":
        assert action.url.params["oauthTokens"] == "true"


async def test_falls_back_to_email_lookup():
    u = user()
    u["profile"]["login"] = "jdoe"
    client, rec = make(okta([u]))
    result = await client.revoke_sessions(user_principal_name="jane.doe@acme.com")
    assert result["success"] is True
    assert [r.url.params.get("search") for r in rec.requests[:2]] == [
        'profile.login eq "jane.doe@acme.com"', 'profile.email eq "jane.doe@acme.com"']


async def test_okta_id_is_used_directly():
    client, rec = make(okta([user()]))
    result = await client.disable_account(user_principal_name=UID)
    assert result["success"] is True
    assert rec.paths() == [f"GET /api/v1/users/{UID}", f"POST /api/v1/users/{UID}/lifecycle/suspend"]


async def test_unknown_user_is_not_found_and_no_action_sent():
    client, rec = make(okta([user()]))
    result = await client.disable_account(user_principal_name="ghost@acme.com")
    assert result["success"] is False and result["not_found"] is True
    assert all(r.method == "GET" for r in rec.requests)


async def test_ambiguous_email_is_not_acted_on():
    a, b = user(uid=UID), user(uid="00u2222222222222222b")
    a["profile"]["login"], b["profile"]["login"] = "jane1", "jane2"
    client, rec = make(okta([a, b]))
    result = await client.disable_account(user_principal_name="jane.doe@acme.com")
    assert result["success"] is False and result["not_found"] is True
    assert all(r.method == "GET" for r in rec.requests)


async def test_already_in_target_state_makes_no_change():
    client, rec = make(okta([user(status="SUSPENDED")]))
    result = await client.disable_account(user_principal_name="jane.doe@acme.com")
    assert result["success"] is True and "already" in result["message"]
    assert rec.paths() == ["GET /api/v1/users"]


async def test_dry_run_makes_no_request():
    client, rec = make(okta([user()]), dry_run=True)
    for name in OktaClient.actions.values():
        result = await getattr(client, name)(user_principal_name="jane.doe@acme.com")
        assert result["success"] is True and result["dry_run"] is True
    assert rec.requests == []


async def test_vendor_error_is_not_success():
    client, _ = make(okta([user(status="PROVISIONED")], action_status=400))
    result = await client.disable_account(user_principal_name="jane.doe@acme.com")
    assert result["success"] is False and "not_found" not in result
    assert "400" in result["message"] and "Cannot suspend" in result["message"]
    assert "okta-secret-token" not in str(result)


async def test_hostile_login_cannot_change_endpoint():
    client, rec = make(okta([user()]))
    for hostile in (f"{UID}/lifecycle/deactivate?sendEmail=false", "a/../../groups/x", 'x" or status eq "ACTIVE'):
        result = await client.disable_account(user_principal_name=hostile)
        assert result["success"] is False and result["not_found"] is True
    assert {f"{r.method} {r.url.path}" for r in rec.requests} == {"GET /api/v1/users"}
    assert all('or status eq' not in r.url.params.get("search", "") for r in rec.requests)
    assert rec.requests[0].url.params["search"] == f'profile.login eq "{UID}/lifecycle/deactivate?sendEmail=false"'


async def test_describe_user():
    client, rec = make(okta([user()], roles=[{"id": "ra1", "type": "SUPER_ADMIN", "label": "Super Administrator"}]))
    info = await client.describe_user("jane.doe@acme.com")
    assert rec.last.method == "GET" and rec.last.url.path == f"/api/v1/users/{UID}/roles"
    assert info["user_id"] == UID and info["display_name"] == "Jane Doe"
    assert info["job_title"] == "Controller" and info["department"] == "Finance" and info["manager"] == "Bob Boss"
    assert info["account_enabled"] is True and info["is_admin"] is True
    assert info["admin_roles"] == ["Super Administrator"]
    assert await client.describe_user("ghost@acme.com") is None


async def test_describe_user_suspended_non_admin():
    client, _ = make(okta([user(status="SUSPENDED")]))
    info = await client.describe_user("jane.doe@acme.com")
    assert info["account_enabled"] is False and info["is_admin"] is False


async def test_connection_health_and_domain_normalised():
    client, rec = make(okta([user()]), creds={"domain": "https://acme.okta.com/", "api_token": "okta-secret-token"})
    assert (await client.test_connection())["success"] is True
    assert str(rec.last.url).startswith("https://acme.okta.com/api/v1/users?")

    client, _ = make(lambda req: httpx.Response(401, json={"errorSummary": "Invalid token provided"}))
    result = await client.test_connection()
    assert result["success"] is False and "okta-secret-token" not in str(result)
    assert (await client.get_health())["status"] == "error"
