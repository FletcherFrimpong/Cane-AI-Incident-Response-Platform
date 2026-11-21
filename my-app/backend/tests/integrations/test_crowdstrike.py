"""Contract tests for the CrowdStrike Falcon connector."""

import httpx

from app.integrations.crowdstrike import CrowdStrikeClient
from tests.integrations.helpers import Recorder

AID = "0123456789abcdef0123456789abcdef"
CREDS = {"client_id": "cid-123", "client_secret": "s3cr3t-value"}


def falcon(known: dict[str, str] | None = None, action_status: int = 202, action_body: dict | None = None):
    """A fake Falcon API. `known` maps hostname -> agent ID."""
    known = known or {}

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "tok-abc", "expires_in": 1799})
        if path == "/devices/queries/devices/v1":
            flt = req.url.params.get("filter", "")
            ids = [aid for name, aid in known.items() if flt == f"hostname:['{name}']"]
            return httpx.Response(200, json={"resources": ids, "errors": []})
        if path == "/devices/entities/devices/v2":
            return httpx.Response(200, json={"resources": [{
                "device_id": req.url.params["ids"], "hostname": "WEB-01", "platform_name": "Windows",
                "os_version": "Windows Server 2022", "status": "contained", "last_seen": "2026-11-20T10:00:00Z",
                "last_login_user": "svc-web", "local_ip": "10.0.0.5", "external_ip": "198.51.100.9",
            }]})
        if path == "/devices/entities/devices-actions/v2":
            return httpx.Response(action_status, json=action_body or {"resources": [{"id": AID}], "errors": []})
        return httpx.Response(404, json={"errors": [{"message": "no route"}]})

    return handler


def make(handler, dry_run=False, config=None):
    client = CrowdStrikeClient(credentials=dict(CREDS), config=config or {}, dry_run=dry_run)
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert CrowdStrikeClient.platform_name == "crowdstrike"
    assert CrowdStrikeClient.category == "response"
    assert CrowdStrikeClient.auth_type == "oauth2_client_credentials"
    assert CrowdStrikeClient.actions == {"isolate_host": "isolate_host", "release_host": "release_host"}
    assert CrowdStrikeClient.provides_context == ("host",)
    assert CrowdStrikeClient.required_credentials == ["client_id", "client_secret"]
    for method in CrowdStrikeClient.actions.values():
        assert callable(getattr(CrowdStrikeClient, method))


async def test_isolate_resolves_hostname_then_contains():
    client, rec = make(falcon({"web-01": AID}))
    result = await client.isolate_host(machine_id="web-01.contoso.com")

    assert result["success"] is True and result["device_id"] == AID
    assert rec.paths() == [
        "POST /oauth2/token",
        "GET /devices/queries/devices/v1",   # full name: unknown
        "GET /devices/queries/devices/v1",   # short name: found
        "POST /devices/entities/devices-actions/v2",
    ]
    token = rec.requests[0]
    assert token.url.host == "api.crowdstrike.com"
    assert token.headers["content-type"] == "application/x-www-form-urlencoded"
    assert b"client_id=cid-123" in token.content and b"client_secret=s3cr3t-value" in token.content
    assert rec.requests[1].url.params["filter"] == "hostname:['web-01.contoso.com']"
    assert rec.requests[2].url.params["filter"] == "hostname:['web-01']"
    assert rec.requests[2].headers["authorization"] == "Bearer tok-abc"
    action = rec.last
    assert action.url.params["action_name"] == "contain"
    assert action.headers["authorization"] == "Bearer tok-abc"
    assert rec.json(action) == {"ids": [AID]}


async def test_release_lifts_containment_and_device_id_is_used_directly():
    client, rec = make(falcon())
    result = await client.release_host(machine_id=AID.upper())

    assert result["success"] is True
    assert rec.paths() == ["POST /oauth2/token", "POST /devices/entities/devices-actions/v2"]
    assert rec.last.url.params["action_name"] == "lift_containment"
    assert rec.json(rec.last) == {"ids": [AID]}


async def test_unknown_host_is_not_found_and_nothing_is_contained():
    client, rec = make(falcon({"other": AID}))
    result = await client.isolate_host(machine_id="ghost.contoso.com")

    assert result["success"] is False and result["not_found"] is True
    assert "ghost.contoso.com" in result["message"]
    assert all(r.method == "GET" or r.url.path == "/oauth2/token" for r in rec.requests)


async def test_dry_run_makes_no_request():
    client, rec = make(falcon({"web-01": AID}), dry_run=True)
    for call in (client.isolate_host, client.release_host):
        result = await call(machine_id="web-01")
        assert result["success"] is True and result["dry_run"] is True
        assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_vendor_error_is_not_success():
    body = {"errors": [{"code": 403, "message": "access denied, authorization failed"}]}
    client, _ = make(falcon({"web-01": AID}, action_status=403, action_body=body))
    result = await client.isolate_host(machine_id="web-01")
    assert result["success"] is False and "not_found" not in result
    assert "403" in result["message"] and "access denied" in result["message"]

    # A 2xx reply that carries errors is a failure too.
    client, _ = make(falcon({"web-01": AID}, action_body={"resources": [], "errors": [{"message": "device busy"}]}))
    result = await client.isolate_host(machine_id="web-01")
    assert result["success"] is False and "device busy" in result["message"]


async def test_bad_credentials_are_not_success_and_secret_is_not_returned():
    client, _ = make(lambda req: httpx.Response(401, json={"errors": [{"message": "invalid client"}]}))
    result = await client.isolate_host(machine_id="web-01")
    assert result["success"] is False
    assert "s3cr3t-value" not in str(result)
    conn = await client.test_connection()
    assert conn["success"] is False and "s3cr3t-value" not in str(conn)
    assert (await client.get_health())["status"] == "error"


async def test_hostile_hostname_cannot_change_endpoint_or_filter():
    client, rec = make(falcon({"web-01": AID}))
    for hostile in ("web-01/../../oauth2/revoke?x=1", "x'],hostname:['web-01"):
        result = await client.isolate_host(machine_id=hostile)
        assert result["success"] is False and result["not_found"] is True
    allowed = {"/oauth2/token", "/devices/queries/devices/v1"}
    assert {r.url.path for r in rec.requests} <= allowed
    assert all("'],hostname" not in r.url.params.get("filter", "") for r in rec.requests)


async def test_describe_host():
    client, rec = make(falcon({"web-01": AID}))
    info = await client.describe_host("web-01")

    assert rec.last.method == "GET" and rec.last.url.path == "/devices/entities/devices/v2"
    assert rec.last.url.params["ids"] == AID
    assert info["device_id"] == AID and info["hostname"] == "WEB-01"
    assert info["is_isolated"] is True and info["owner"] == "svc-web"
    assert info["os"] == "Windows Server 2022" and info["last_seen"] == "2026-11-20T10:00:00Z"
    assert await client.describe_host("ghost") is None


async def test_describe_host_runs_in_dry_run():
    client, rec = make(falcon({"web-01": AID}), dry_run=True)
    assert (await client.describe_host("web-01"))["device_id"] == AID
    assert all(r.method == "GET" or r.url.path == "/oauth2/token" for r in rec.requests)


async def test_connection_token_cached_and_base_url_config():
    client, rec = make(falcon(), config={"base_url": "https://api.eu-1.crowdstrike.com/"})
    assert (await client.test_connection())["success"] is True
    assert (await client.get_health())["status"] == "healthy"
    assert rec.paths().count("POST /oauth2/token") == 1
    assert all(r.url.host == "api.eu-1.crowdstrike.com" for r in rec.requests)
