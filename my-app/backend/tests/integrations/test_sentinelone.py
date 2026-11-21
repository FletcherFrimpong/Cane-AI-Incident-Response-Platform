"""Contract tests for the SentinelOne connector."""

import httpx
import pytest

from app.integrations.sentinelone import SentinelOneClient
from tests.integrations.helpers import Recorder

AGENT_ID = "225494730938493804"
CREDS = {"api_token": "tok-s1-secret", "console_url": "https://acme.sentinelone.net/"}
AGENTS = "/web/api/v2.1/agents"


def console(agents: list[dict] | None = None, action_status: int = 200, affected: int = 1):
    agents = agents or []

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == AGENTS and req.method == "GET":
            params = req.url.params
            if "ids" in params:
                data = [a for a in agents if a["id"] == params["ids"]]
            elif "computerName__like" in params:
                needle = params["computerName__like"].lower()
                data = [a for a in agents if needle in a["computerName"].lower()]
            else:
                data = agents[:1]
            return httpx.Response(200, json={"data": data, "pagination": {"totalItems": len(data)}})
        if path.startswith(f"{AGENTS}/actions/") and req.method == "POST":
            if action_status != 200:
                return httpx.Response(action_status, json={"errors": [{"title": "Forbidden", "detail": "Insufficient permissions"}]})
            return httpx.Response(200, json={"data": {"affected": affected}})
        return httpx.Response(404, json={"errors": [{"title": "Not found"}]})

    return handler


def agent(name: str, agent_id: str = AGENT_ID, **extra) -> dict:
    return {"id": agent_id, "computerName": name, "networkStatus": "connected", "isActive": True,
            "osName": "Windows 11 Pro", "lastLoggedInUserName": "jdoe", "lastActiveDate": "2026-11-20T10:00:00Z",
            "isDecommissioned": False, "infected": False, "activeThreats": 0, **extra}


def make(handler, dry_run=False):
    client = SentinelOneClient(credentials=dict(CREDS), dry_run=dry_run)
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert SentinelOneClient.platform_name == "sentinelone"
    assert SentinelOneClient.category == "response"
    assert SentinelOneClient.auth_type == "api_key"
    assert SentinelOneClient.required_credentials == ["api_token", "console_url"]
    assert set(SentinelOneClient.actions) == {"isolate_host", "release_host", "run_av_scan"}
    assert SentinelOneClient.provides_context == ("host",)
    for method in SentinelOneClient.actions.values():
        assert callable(getattr(SentinelOneClient, method))


@pytest.mark.parametrize("method,endpoint", [
    ("isolate_host", "disconnect"),
    ("release_host", "connect"),
    ("run_av_scan", "initiate-scan"),
])
async def test_action_resolves_hostname_then_acts(method, endpoint):
    # "WEB-01-OLD" also contains the short name: only the exact match may be picked.
    client, rec = make(console([agent("WEB-01-OLD", "111111111111111111"), agent("WEB-01")]))
    result = await getattr(client, method)(machine_id="web-01.contoso.com")

    assert result["success"] is True and result["device_id"] == AGENT_ID
    assert rec.paths() == [f"GET {AGENTS}", f"GET {AGENTS}", f"POST {AGENTS}/actions/{endpoint}"]
    assert rec.requests[0].url.params["computerName__like"] == "web-01.contoso.com"
    assert rec.requests[1].url.params["computerName__like"] == "web-01"
    assert rec.last.url.host == "acme.sentinelone.net"
    assert rec.last.headers["authorization"] == "ApiToken tok-s1-secret"
    assert rec.json(rec.last) == {"filter": {"ids": [AGENT_ID]}, "data": {}}


async def test_agent_id_is_used_directly():
    client, rec = make(console([agent("WEB-01")]))
    result = await client.isolate_host(machine_id=AGENT_ID)
    assert result["success"] is True
    assert rec.requests[0].url.params["ids"] == AGENT_ID
    assert rec.json(rec.last)["filter"]["ids"] == [AGENT_ID]


async def test_live_agent_preferred_over_decommissioned_duplicate():
    client, rec = make(console([
        agent("WEB-01", "111111111111111111", isDecommissioned=True, lastActiveDate="2026-11-21T00:00:00Z"),
        agent("WEB-01"),
    ]))
    await client.isolate_host(machine_id="web-01")
    assert rec.json(rec.last)["filter"]["ids"] == [AGENT_ID]


async def test_unknown_host_is_not_found_and_no_action_sent():
    client, rec = make(console([agent("WEB-010")]))
    result = await client.isolate_host(machine_id="web-01.contoso.com")
    assert result["success"] is False and result["not_found"] is True
    assert all(r.method == "GET" for r in rec.requests)


async def test_dry_run_makes_no_request():
    client, rec = make(console([agent("WEB-01")]), dry_run=True)
    for call in (client.isolate_host, client.release_host, client.run_av_scan):
        result = await call(machine_id="web-01")
        assert result["success"] is True and result["dry_run"] is True
    assert rec.requests == []


async def test_vendor_error_is_not_success():
    client, _ = make(console([agent("WEB-01")], action_status=403))
    result = await client.isolate_host(machine_id="web-01")
    assert result["success"] is False and "not_found" not in result
    assert "403" in result["message"] and "Insufficient permissions" in result["message"]
    assert "tok-s1-secret" not in str(result)


async def test_zero_affected_is_not_success():
    client, _ = make(console([agent("WEB-01")], affected=0))
    result = await client.run_av_scan(machine_id="web-01")
    assert result["success"] is False


async def test_hostile_hostname_cannot_change_endpoint():
    client, rec = make(console([agent("WEB-01")]))
    hostile = "web-01/actions/decommission?x=1&ids=5"
    result = await client.isolate_host(machine_id=hostile)
    assert result["success"] is False and result["not_found"] is True
    assert {r.url.path for r in rec.requests} == {AGENTS}
    assert all(r.method == "GET" and "ids" not in r.url.params for r in rec.requests)
    assert rec.requests[0].url.params["computerName__like"] == hostile


async def test_describe_host():
    client, rec = make(console([agent("WEB-01", networkStatus="disconnected")]))
    info = await client.describe_host("web-01")
    assert info["device_id"] == AGENT_ID and info["hostname"] == "WEB-01"
    assert info["is_isolated"] is True and info["owner"] == "jdoe" and info["os"] == "Windows 11 Pro"
    assert await client.describe_host("ghost") is None
    assert all(r.method == "GET" for r in rec.requests)


async def test_connection_and_health():
    client, rec = make(console([agent("WEB-01")]))
    assert (await client.test_connection())["success"] is True
    assert rec.last.url.path == AGENTS and rec.last.headers["authorization"] == "ApiToken tok-s1-secret"

    client, _ = make(lambda req: httpx.Response(401, json={"errors": [{"title": "Unauthorized"}]}))
    result = await client.test_connection()
    assert result["success"] is False and "tok-s1-secret" not in str(result)
    assert (await client.get_health())["status"] == "error"
