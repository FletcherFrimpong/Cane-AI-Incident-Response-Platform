"""Contract tests for the DefenderHostResolver mixin."""

import httpx
import pytest

from app.integrations.base_client import BaseIntegrationClient
from app.integrations.defender_hosts import DefenderHostResolver
from tests.integrations.helpers import Recorder

MID = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"


class Host(DefenderHostResolver, BaseIntegrationClient):
    platform_name = "microsoft_defender"
    BASE_URL = "https://api.securitycenter.microsoft.com/api"

    async def _auth_headers(self) -> dict:
        return {"Authorization": "Bearer test-token"}

    async def test_connection(self) -> dict:
        return {"success": True, "message": "ok"}

    async def get_health(self) -> dict:
        return {"status": "healthy"}


def machine(name: str, mid: str = MID, last_seen: str = "2026-11-20T10:00:00Z") -> dict:
    return {"id": mid, "computerDnsName": name, "lastSeen": last_seen, "osPlatform": "Windows11", "version": "23H2",
            "healthStatus": "Active", "riskScore": "High", "exposureLevel": "Medium", "lastIpAddress": "10.0.0.5",
            "lastExternalIpAddress": "198.51.100.9", "machineTags": ["finance"], "aadDeviceId": "aad-1"}


def defender(machines: list[dict]):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/machines":
            flt = req.url.params.get("$filter", "")
            hits = [m for m in machines
                    if flt == f"computerDnsName eq '{m['computerDnsName']}'"
                    or (flt.startswith("startswith(computerDnsName,'")
                        and m["computerDnsName"].startswith(flt[len("startswith(computerDnsName,'"):-2]))]
            return httpx.Response(200, json={"value": hits})
        if req.url.path.startswith("/api/machines/"):
            mid = req.url.path.rsplit("/", 1)[-1]
            found = [m for m in machines if m["id"] == mid]
            return httpx.Response(200, json=found[0]) if found else httpx.Response(404, json={"error": {"code": "ResourceNotFound"}})
        return httpx.Response(404)

    return handler


def make(handler):
    client = Host(credentials={})
    rec = Recorder(handler)
    rec.attach(client)
    return client, rec


async def test_exact_fqdn_match():
    client, rec = make(defender([machine("web-01.contoso.com")]))
    assert await client.resolve_machine_id("web-01.contoso.com") == MID
    assert rec.paths() == ["GET /api/machines"]
    assert rec.last.url.host == "api.securitycenter.microsoft.com"
    assert rec.last.headers["authorization"] == "Bearer test-token"
    assert rec.last.url.params["$filter"] == "computerDnsName eq 'web-01.contoso.com'"


async def test_falls_back_to_short_name():
    client, rec = make(defender([machine("web-01")]))
    assert await client.resolve_machine_id("web-01.contoso.com") == MID
    assert [r.url.params["$filter"] for r in rec.requests] == [
        "computerDnsName eq 'web-01.contoso.com'", "computerDnsName eq 'web-01'"]


async def test_short_name_finds_fully_qualified_machine():
    client, rec = make(defender([machine("web-01.corp.contoso.com"), machine("web-010.corp.contoso.com", "f" * 40)]))
    assert await client.resolve_machine_id("web-01") == MID
    assert rec.last.url.params["$filter"] == "startswith(computerDnsName,'web-01.')"


async def test_machine_id_is_returned_without_a_request():
    client, rec = make(defender([]))
    assert await client.resolve_machine_id(MID) == MID
    assert await client.resolve_machine_id(MID.upper()) == MID.upper()
    assert rec.requests == []


async def test_most_recently_seen_duplicate_wins():
    client, _ = make(defender([
        machine("web-01", "a" * 40, last_seen="2025-01-01T00:00:00Z"),
        machine("web-01", MID, last_seen="2026-11-20T10:00:00Z"),
    ]))
    assert await client.resolve_machine_id("web-01") == MID


async def test_unknown_host_is_none():
    client, rec = make(defender([machine("other")]))
    assert await client.resolve_machine_id("ghost.contoso.com") is None
    assert await client.describe_host("ghost.contoso.com") is None
    assert all(r.method == "GET" for r in rec.requests)

    # Defender answers 404 for "nothing matched".
    client, _ = make(lambda req: httpx.Response(404, json={"error": {"code": "NotFound"}}))
    assert await client.resolve_machine_id("ghost") is None


async def test_vendor_error_is_raised_not_swallowed():
    client, _ = make(lambda req: httpx.Response(403, json={"error": {"code": "Forbidden"}}))
    with pytest.raises(httpx.HTTPStatusError):
        await client.resolve_machine_id("web-01")


async def test_hostile_names_stay_inside_the_filter():
    client, rec = make(defender([machine("web-01")]))
    hostile = "x' or computerDnsName eq 'web-01"
    assert await client.resolve_machine_id(hostile) is None
    assert rec.requests[0].url.params["$filter"] == "computerDnsName eq 'x'' or computerDnsName eq ''web-01'"

    assert await client.resolve_machine_id("web-01/isolate?x=1&$top=5") is None
    assert {r.url.path for r in rec.requests} == {"/api/machines"}
    assert all(set(r.url.params.keys()) == {"$filter"} for r in rec.requests)


async def test_describe_host_by_name_and_by_id():
    client, rec = make(defender([machine("web-01.contoso.com")]))
    info = await client.describe_host("web-01.contoso.com")
    assert info == {
        "device_id": MID, "hostname": "web-01.contoso.com", "os": "Windows11 23H2",
        "last_seen": "2026-11-20T10:00:00Z", "risk": "High", "exposure": "Medium", "health": "Active",
        "last_ip": "10.0.0.5", "external_ip": "198.51.100.9", "tags": ["finance"], "aad_device_id": "aad-1",
    }
    by_id = await client.describe_host(MID)
    assert rec.last.url.path == f"/api/machines/{MID}" and by_id["hostname"] == "web-01.contoso.com"
