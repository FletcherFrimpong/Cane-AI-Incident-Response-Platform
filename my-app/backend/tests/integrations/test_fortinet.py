"""Contract tests for the Fortinet FortiGate connector."""

import httpx

from app.integrations.fortinet import FortiGateClient
from tests.integrations.helpers import Recorder

CREDS = {"host": "fgt.acme.example", "api_token": "fgt-secret-token"}
OK = {"http_method": "POST", "status": "success", "http_status": 200, "vdom": "root"}


def make(reply=None, status=200, dry_run=False, config=None, creds=None):
    client = FortiGateClient(credentials=dict(creds or CREDS), config=config or {}, dry_run=dry_run)
    rec = Recorder(lambda req: httpx.Response(status, json=OK if reply is None else reply))
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert FortiGateClient.platform_name == "fortinet"
    assert FortiGateClient.category == "response"
    assert FortiGateClient.auth_type == "bearer_token"
    assert FortiGateClient.required_credentials == ["host", "api_token"]
    assert "vdom" in FortiGateClient.optional_config
    assert FortiGateClient.actions == {"block_ip": "block_ip"}


async def test_block_ip_adds_to_banned_list():
    client, rec = make()
    result = await client.block_ip(ip_address=" 203.0.113.7 ")

    assert result["success"] is True
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "https://fgt.acme.example/api/v2/monitor/user/banned/add_users"
    assert req.headers["authorization"] == "Bearer fgt-secret-token"
    assert "fgt-secret-token" not in str(req.url)
    assert rec.json(req) == {"ip_addresses": ["203.0.113.7"]}


async def test_vdom_and_expiry_from_config():
    client, rec = make(config={"vdom": "edge", "ban_seconds": "3600"})
    assert (await client.block_ip(ip_address="2001:db8::1"))["success"] is True
    assert rec.last.url.path == "/api/v2/monitor/user/banned/add_users"
    assert rec.last.url.params["vdom"] == "edge"
    assert rec.json(rec.last) == {"ip_addresses": ["2001:db8::1"], "expiry": 3600}


async def test_dry_run_makes_no_request():
    client, rec = make(dry_run=True)
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_vendor_error_is_not_success():
    client, _ = make({"status": "error", "http_status": 403}, status=403)
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is False and "403" in result["message"]
    assert "fgt-secret-token" not in str(result)

    # A 200 whose body says "error" is a failure too.
    client, _ = make({"status": "error", "error": -651, "http_status": 200})
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is False and "-651" in result["message"]


async def test_non_ip_values_are_rejected_without_a_request():
    client, rec = make()
    for bad in ("10.0.0.0/8", "evil.example/api/v2/cmdb?x=1", "", "1.2.3.4, 5.6.7.8"):
        assert (await client.block_ip(ip_address=bad))["success"] is False
    assert rec.requests == []

    client, rec = make(config={"ban_seconds": "soon"})
    assert (await client.block_ip(ip_address="203.0.113.7"))["success"] is False
    assert rec.requests == []


async def test_host_with_scheme_or_path_cannot_change_endpoint():
    client, rec = make(creds={"host": "https://fgt.acme.example:10443/api/v2/cmdb/system/admin?x=1", "api_token": "t"})
    await client.block_ip(ip_address="203.0.113.7")
    assert str(rec.last.url) == "https://fgt.acme.example:10443/api/v2/monitor/user/banned/add_users"


async def test_connection_and_health():
    client, rec = make({"status": "success", "version": "v7.4.5", "build": 2702, "results": {}}, config={"vdom": "edge"})
    result = await client.test_connection()
    assert result["success"] is True and result["details"]["version"] == "v7.4.5"
    assert rec.last.method == "GET" and rec.last.url.path == "/api/v2/monitor/system/status"
    assert rec.last.headers["authorization"] == "Bearer fgt-secret-token"
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make({"status": "error"}, status=401)
    result = await client.test_connection()
    assert result["success"] is False and "fgt-secret-token" not in str(result)
    assert (await client.get_health())["status"] == "error"
