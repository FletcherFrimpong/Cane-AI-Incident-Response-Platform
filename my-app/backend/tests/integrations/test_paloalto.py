"""Contract tests for the Palo Alto Networks (PAN-OS) connector."""

import xml.etree.ElementTree as ET
from urllib.parse import parse_qs

import httpx

from app.integrations.paloalto import PaloAltoClient
from tests.integrations.helpers import Recorder

CREDS = {"host": "fw.acme.example", "api_key": "pan-secret-key"}
OK = '<response status="success"><result/></response>'


def make(reply=OK, status=200, dry_run=False, config=None, creds=None):
    client = PaloAltoClient(credentials=dict(creds or CREDS), config=config or {}, dry_run=dry_run)
    rec = Recorder(lambda req: httpx.Response(status, text=reply))
    rec.attach(client)
    return client, rec


def form(request: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def test_declares_contract():
    assert PaloAltoClient.platform_name == "palo_alto"
    assert PaloAltoClient.category == "response"
    assert PaloAltoClient.auth_type == "api_key"
    assert PaloAltoClient.required_credentials == ["host", "api_key"]
    assert {"block_tag", "vsys"} <= set(PaloAltoClient.optional_config)
    assert PaloAltoClient.actions == {"block_ip": "block_ip"}
    assert "Dynamic Address Group" in PaloAltoClient.description


async def test_block_ip_registers_tag_through_user_id_api():
    client, rec = make()
    result = await client.block_ip(ip_address="203.0.113.7")

    assert result["success"] is True and result["tag"] == "cane-blocked"
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST" and str(req.url) == "https://fw.acme.example/api/"
    assert req.headers["x-pan-key"] == "pan-secret-key"
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"
    assert "pan-secret-key" not in str(req.url) and b"pan-secret-key" not in req.content
    body = form(req)
    assert body["type"] == "user-id" and "vsys" not in body
    msg = ET.fromstring(body["cmd"])
    assert msg.tag == "uid-message" and msg.findtext("type") == "update" and msg.findtext("version") == "1.0"
    entry = msg.find("payload/register/entry")
    assert entry.get("ip") == "203.0.113.7"
    assert [m.text for m in entry.findall("tag/member")] == ["cane-blocked"]


async def test_block_tag_and_vsys_from_config():
    client, rec = make(config={"block_tag": "soc <deny> & drop", "vsys": "vsys2"})
    result = await client.block_ip(ip_address="2001:db8::1")
    assert result["success"] is True
    body = form(rec.last)
    assert body["vsys"] == "vsys2"
    entry = ET.fromstring(body["cmd"]).find("payload/register/entry")   # still well-formed XML
    assert entry.get("ip") == "2001:db8::1"
    assert entry.findtext("tag/member") == "soc <deny> & drop"


async def test_dry_run_makes_no_request():
    client, rec = make(dry_run=True)
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_firewall_error_status_is_not_success():
    client, _ = make('<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>', status=403)
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is False and "pan-secret-key" not in str(result)

    # PAN-OS reports many failures with HTTP 200 and status="error".
    client, _ = make('<response status="error"><msg><line>vsys vsys9 not found</line></msg></response>')
    result = await client.block_ip(ip_address="203.0.113.7")
    assert result["success"] is False and "vsys9 not found" in result["message"]

    client, _ = make("<html>login page</html>")
    assert (await client.block_ip(ip_address="203.0.113.7"))["success"] is False


async def test_already_registered_tag_counts_as_blocked():
    reply = ('<response status="error"><msg><line><uid-response><payload><register>'
             '<entry ip="203.0.113.7" message="tag cane-blocked already exists, ignore"/>'
             '</register></payload></uid-response></line></msg></response>')
    # The detail may sit in a `message` attribute or in element text: accept both.
    as_text = reply.replace('message="tag cane-blocked already exists, ignore"/>',
                            '>tag cane-blocked already exists, ignore</entry>')
    for body in (reply, as_text):
        client, _ = make(body)
        result = await client.block_ip(ip_address="203.0.113.7")
        assert result["success"] is True and "already" in result["message"]


async def test_non_ip_values_are_rejected_without_a_request():
    client, rec = make()
    for bad in ('1.2.3.4"><tag><member>x', "10.0.0.0/8", "evil.example/?type=config", ""):
        result = await client.block_ip(ip_address=bad)
        assert result["success"] is False
    assert rec.requests == []


async def test_host_with_scheme_or_path_cannot_change_endpoint():
    client, rec = make(creds={"host": "https://fw.acme.example:8443/api/?type=config", "api_key": "pan-secret-key"})
    await client.block_ip(ip_address="203.0.113.7")
    assert str(rec.last.url) == "https://fw.acme.example:8443/api/"


async def test_connection_and_health():
    info = ('<response status="success"><result><system><hostname>fw01</hostname>'
            '<sw-version>11.1.4</sw-version><model>PA-440</model></system></result></response>')
    client, rec = make(info)
    result = await client.test_connection()
    assert result["success"] is True and result["details"]["sw_version"] == "11.1.4"
    body = form(rec.last)
    assert body["type"] == "op" and body["cmd"] == "<show><system><info></info></system></show>"
    assert rec.last.headers["x-pan-key"] == "pan-secret-key"
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make('<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>', status=403)
    result = await client.test_connection()
    assert result["success"] is False and "pan-secret-key" not in str(result)
    assert (await client.get_health())["status"] == "error"
