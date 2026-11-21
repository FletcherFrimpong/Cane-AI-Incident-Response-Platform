import base64

import httpx
import pytest

from app.integrations.servicenow import ServiceNowClient
from tests.integrations.helpers import Recorder

CREDS = {"instance_url": "https://acme.service-now.com/", "username": "cane.bot", "password": "p@ss-secret"}
BASIC = "Basic " + base64.b64encode(b"cane.bot:p@ss-secret").decode()
SYS_ID = "c537bae64f411200adf9f8e18110c76e"

INCIDENT = {
    "id": "inc-42",
    "title": "Ransomware Activity Detected",
    "description": "Mass file encryption on FIN-01.",
    "severity": "critical",
    "status": "open",
    "attack_type": "ransomware",
    "url": "https://cane.example.com/incidents/inc-42",
}


def make_client(handler, config=None, dry_run=False, creds=CREDS):
    rec = Recorder(handler)
    client = ServiceNowClient(creds, config, dry_run=dry_run)
    rec.attach(client)
    return client, rec


def record(state="1"):
    return {"result": {"sys_id": SYS_ID, "number": "INC0010002", "state": state}}


async def test_create_ticket():
    client, rec = make_client(lambda r: httpx.Response(201, json=record()))
    result = await client.create_ticket(INCIDENT)

    assert result["success"] is True
    assert result["ticket_id"] == SYS_ID
    assert result["ticket_number"] == "INC0010002"
    assert result["ticket_url"].startswith("https://acme.service-now.com/") and SYS_ID in result["ticket_url"]
    assert "INC0010002" in result["message"]

    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert req.url.host == "acme.service-now.com" and req.url.path == "/api/now/table/incident"
    assert req.headers["Authorization"] == BASIC
    assert req.headers["Accept"] == "application/json"
    body = rec.json(req)
    assert body["short_description"] == "Ransomware Activity Detected"
    assert "Mass file encryption on FIN-01." in body["description"]
    assert "https://cane.example.com/incidents/inc-42" in body["description"]
    assert body["urgency"] == "1" and body["impact"] == "1"


@pytest.mark.parametrize("severity,urgency,impact", [
    ("critical", "1", "1"), ("high", "1", "2"), ("medium", "2", "2"),
    ("low", "2", "3"), ("info", "3", "3"), ("weird", "2", "2"),
])
async def test_severity_maps_to_urgency_and_impact(severity, urgency, impact):
    client, rec = make_client(lambda r: httpx.Response(201, json=record()))
    await client.create_ticket({**INCIDENT, "severity": severity})
    body = rec.json(rec.last)
    assert (body["urgency"], body["impact"]) == (urgency, impact)


async def test_create_ticket_vendor_error_is_failure():
    client, _ = make_client(lambda r: httpx.Response(403, json={
        "error": {"message": "Operation Failed", "detail": "ACL Exception Insert Failed due to security constraints"},
        "status": "failure"}))
    result = await client.create_ticket(INCIDENT)
    assert result["success"] is False
    assert "403" in result["message"] and "ACL Exception" in result["message"]
    assert "p@ss-secret" not in str(result) and "ticket_id" not in result


async def test_create_ticket_without_sys_id_is_failure():
    client, _ = make_client(lambda r: httpx.Response(201, json={"result": {}}))
    assert (await client.create_ticket(INCIDENT))["success"] is False


async def test_add_ticket_comment_writes_work_notes():
    client, rec = make_client(lambda r: httpx.Response(200, json=record()))
    result = await client.add_ticket_comment(SYS_ID, "Host isolated.")

    assert result["success"] is True and result["ticket_number"] == "INC0010002"
    req = rec.last
    assert req.method == "PATCH"
    assert req.url.path == f"/api/now/table/incident/{SYS_ID}"
    assert req.headers["Authorization"] == BASIC
    assert rec.json(req) == {"work_notes": "Host isolated."}


async def test_add_ticket_comment_error_is_failure():
    client, _ = make_client(lambda r: httpx.Response(404, json={
        "error": {"message": "No Record found", "detail": "Record doesn't exist or ACL restricts the record retrieval"},
        "status": "failure"}))
    result = await client.add_ticket_comment("nope", "hello")
    assert result["success"] is False and "No Record found" in result["message"]


async def test_ticket_id_is_encoded_as_one_path_segment():
    client, rec = make_client(lambda r: httpx.Response(200, json=record()))
    await client.add_ticket_comment("abc/../../sys_user?x", "hello")
    assert rec.last.url.raw_path.startswith(b"/api/now/table/incident/abc%2F..%2F..%2Fsys_user%3Fx?")


async def test_close_ticket_resolves_with_code_and_notes():
    client, rec = make_client(lambda r: httpx.Response(200, json=record(state="6")))
    result = await client.close_ticket(SYS_ID, "Contained and remediated.")

    assert result["success"] is True and result["ticket_number"] == "INC0010002"
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "PATCH"
    assert req.url.path == f"/api/now/table/incident/{SYS_ID}"
    assert req.headers["Authorization"] == BASIC
    assert rec.json(req) == {
        "state": "6",
        "close_code": "Solution provided",
        "close_notes": "Contained and remediated.",
    }


async def test_close_ticket_honours_configured_state_and_code():
    client, rec = make_client(lambda r: httpx.Response(200, json=record(state="7")),
                              config={"close_state": "closed", "close_code": "Solved (Permanently)"})
    assert (await client.close_ticket(SYS_ID, "done"))["success"] is True
    body = rec.json(rec.last)
    assert body["state"] == "7" and body["close_code"] == "Solved (Permanently)"


async def test_close_ticket_invalid_state_config_fails_without_request():
    client, rec = make_client(lambda r: httpx.Response(200, json=record()), config={"close_state": "deleted"})
    assert (await client.close_ticket(SYS_ID, "done"))["success"] is False
    assert rec.requests == []


async def test_close_ticket_vendor_error_is_failure():
    client, _ = make_client(lambda r: httpx.Response(403, json={
        "error": {"message": "Operation Failed",
                  "detail": "Data Policy Exception: The following fields are mandatory: Resolution code"},
        "status": "failure"}))
    result = await client.close_ticket(SYS_ID, "done")
    assert result["success"] is False and "Resolution code" in result["message"]


async def test_close_ticket_that_did_not_change_state_is_failure():
    # HTTP 200, but the record is still "In Progress": the state write was discarded.
    client, _ = make_client(lambda r: httpx.Response(200, json=record(state="2")))
    result = await client.close_ticket(SYS_ID, "done")
    assert result["success"] is False and "not moved" in result["message"]


async def test_dry_run_makes_no_request():
    client, rec = make_client(lambda r: httpx.Response(500), dry_run=True)
    for result in (
        await client.create_ticket(INCIDENT),
        await client.add_ticket_comment(SYS_ID, "hello"),
        await client.close_ticket(SYS_ID, "done"),
    ):
        assert result["success"] is True and result["dry_run"] is True
        assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_network_error_is_failure():
    def boom(request):
        raise httpx.ConnectTimeout("timeout", request=request)

    client, _ = make_client(boom)
    for result in (
        await client.create_ticket(INCIDENT),
        await client.add_ticket_comment(SYS_ID, "hello"),
        await client.close_ticket(SYS_ID, "done"),
        await client.test_connection(),
    ):
        assert result["success"] is False and "p@ss-secret" not in str(result)


async def test_non_https_instance_url_is_rejected_without_request():
    client, rec = make_client(lambda r: httpx.Response(200, json=record()),
                              creds={**CREDS, "instance_url": "http://acme.service-now.com"})
    assert (await client.test_connection())["success"] is False
    assert (await client.create_ticket(INCIDENT))["success"] is False
    assert (await client.add_ticket_comment(SYS_ID, "x"))["success"] is False
    assert rec.requests == []


async def test_test_connection():
    client, rec = make_client(lambda r: httpx.Response(200, json={"result": [{"sys_id": SYS_ID}]}))
    result = await client.test_connection()
    assert result == {"success": True, "message": "Connected to ServiceNow"}
    assert rec.paths() == ["GET /api/now/table/incident"]
    assert rec.last.url.params["sysparm_limit"] == "1"
    assert rec.last.headers["Authorization"] == BASIC
    assert (await client.get_health())["status"] == "healthy"


async def test_test_connection_failure():
    client, _ = make_client(lambda r: httpx.Response(401, json={
        "error": {"message": "User Not Authenticated", "detail": "Required to provide Auth information"},
        "status": "failure"}))
    result = await client.test_connection()
    assert result["success"] is False and "User Not Authenticated" in result["message"]
    assert "p@ss-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
