import base64

import httpx

from app.integrations.jira import JiraClient, adf
from tests.integrations.helpers import Recorder

CREDS = {"base_url": "https://acme.atlassian.net/", "email": "soc@acme.com", "api_token": "ATATT-secret-token"}
BASIC = "Basic " + base64.b64encode(b"soc@acme.com:ATATT-secret-token").decode()

INCIDENT = {
    "id": "inc-42",
    "title": "Ransomware Activity\nDetected",
    "description": "Mass file encryption on FIN-01.\n\nStarted 02:14 UTC.",
    "severity": "critical",
    "status": "open",
    "attack_type": "ransomware",
    "url": "https://cane.example.com/incidents/inc-42",
}

TRANSITIONS = {"transitions": [
    {"id": "11", "name": "In Progress", "to": {"name": "In Progress"}},
    {"id": "31", "name": "Done", "to": {"name": "Done"}},
    {"id": "41", "name": "Close Issue", "to": {"name": "Closed"}},
]}


def router(routes: dict):
    """Handler answering by 'METHOD path'."""
    def handle(request: httpx.Request) -> httpx.Response:
        return routes[f"{request.method} {request.url.path}"]
    return handle


def make_client(handler, config=None, dry_run=False, creds=CREDS):
    rec = Recorder(handler)
    client = JiraClient(creds, {"project_key": "SEC"} if config is None else config, dry_run=dry_run)
    rec.attach(client)
    return client, rec


def all_text(doc: dict) -> str:
    return "\n".join(node["text"] for para in doc["content"] for node in para["content"])


def test_adf_shape():
    doc = adf("line one\n\nline two", "Open", "https://x.example/1")
    assert doc["type"] == "doc" and doc["version"] == 1
    assert [p["type"] for p in doc["content"]] == ["paragraph"] * 3
    assert doc["content"][0]["content"] == [{"type": "text", "text": "line one"}]
    assert doc["content"][2]["content"] == [{
        "type": "text", "text": "Open",
        "marks": [{"type": "link", "attrs": {"href": "https://x.example/1"}}],
    }]
    # ADF does not allow empty text nodes
    assert all(n["text"] for p in adf("\n\n a \n")["content"] for n in p["content"])


async def test_create_ticket():
    client, rec = make_client(lambda r: httpx.Response(
        201, json={"id": "10000", "key": "SEC-24", "self": "https://acme.atlassian.net/rest/api/3/issue/10000"}))
    result = await client.create_ticket(INCIDENT)

    assert result == {
        "success": True,
        "ticket_id": "SEC-24",
        "ticket_url": "https://acme.atlassian.net/browse/SEC-24",
        "message": "Created Jira issue SEC-24",
    }
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "https://acme.atlassian.net/rest/api/3/issue"
    assert req.headers["Authorization"] == BASIC

    fields = rec.json(req)["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "Ransomware Activity Detected"  # single line
    description = fields["description"]
    assert description["type"] == "doc" and description["version"] == 1
    text = all_text(description)
    assert "Mass file encryption on FIN-01." in text and "Severity: critical" in text
    link = description["content"][-1]["content"][0]
    assert link["marks"] == [{"type": "link", "attrs": {"href": "https://cane.example.com/incidents/inc-42"}}]


async def test_create_ticket_uses_configured_issue_type():
    client, rec = make_client(lambda r: httpx.Response(201, json={"id": "1", "key": "OPS-1"}),
                              config={"project_key": "OPS", "issue_type": "Incident"})
    await client.create_ticket(INCIDENT)
    fields = rec.json(rec.last)["fields"]
    assert fields["project"] == {"key": "OPS"} and fields["issuetype"] == {"name": "Incident"}


async def test_create_ticket_vendor_error_is_failure():
    client, _ = make_client(lambda r: httpx.Response(
        400, json={"errorMessages": [], "errors": {"issuetype": "Specify a valid issue type"}}))
    result = await client.create_ticket(INCIDENT)
    assert result["success"] is False
    assert "400" in result["message"] and "Specify a valid issue type" in result["message"]
    assert "ATATT-secret-token" not in str(result)
    assert "ticket_id" not in result


async def test_create_ticket_without_project_key_fails_without_request():
    client, rec = make_client(lambda r: httpx.Response(201, json={}), config={})
    assert (await client.create_ticket(INCIDENT))["success"] is False
    assert rec.requests == []


async def test_add_ticket_comment():
    client, rec = make_client(lambda r: httpx.Response(201, json={"id": "10001"}))
    result = await client.add_ticket_comment("SEC-24", "Host isolated.\nUser disabled.")

    assert result["success"] is True
    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/rest/api/3/issue/SEC-24/comment"
    assert req.headers["Authorization"] == BASIC
    body = rec.json(req)["body"]
    assert body["type"] == "doc" and body["version"] == 1
    assert all_text(body) == "Host isolated.\nUser disabled."


async def test_add_ticket_comment_error_is_failure():
    client, _ = make_client(lambda r: httpx.Response(
        404, json={"errorMessages": ["Issue does not exist or you do not have permission to see it."]}))
    result = await client.add_ticket_comment("SEC-999", "hello")
    assert result["success"] is False and "Issue does not exist" in result["message"]


async def test_ticket_id_is_encoded_as_one_path_segment():
    client, rec = make_client(lambda r: httpx.Response(201, json={"id": "1"}))
    await client.add_ticket_comment("SEC-1/../../user?x", "hello")
    assert rec.last.url.raw_path == b"/rest/api/3/issue/SEC-1%2F..%2F..%2Fuser%3Fx/comment"


async def test_close_ticket_looks_up_transition_applies_it_and_comments():
    client, rec = make_client(router({
        "GET /rest/api/3/issue/SEC-24/transitions": httpx.Response(200, json=TRANSITIONS),
        "POST /rest/api/3/issue/SEC-24/transitions": httpx.Response(204),
        "POST /rest/api/3/issue/SEC-24/comment": httpx.Response(201, json={"id": "10002"}),
    }))
    result = await client.close_ticket("SEC-24", "Contained and remediated.")

    assert result["success"] is True and result["comment_added"] is True
    assert rec.paths() == [
        "GET /rest/api/3/issue/SEC-24/transitions",
        "POST /rest/api/3/issue/SEC-24/transitions",
        "POST /rest/api/3/issue/SEC-24/comment",
    ]
    assert all(r.headers["Authorization"] == BASIC for r in rec.requests)
    assert rec.json(rec.requests[1]) == {"transition": {"id": "31"}}
    assert "Contained and remediated." in all_text(rec.json(rec.requests[2])["body"])


async def test_close_ticket_uses_configured_transition_case_insensitively():
    client, rec = make_client(router({
        "GET /rest/api/3/issue/SEC-24/transitions": httpx.Response(200, json=TRANSITIONS),
        "POST /rest/api/3/issue/SEC-24/transitions": httpx.Response(204),
        "POST /rest/api/3/issue/SEC-24/comment": httpx.Response(201, json={}),
    }), config={"project_key": "SEC", "done_transition": "close issue"})
    assert (await client.close_ticket("SEC-24", "done"))["success"] is True
    assert rec.json(rec.requests[1]) == {"transition": {"id": "41"}}


async def test_close_ticket_without_matching_transition_fails_and_changes_nothing():
    client, rec = make_client(router({
        "GET /rest/api/3/issue/SEC-24/transitions": httpx.Response(
            200, json={"transitions": [{"id": "11", "name": "In Progress", "to": {"name": "In Progress"}}]}),
    }))
    result = await client.close_ticket("SEC-24", "done")
    assert result["success"] is False
    assert "Done" in result["message"] and "In Progress" in result["message"]
    assert rec.paths() == ["GET /rest/api/3/issue/SEC-24/transitions"]


async def test_close_ticket_transition_error_is_failure():
    client, rec = make_client(router({
        "GET /rest/api/3/issue/SEC-24/transitions": httpx.Response(200, json=TRANSITIONS),
        "POST /rest/api/3/issue/SEC-24/transitions": httpx.Response(
            400, json={"errorMessages": ["Resolution is required"], "errors": {}}),
    }))
    result = await client.close_ticket("SEC-24", "done")
    assert result["success"] is False and "Resolution is required" in result["message"]
    assert len(rec.requests) == 2  # no comment after a failed transition


async def test_close_ticket_reports_failed_comment():
    client, _ = make_client(router({
        "GET /rest/api/3/issue/SEC-24/transitions": httpx.Response(200, json=TRANSITIONS),
        "POST /rest/api/3/issue/SEC-24/transitions": httpx.Response(204),
        "POST /rest/api/3/issue/SEC-24/comment": httpx.Response(403, json={"errorMessages": ["No permission"]}),
    }))
    result = await client.close_ticket("SEC-24", "done")
    assert result["success"] is True  # the issue was closed
    assert result["comment_added"] is False and "No permission" in result["message"]


async def test_dry_run_makes_no_request():
    client, rec = make_client(lambda r: httpx.Response(500), dry_run=True)
    for result in (
        await client.create_ticket(INCIDENT),
        await client.add_ticket_comment("SEC-24", "hello"),
        await client.close_ticket("SEC-24", "done"),
    ):
        assert result["success"] is True and result["dry_run"] is True
        assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_network_error_is_failure():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    client, _ = make_client(boom)
    for result in (
        await client.create_ticket(INCIDENT),
        await client.add_ticket_comment("SEC-24", "hello"),
        await client.close_ticket("SEC-24", "done"),
        await client.test_connection(),
    ):
        assert result["success"] is False and "ATATT-secret-token" not in str(result)


async def test_non_https_base_url_is_rejected_without_request():
    client, rec = make_client(lambda r: httpx.Response(200, json={}),
                              creds={**CREDS, "base_url": "http://acme.atlassian.net"})
    assert (await client.test_connection())["success"] is False
    assert (await client.create_ticket(INCIDENT))["success"] is False
    assert (await client.close_ticket("SEC-1", "x"))["success"] is False
    assert rec.requests == []


async def test_test_connection():
    client, rec = make_client(lambda r: httpx.Response(200, json={"accountId": "abc", "displayName": "SOC Bot"}))
    result = await client.test_connection()
    assert result == {"success": True, "message": "Connected to Jira as SOC Bot"}
    assert rec.paths() == ["GET /rest/api/3/myself"]
    assert rec.last.headers["Authorization"] == BASIC
    assert (await client.get_health())["status"] == "healthy"


async def test_test_connection_failure():
    client, _ = make_client(lambda r: httpx.Response(401, text="Client must be authenticated"))
    result = await client.test_connection()
    assert result["success"] is False and "401" in result["message"]
    assert "ATATT-secret-token" not in result["message"]
    assert (await client.get_health())["status"] == "error"
