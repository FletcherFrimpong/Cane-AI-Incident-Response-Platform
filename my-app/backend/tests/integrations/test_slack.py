import hashlib
import hmac
import time

import httpx

from app.integrations.base_client import NotificationEvent
from app.integrations.slack import SlackClient, verify_slack_signature
from tests.integrations.helpers import Recorder

CREDS = {"bot_token": "xoxb-test-token", "signing_secret": "shhh"}


def make_event(**overrides) -> NotificationEvent:
    data = dict(
        kind="incident_opened",
        title="Critical incident: Ransomware Activity Detected",
        summary="Mass file encryption on <FIN-01> & two other hosts.",
        severity="critical",
        incident_id="inc-42",
        incident_url="https://cane.example.com/incidents/inc-42",
        fields={"Host": "FIN-01", "User": "j.doe"},
    )
    data.update(overrides)
    return NotificationEvent(**data)


def make_client(handler, config=None, dry_run=False):
    rec = Recorder(handler)
    client = SlackClient(CREDS, {"channel": "#soc"} if config is None else config, dry_run=dry_run)
    rec.attach(client)
    return client, rec


def ok(_request):
    return httpx.Response(200, json={"ok": True, "channel": "C123", "ts": "1700000000.000100"})


def buttons(body) -> dict:
    actions = [b for b in body["blocks"] if b["type"] == "actions"]
    assert len(actions) == 1
    return {el["action_id"]: el for el in actions[0]["elements"]}


async def test_notify_posts_block_kit_message():
    client, rec = make_client(ok)
    result = await client.notify(make_event())

    assert result["success"] is True and result["ts"] == "1700000000.000100"
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "https://slack.com/api/chat.postMessage"
    assert req.headers["Authorization"] == "Bearer xoxb-test-token"
    assert req.headers["Content-Type"].startswith("application/json")

    body = rec.json(req)
    assert body["channel"] == "#soc"
    assert body["text"]
    types = [b["type"] for b in body["blocks"]]
    assert types == ["header", "section", "section", "actions"]
    assert body["blocks"][0]["text"] == {
        "type": "plain_text", "text": "Critical incident: Ransomware Activity Detected", "emoji": True,
    }
    # summary is escaped so log content cannot inject mrkdwn links or mentions
    assert body["blocks"][1]["text"]["text"] == "Mass file encryption on &lt;FIN-01&gt; &amp; two other hosts."
    field_texts = [f["text"] for f in body["blocks"][2]["fields"]]
    assert "*Severity*\nCritical" in field_texts
    assert "*Host*\nFIN-01" in field_texts and "*User*\nj.doe" in field_texts

    btns = buttons(body)
    assert set(btns) == {"cane_open"}
    assert btns["cane_open"]["url"] == "https://cane.example.com/incidents/inc-42"
    assert btns["cane_open"]["text"]["text"] == "Open in Cane AI"


async def test_action_pending_adds_approve_and_reject_buttons():
    client, rec = make_client(ok)
    await client.notify(make_event(kind="action_pending", action_id="act-7"))

    btns = buttons(rec.json(rec.last))
    assert set(btns) == {"cane_approve", "cane_reject", "cane_open"}
    assert btns["cane_approve"]["value"] == "act-7" and btns["cane_approve"]["text"]["text"] == "Approve"
    assert btns["cane_reject"]["value"] == "act-7" and btns["cane_reject"]["text"]["text"] == "Reject"
    assert btns["cane_approve"]["style"] == "primary" and btns["cane_reject"]["style"] == "danger"
    assert "url" not in btns["cane_approve"]


async def test_other_kinds_have_no_approve_buttons():
    client, rec = make_client(ok)
    await client.notify(make_event(kind="incident_closed", action_id="act-7"))
    assert set(buttons(rec.json(rec.last))) == {"cane_open"}


async def test_section_never_exceeds_ten_fields():
    client, rec = make_client(ok)
    await client.notify(make_event(fields={f"k{i}": "v" for i in range(30)}))
    assert len(rec.json(rec.last)["blocks"][2]["fields"]) == 10


async def test_dry_run_makes_no_request():
    client, rec = make_client(ok, dry_run=True)
    result = await client.notify(make_event(kind="action_pending", action_id="act-7"))
    assert rec.requests == []
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")


async def test_ok_false_with_http_200_is_a_failure():
    client, _ = make_client(lambda r: httpx.Response(200, json={"ok": False, "error": "channel_not_found"}))
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "channel_not_found" in result["message"]


async def test_http_error_and_rate_limit_are_failures():
    client, _ = make_client(lambda r: httpx.Response(500, text="oops"))
    assert (await client.notify(make_event()))["success"] is False
    client, _ = make_client(lambda r: httpx.Response(429, headers={"Retry-After": "30"}))
    result = await client.notify(make_event())
    assert result["success"] is False and "ratelimited" in result["message"]


async def test_network_error_is_a_failure_without_leaking_the_token():
    def boom(request):
        raise httpx.ConnectError("no route", request=request)

    client, _ = make_client(boom)
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "xoxb-test-token" not in str(result)


async def test_missing_channel_fails_without_request():
    client, rec = make_client(ok, config={})
    result = await client.notify(make_event())
    assert result["success"] is False and rec.requests == []


async def test_test_connection_uses_auth_test():
    client, rec = make_client(lambda r: httpx.Response(200, json={"ok": True, "team": "Acme"}))
    result = await client.test_connection()
    assert result == {"success": True, "message": "Connected to Slack workspace Acme"}
    assert rec.paths() == ["POST /api/auth.test"]
    assert rec.last.headers["Authorization"] == "Bearer xoxb-test-token"
    assert (await client.get_health())["status"] == "healthy"


async def test_test_connection_reports_invalid_auth():
    client, _ = make_client(lambda r: httpx.Response(200, json={"ok": False, "error": "invalid_auth"}))
    result = await client.test_connection()
    assert result["success"] is False and "invalid_auth" in result["message"]
    assert "xoxb-test-token" not in result["message"]
    assert (await client.get_health())["status"] == "error"


async def test_get_user_email():
    client, rec = make_client(lambda r: httpx.Response(
        200, json={"ok": True, "user": {"id": "U1", "profile": {"email": "ana@example.com"}}}))
    assert await client.get_user_email("U1") == "ana@example.com"
    assert rec.last.method == "GET"
    assert rec.last.url.path == "/api/users.info"
    assert rec.last.url.params["user"] == "U1"
    assert rec.last.headers["Authorization"] == "Bearer xoxb-test-token"


async def test_get_user_email_runs_in_dry_run_because_it_is_read_only():
    client, rec = make_client(lambda r: httpx.Response(
        200, json={"ok": True, "user": {"profile": {"email": "ana@example.com"}}}), dry_run=True)
    assert await client.get_user_email("U1") == "ana@example.com"
    assert len(rec.requests) == 1


async def test_get_user_email_returns_none_on_error_or_missing_email():
    client, _ = make_client(lambda r: httpx.Response(200, json={"ok": False, "error": "user_not_found"}))
    assert await client.get_user_email("U404") is None
    client, _ = make_client(lambda r: httpx.Response(200, json={"ok": True, "user": {"profile": {}}}))
    assert await client.get_user_email("U1") is None


# ---- request signing -------------------------------------------------------------

def sign(secret: str, timestamp: str, body: bytes) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


BODY = b"payload=%7B%22type%22%3A%22block_actions%22%7D"


def test_signature_matches_slack_documented_example(monkeypatch):
    # Worked example from Slack's "Verifying requests from Slack" documentation.
    secret = "8f742231b10e8888abcd99yyyzzz85a5"
    timestamp = "1531420618"
    body = (
        b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow"
        b"&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner"
        b"&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands"
        b"%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121"
        b".803a0bc887a14d10d2c447fce8b6703c"
    )
    signature = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
    monkeypatch.setattr(time, "time", lambda: 1531420618 + 10)
    assert verify_slack_signature(secret, timestamp, body, signature) is True


def test_signature_accepts_correct_signature():
    ts = str(int(time.time()))
    assert verify_slack_signature("shhh", ts, BODY, sign("shhh", ts, BODY)) is True


def test_signature_rejects_wrong_signature():
    ts = str(int(time.time()))
    assert verify_slack_signature("shhh", ts, BODY, sign("other-secret", ts, BODY)) is False
    assert verify_slack_signature("shhh", ts, BODY + b"x", sign("shhh", ts, BODY)) is False
    assert verify_slack_signature("shhh", ts, BODY, "v0=deadbeef") is False


def test_signature_rejects_stale_timestamp():
    ts = str(int(time.time()) - 301)
    assert verify_slack_signature("shhh", ts, BODY, sign("shhh", ts, BODY)) is False
    recent = str(int(time.time()) - 200)
    assert verify_slack_signature("shhh", recent, BODY, sign("shhh", recent, BODY)) is True


def test_signature_rejects_far_future_timestamp():
    ts = str(int(time.time()) + 3600)
    assert verify_slack_signature("shhh", ts, BODY, sign("shhh", ts, BODY)) is False


def test_signature_rejects_missing_or_malformed_values():
    ts = str(int(time.time()))
    good = sign("shhh", ts, BODY)
    assert verify_slack_signature("", ts, BODY, good) is False
    assert verify_slack_signature("shhh", "", BODY, good) is False
    assert verify_slack_signature("shhh", "not-a-number", BODY, good) is False
    assert verify_slack_signature("shhh", ts, BODY, "") is False
    assert verify_slack_signature("shhh", ts, BODY, None) is False
    assert verify_slack_signature("shhh", ts, BODY, "v0=ünicode") is False
