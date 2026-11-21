import hashlib
import hmac
import json

import httpx
import pytest

from app.integrations.base_client import NotificationEvent
from app.integrations.webhook import GenericWebhookClient
from tests.integrations.helpers import Recorder

URL = "https://hooks.example.com/cane?token=URLTOKEN"
SECRET = "whsec-super-secret"


def make_event(**overrides) -> NotificationEvent:
    data = dict(
        kind="action_pending",
        title="Approval needed: isolate FIN-01",
        summary="Cane AI recommends isolating FIN-01 — ünïcode.",
        severity="high",
        incident_id="inc-42",
        incident_url="https://cane.example.com/incidents/inc-42",
        fields={"Host": "FIN-01"},
        action_id="act-7",
    )
    data.update(overrides)
    return NotificationEvent(**data)


def make_client(handler=lambda r: httpx.Response(200), url=URL, config=None, dry_run=False):
    rec = Recorder(handler)
    client = GenericWebhookClient({"url": url}, config, dry_run=dry_run)
    rec.attach(client)
    return client, rec


async def test_notify_posts_event_as_json():
    client, rec = make_client()
    result = await client.notify(make_event())

    assert result["success"] is True
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == URL
    assert req.headers["Content-Type"] == "application/json"
    assert "X-Cane-Signature" not in req.headers  # no secret configured
    assert rec.json(req) == {
        "kind": "action_pending",
        "title": "Approval needed: isolate FIN-01",
        "summary": "Cane AI recommends isolating FIN-01 — ünïcode.",
        "severity": "high",
        "incident_id": "inc-42",
        "incident_url": "https://cane.example.com/incidents/inc-42",
        "fields": {"Host": "FIN-01"},
        "action_id": "act-7",
    }


async def test_secret_adds_hmac_signature_over_raw_body():
    client, rec = make_client(config={"secret": SECRET})
    await client.notify(make_event())

    req = rec.last
    expected = hmac.new(SECRET.encode(), req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Cane-Signature"] == f"sha256={expected}"
    assert json.loads(req.content)["incident_id"] == "inc-42"
    assert SECRET not in req.content.decode()


async def test_empty_secret_sends_no_signature():
    client, rec = make_client(config={"secret": ""})
    await client.notify(make_event())
    assert "X-Cane-Signature" not in rec.last.headers


async def test_dry_run_makes_no_request():
    client, rec = make_client(config={"secret": SECRET}, dry_run=True)
    result = await client.notify(make_event())
    assert rec.requests == []
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")
    assert "URLTOKEN" not in result["message"]


@pytest.mark.parametrize("status", [301, 400, 401, 404, 500, 503])
async def test_non_2xx_is_failure_and_does_not_leak_url_or_secret(status):
    client, rec = make_client(
        lambda r: httpx.Response(status, headers={"Location": "http://169.254.169.254/"}, text="no"),
        config={"secret": SECRET},
    )
    result = await client.notify(make_event())
    assert result["success"] is False
    assert str(status) in result["message"]
    assert "URLTOKEN" not in str(result) and SECRET not in str(result)
    assert len(rec.requests) == 1  # a redirect is not followed


async def test_network_error_is_failure_and_does_not_leak_url():
    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    client, _ = make_client(boom)
    result = await client.notify(make_event())
    assert result["success"] is False and "URLTOKEN" not in str(result)


@pytest.mark.parametrize("url", [
    "https://hooks.example.com/cane",
    "https://10.0.0.5:8443/hook",
    "http://localhost:9000/hook",
    "http://127.0.0.1/hook",
    "HTTP://LOCALHOST/hook",
])
async def test_allowed_urls(url):
    client, rec = make_client(url=url)
    assert (await client.test_connection())["success"] is True
    assert rec.requests == []  # test_connection only validates
    assert (await client.notify(make_event()))["success"] is True
    assert len(rec.requests) == 1


@pytest.mark.parametrize("url", [
    "http://example.com/hook",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost.evil.com/hook",
    "http://localhost@evil.com/hook",
    "http://127.0.0.1.evil.com/hook",
    "http://127.0.0.2/hook",
    "ftp://example.com/hook",
    "file:///etc/passwd",
    "gopher://localhost/x",
    "javascript:alert(1)",
    "//example.com/hook",
    "example.com/hook",
    "https://",
    "https:///path",
    "http://localhost:notaport/hook",
    "",
    None,
    12345,
])
async def test_rejected_urls(url):
    client, rec = make_client(url=url)
    test = await client.test_connection()
    assert test["success"] is False
    assert (await client.get_health())["status"] == "error"
    result = await client.notify(make_event())
    assert result["success"] is False
    assert rec.requests == []


async def test_rejected_url_is_checked_before_dry_run():
    client, rec = make_client(url="http://example.com/hook", dry_run=True)
    result = await client.notify(make_event())
    assert result["success"] is False and "dry_run" not in result
    assert rec.requests == []
