import httpx

from app.integrations.base_client import NotificationEvent
from app.integrations.teams import TeamsClient
from tests.integrations.helpers import Recorder

WEBHOOK = "https://prod-12.westeurope.logic.azure.com:443/workflows/abc123/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SECRETSIG"


def make_event(**overrides) -> NotificationEvent:
    data = dict(
        kind="action_pending",
        title="Approval needed: isolate FIN-01",
        summary="Cane AI recommends isolating FIN-01.",
        severity="high",
        incident_id="inc-42",
        incident_url="https://cane.example.com/incidents/inc-42",
        fields={"Host": "FIN-01"},
        action_id="act-7",
    )
    data.update(overrides)
    return NotificationEvent(**data)


def make_client(handler, url=WEBHOOK, dry_run=False):
    rec = Recorder(handler)
    client = TeamsClient({"webhook_url": url}, dry_run=dry_run)
    rec.attach(client)
    return client, rec


async def test_notify_posts_adaptive_card_envelope():
    client, rec = make_client(lambda r: httpx.Response(202))
    result = await client.notify(make_event())

    assert result == {"success": True, "message": "Posted to Microsoft Teams"}
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == WEBHOOK.replace(":443", "")  # httpx drops the default port
    assert req.url.params["sig"] == "SECRETSIG"
    assert req.headers["Content-Type"] == "application/json"
    assert "Authorization" not in req.headers

    body = rec.json(req)
    assert body["type"] == "message"
    assert len(body["attachments"]) == 1
    attachment = body["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["version"]
    texts = [b["text"] for b in card["body"] if b["type"] == "TextBlock"]
    assert texts == ["Approval needed: isolate FIN-01", "Cane AI recommends isolating FIN-01."]
    facts = next(b for b in card["body"] if b["type"] == "FactSet")["facts"]
    assert {"title": "Severity", "value": "High"} in facts
    assert {"title": "Host", "value": "FIN-01"} in facts


async def test_card_links_to_incident_and_has_no_approve_buttons():
    client, rec = make_client(lambda r: httpx.Response(202))
    await client.notify(make_event())
    card = rec.json(rec.last)["attachments"][0]["content"]
    assert card["actions"] == [{
        "type": "Action.OpenUrl", "title": "Open in Cane AI",
        "url": "https://cane.example.com/incidents/inc-42",
    }]


async def test_dry_run_makes_no_request():
    client, rec = make_client(lambda r: httpx.Response(202), dry_run=True)
    result = await client.notify(make_event())
    assert rec.requests == []
    assert result["success"] is True and result["dry_run"] is True
    assert result["message"].startswith("[DRY RUN] Would ")


async def test_error_response_is_failure_and_does_not_leak_url():
    client, _ = make_client(lambda r: httpx.Response(400, text="Bad payload"))
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "400" in result["message"]
    assert "SECRETSIG" not in str(result) and "logic.azure.com" not in str(result)


async def test_network_error_is_failure_and_does_not_leak_url():
    def boom(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    client, _ = make_client(boom)
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "SECRETSIG" not in str(result)


async def test_legacy_connector_error_in_200_body_is_failure():
    client, _ = make_client(lambda r: httpx.Response(
        200, text="Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 429"))
    assert (await client.notify(make_event()))["success"] is False


async def test_non_https_url_is_rejected_without_request():
    for bad in ["http://example.com/hook", "", None, "ftp://example.com/x", "not a url"]:
        client, rec = make_client(lambda r: httpx.Response(202), url=bad)
        assert (await client.notify(make_event()))["success"] is False
        assert (await client.test_connection())["success"] is False
        assert rec.requests == []


async def test_test_connection_validates_without_posting():
    client, rec = make_client(lambda r: httpx.Response(202))
    result = await client.test_connection()
    assert result["success"] is True
    assert rec.requests == []
    assert "SECRETSIG" not in result["message"]
    assert (await client.get_health())["status"] == "healthy"
