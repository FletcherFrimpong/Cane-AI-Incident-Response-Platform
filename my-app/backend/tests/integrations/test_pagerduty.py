import httpx
import pytest

from app.integrations.base_client import NotificationEvent
from app.integrations.pagerduty import PagerDutyClient
from tests.integrations.helpers import Recorder

ROUTING_KEY = "R0UTINGKEY0123456789abcdefABCDEF"


def make_event(**overrides) -> NotificationEvent:
    data = dict(
        kind="incident_opened",
        title="Critical incident: Ransomware Activity Detected",
        summary="Mass file encryption on FIN-01.",
        severity="critical",
        incident_id="inc-42",
        incident_url="https://cane.example.com/incidents/inc-42",
        fields={"Host": "FIN-01"},
    )
    data.update(overrides)
    return NotificationEvent(**data)


def accepted(_request):
    return httpx.Response(202, json={"status": "success", "message": "Event processed", "dedup_key": "cane-inc-42"})


def make_client(handler=accepted, dry_run=False):
    rec = Recorder(handler)
    client = PagerDutyClient({"routing_key": ROUTING_KEY}, dry_run=dry_run)
    rec.attach(client)
    return client, rec


async def test_incident_opened_sends_trigger():
    client, rec = make_client()
    result = await client.notify(make_event())

    assert result["success"] is True
    assert result["event_action"] == "trigger" and result["dedup_key"] == "cane-inc-42"
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "https://events.pagerduty.com/v2/enqueue"
    assert "Authorization" not in req.headers  # Events API v2 authenticates with the routing key

    body = rec.json(req)
    assert body["routing_key"] == ROUTING_KEY
    assert body["event_action"] == "trigger"
    assert body["dedup_key"] == "cane-inc-42"
    assert body["payload"]["summary"] == "Critical incident: Ransomware Activity Detected"
    assert body["payload"]["source"]
    assert body["payload"]["severity"] == "critical"
    assert body["payload"]["custom_details"]["Host"] == "FIN-01"
    assert body["links"] == [{"href": "https://cane.example.com/incidents/inc-42", "text": "Open in Cane AI"}]


@pytest.mark.parametrize("kind", ["incident_opened", "incident_escalated", "triage_failed", "action_pending"])
async def test_trigger_kinds(kind):
    client, rec = make_client()
    assert (await client.notify(make_event(kind=kind)))["success"] is True
    body = rec.json(rec.last)
    assert body["event_action"] == "trigger" and body["dedup_key"] == "cane-inc-42"


async def test_incident_closed_sends_resolve_with_same_dedup_key():
    client, rec = make_client()
    result = await client.notify(make_event(kind="incident_closed"))
    assert result["success"] is True and result["event_action"] == "resolve"
    body = rec.json(rec.last)
    assert body == {"routing_key": ROUTING_KEY, "event_action": "resolve", "dedup_key": "cane-inc-42"}


@pytest.mark.parametrize("severity,expected", [
    ("critical", "critical"), ("high", "error"), ("medium", "warning"),
    ("low", "info"), ("info", "info"), ("CRITICAL", "critical"), ("weird", "warning"),
])
async def test_severity_is_mapped_to_allowed_values(severity, expected):
    client, rec = make_client()
    await client.notify(make_event(severity=severity))
    assert rec.json(rec.last)["payload"]["severity"] == expected


async def test_dry_run_makes_no_request():
    client, rec = make_client(dry_run=True)
    for kind in ("incident_opened", "incident_closed"):
        result = await client.notify(make_event(kind=kind))
        assert result["success"] is True and result["dry_run"] is True
        assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_vendor_error_is_failure_and_does_not_leak_routing_key():
    client, _ = make_client(lambda r: httpx.Response(
        400, json={"status": "invalid event", "message": "Event object is invalid",
                   "errors": ["'routing_key' is invalid"]}))
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "400" in result["message"] and "Event object is invalid" in result["message"]
    assert ROUTING_KEY not in str(result)


async def test_rate_limit_and_network_error_are_failures():
    client, _ = make_client(lambda r: httpx.Response(429, text="Too many requests"))
    assert (await client.notify(make_event()))["success"] is False

    def boom(request):
        raise httpx.ReadTimeout("timeout", request=request)

    client, _ = make_client(boom)
    result = await client.notify(make_event())
    assert result["success"] is False and ROUTING_KEY not in str(result)


async def test_unknown_kind_and_missing_key_fail_without_request():
    client, rec = make_client()
    assert (await client.notify(make_event(kind="something_else")))["success"] is False
    assert rec.requests == []

    rec = Recorder(accepted)
    client = PagerDutyClient({})
    rec.attach(client)
    assert (await client.notify(make_event()))["success"] is False
    assert (await client.test_connection())["success"] is False
    assert rec.requests == []


async def test_test_connection_sends_no_event():
    client, rec = make_client()
    result = await client.test_connection()
    assert result["success"] is True
    assert rec.requests == []
    assert ROUTING_KEY not in result["message"]
    assert (await client.get_health())["status"] == "healthy"
