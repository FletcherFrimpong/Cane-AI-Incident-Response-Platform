import httpx
import pytest

from app.integrations.base_client import NotificationEvent
from app.integrations.opsgenie import OpsgenieClient
from tests.integrations.helpers import Recorder

API_KEY = "0a1b2c3d-secret-genie-key"


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
    return httpx.Response(202, json={"result": "Request will be processed", "took": 0.1, "requestId": "req-1"})


def make_client(handler=accepted, config=None, dry_run=False):
    rec = Recorder(handler)
    client = OpsgenieClient({"api_key": API_KEY}, config, dry_run=dry_run)
    rec.attach(client)
    return client, rec


async def test_notify_creates_alert():
    client, rec = make_client()
    result = await client.notify(make_event())

    assert result["success"] is True
    assert result["alias"] == "cane-inc-42" and result["request_id"] == "req-1"
    assert len(rec.requests) == 1
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "https://api.opsgenie.com/v2/alerts"
    assert req.headers["Authorization"] == f"GenieKey {API_KEY}"

    body = rec.json(req)
    assert body["message"] == "Critical incident: Ransomware Activity Detected"
    assert body["alias"] == "cane-inc-42"
    assert body["priority"] == "P1"
    assert "Mass file encryption on FIN-01." in body["description"]
    assert "https://cane.example.com/incidents/inc-42" in body["description"]
    assert body["details"]["Host"] == "FIN-01"
    assert all(isinstance(v, str) for v in body["details"].values())


async def test_message_is_limited_to_130_characters():
    client, rec = make_client()
    await client.notify(make_event(title="x" * 500))
    assert len(rec.json(rec.last)["message"]) == 130


@pytest.mark.parametrize("severity,priority", [
    ("critical", "P1"), ("high", "P2"), ("medium", "P3"), ("low", "P4"), ("info", "P5"), ("weird", "P3"),
])
async def test_severity_maps_to_priority(severity, priority):
    client, rec = make_client()
    await client.notify(make_event(severity=severity))
    assert rec.json(rec.last)["priority"] == priority


@pytest.mark.parametrize("kind", ["incident_escalated", "triage_failed", "action_pending"])
async def test_other_kinds_create_alert_with_same_alias(kind):
    client, rec = make_client()
    await client.notify(make_event(kind=kind))
    assert rec.paths() == ["POST /v2/alerts"]
    assert rec.json(rec.last)["alias"] == "cane-inc-42"


async def test_incident_closed_closes_alert_by_alias():
    client, rec = make_client()
    result = await client.notify(make_event(kind="incident_closed", summary="Contained and remediated."))

    assert result["success"] is True
    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/v2/alerts/cane-inc-42/close"
    assert req.url.params["identifierType"] == "alias"
    assert req.headers["Authorization"] == f"GenieKey {API_KEY}"
    assert rec.json(req)["note"] == "Contained and remediated."


async def test_alias_is_encoded_as_one_path_segment():
    client, rec = make_client()
    await client.notify(make_event(kind="incident_closed", incident_id="a/../b?x"))
    assert rec.last.url.raw_path.startswith(b"/v2/alerts/cane-a%2F..%2Fb%3Fx/close?")


async def test_eu_region_uses_eu_host():
    client, rec = make_client(config={"region": "eu"})
    await client.notify(make_event())
    assert str(rec.last.url) == "https://api.eu.opsgenie.com/v2/alerts"
    await client.test_connection()
    assert str(rec.last.url) == "https://api.eu.opsgenie.com/v2/account"


async def test_unknown_region_fails_without_request():
    client, rec = make_client(config={"region": "evil.example.com/"})
    assert (await client.notify(make_event()))["success"] is False
    assert (await client.test_connection())["success"] is False
    assert rec.requests == []


async def test_dry_run_makes_no_request():
    client, rec = make_client(dry_run=True)
    for kind in ("incident_opened", "incident_closed"):
        result = await client.notify(make_event(kind=kind))
        assert result["success"] is True and result["dry_run"] is True
        assert result["message"].startswith("[DRY RUN] Would ")
    assert rec.requests == []


async def test_vendor_error_is_failure_and_does_not_leak_key():
    client, _ = make_client(lambda r: httpx.Response(
        422, json={"message": "Request body is not processable.", "requestId": "x"}))
    result = await client.notify(make_event())
    assert result["success"] is False
    assert "422" in result["message"] and "not processable" in result["message"]
    assert API_KEY not in str(result)

    client, _ = make_client(lambda r: httpx.Response(401, json={"message": "Key format is not valid!"}))
    assert (await client.notify(make_event(kind="incident_closed")))["success"] is False


async def test_network_error_is_failure():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    client, _ = make_client(boom)
    result = await client.notify(make_event())
    assert result["success"] is False and API_KEY not in str(result)


async def test_test_connection():
    client, rec = make_client(lambda r: httpx.Response(200, json={"data": {"name": "acme"}}))
    result = await client.test_connection()
    assert result == {"success": True, "message": "Connected to Opsgenie"}
    assert rec.paths() == ["GET /v2/account"]
    assert rec.last.url.host == "api.opsgenie.com"
    assert rec.last.headers["Authorization"] == f"GenieKey {API_KEY}"
    assert (await client.get_health())["status"] == "healthy"


async def test_test_connection_failure():
    for status in (401, 403):
        client, _ = make_client(lambda r, s=status: httpx.Response(s, json={"message": "nope"}))
        result = await client.test_connection()
        assert result["success"] is False and API_KEY not in result["message"]
        assert (await client.get_health())["status"] == "error"
