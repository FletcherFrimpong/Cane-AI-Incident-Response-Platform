from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from app.integrations.splunk import SplunkClient
from app.services.log_normalizer import normalize_log_event
from tests.integrations.helpers import Recorder

CREDS = {"base_url": "https://splunk.example.org:8089/", "token": "splunk-secret"}
SINCE = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def notable(time, title, urgency="high", src="203.0.113.7", dest="FIN-01", user="j.doe", event_id="A1@@notable@@1"):
    # One result row of the Enterprise Security `notable` macro, as output_mode=json returns it.
    return {
        "_time": time, "_raw": f"{time}, search_name=\"{title}\"", "_cd": "12:345", "_indextime": "1795262400",
        "event_id": event_id, "rule_name": title, "rule_title": title,
        "rule_description": "Multiple failed logins followed by a success.",
        "search_name": f"Access - {title} - Rule", "security_domain": "access",
        "severity": "medium", "urgency": urgency, "src": src, "dest": dest, "user": user,
        "host": "es-sh01", "source": f"Access - {title} - Rule", "sourcetype": "stash", "index": "notable",
    }


def oneshot(*results):
    return {"preview": False, "init_offset": 0, "messages": [], "fields": [{"name": "_time"}], "results": list(results)}


def make_client(handler, config=None):
    rec = Recorder(handler)
    client = SplunkClient(CREDS, config)
    rec.attach(client)
    return client, rec


def form(request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def test_declares_contract():
    assert SplunkClient.platform_name == "splunk"
    assert SplunkClient.category == "source"
    assert SplunkClient.required_credentials == ["base_url", "token"]
    assert SplunkClient.optional_config == ["search", "schema_id"]
    assert SplunkClient.auth_type == "bearer_token"


async def test_oneshot_search_request_with_defaults():
    client, rec = make_client(lambda r: httpx.Response(200, json=oneshot()))
    await client.fetch_events(SINCE, limit=200)
    assert rec.last.method == "POST"
    assert str(rec.last.url) == "https://splunk.example.org:8089/services/search/jobs"
    assert rec.last.headers["authorization"] == "Bearer splunk-secret"
    assert rec.last.headers["content-type"] == "application/x-www-form-urlencoded"
    body = form(rec.last)
    assert body["exec_mode"] == "oneshot"
    assert body["output_mode"] == "json"
    assert body["earliest_time"] == f"{SINCE.timestamp():.3f}"
    assert body["search"] == "search `notable` | sort 0 _time | head 200"
    assert body["count"] == "0"


@pytest.mark.parametrize("configured,expected_start", [
    ("index=notable urgency=critical", "search index=notable urgency=critical |"),
    ("search index=main sourcetype=fw", "search index=main sourcetype=fw |"),
    ("| tstats count from datamodel=Risk", "| tstats count from datamodel=Risk |"),
])
async def test_configured_search_gets_the_search_command_when_missing(configured, expected_start):
    client, rec = make_client(lambda r: httpx.Response(200, json=oneshot()), {"search": configured})
    await client.fetch_events(SINCE)
    assert form(rec.last)["search"].startswith(expected_start)
    assert form(rec.last)["search"].endswith("| sort 0 _time | head 500")


async def test_notables_map_to_security_alerts_oldest_first():
    newer = notable("2026-11-21T09:30:00.000+00:00", "Brute Force Access Behavior Detected", urgency="critical")
    older = notable("2026-11-21T08:00:00.000+00:00", "Geographically Improbable Access", urgency="informational",
                    src="fw-edge-01", user=["svc-backup", "j.doe"])
    client, _ = make_client(lambda r: httpx.Response(200, json=oneshot(newer, older)))
    events = await client.fetch_events(SINCE)

    assert [e["schemaId"] for e in events] == ["securityalert", "securityalert"]
    assert [e["data"]["DisplayName"] for e in events] == [
        "Geographically Improbable Access", "Brute Force Access Behavior Detected"]
    times = [e["data"]["TimeGenerated"] for e in events]
    assert times == ["2026-11-21T08:00:00+00:00", "2026-11-21T09:30:00+00:00"]

    data = events[1]["data"]
    assert data["AlertSeverity"] == "critical"
    assert data["Description"] == "Multiple failed logins followed by a success."
    assert data["CompromisedEntity"] == "FIN-01"
    assert data["Entities"] == [
        {"Type": "ip", "Address": "203.0.113.7"},
        {"Type": "host", "HostName": "FIN-01"},
        {"Type": "account", "Name": "j.doe"},
    ]
    assert data["SystemAlertId"] == "A1@@notable@@1"
    assert data["SourceSystem"] == "Splunk"
    assert data["SplunkEvent"]["index"] == "notable"

    # A non-IP src is not offered as an IP entity; multi-value fields use their first value.
    assert events[0]["data"]["Entities"] == [
        {"Type": "host", "HostName": "FIN-01"}, {"Type": "account", "Name": "svc-backup"}]

    normalized = [normalize_log_event(e["schemaId"], e["data"]) for e in events]
    assert [n["severity"] for n in normalized] == ["info", "critical"]
    assert normalized[1]["summary"] == "Brute Force Access Behavior Detected"
    assert normalized[1]["source_ip"] == "203.0.113.7"
    assert normalized[1]["host"] == "FIN-01"
    assert normalized[1]["user_identity"] == "j.doe"
    assert normalized[1]["time_generated"] == datetime(2026, 11, 21, 9, 30, tzinfo=timezone.utc)
    assert "splunk-secret" not in str(events)


async def test_common_security_log_schema_mapping():
    row = {
        "_time": "2026-11-21T08:00:00.000+00:00", "_raw": "deny tcp 203.0.113.7 -> 10.0.0.5:445",
        "vendor": "Palo Alto Networks", "product": "Firewall", "action": "blocked", "severity": "high",
        "src_ip": "203.0.113.7", "dest_ip": "10.0.0.5", "user": "j.doe", "host": "fw-edge-01",
        "signature": "SMB brute force",
    }
    client, _ = make_client(lambda r: httpx.Response(200, json=oneshot(row)), {"schema_id": "CommonSecurityLog"})
    events = await client.fetch_events(SINCE)
    assert events[0]["schemaId"] == "commonsecuritylog"
    normalized = normalize_log_event(events[0]["schemaId"], events[0]["data"])
    assert normalized["summary"] == "Palo Alto Networks Firewall: blocked"
    assert normalized["source_ip"] == "203.0.113.7" and normalized["destination_ip"] == "10.0.0.5"
    assert normalized["severity"] == "high"
    assert normalized["host"] == "fw-edge-01" and normalized["user_identity"] == "j.doe"


async def test_other_schema_passes_the_search_fields_through():
    row = {"_time": "1795248000.000", "_raw": "x", "EventName": "ConsoleLogin", "EventSource": "signin.amazonaws.com",
           "UserIdentityUserName": "root", "SourceIpAddress": "203.0.113.7"}
    client, _ = make_client(lambda r: httpx.Response(200, json=oneshot(row)), {"schema_id": "awscloudtrail"})
    events = await client.fetch_events(SINCE)
    assert "_raw" not in events[0]["data"]
    normalized = normalize_log_event(events[0]["schemaId"], events[0]["data"])
    assert normalized["summary"] == "AWS signin.amazonaws.com: ConsoleLogin by root"
    assert normalized["source_ip"] == "203.0.113.7"
    assert normalized["time_generated"] == datetime.fromtimestamp(1795248000, tz=timezone.utc)


async def test_limit_is_respected():
    rows = [notable(f"2026-11-21T08:0{i}:00.000+00:00", f"Rule {i}") for i in range(5)]
    client, _ = make_client(lambda r: httpx.Response(200, json=oneshot(*rows)))
    events = await client.fetch_events(SINCE, limit=3)
    assert [e["data"]["DisplayName"] for e in events] == ["Rule 0", "Rule 1", "Rule 2"]


async def test_no_results_is_empty_list():
    client, _ = make_client(lambda r: httpx.Response(200, json=oneshot()))
    assert await client.fetch_events(SINCE) == []


@pytest.mark.parametrize("status", [400, 401, 503])
async def test_http_error_raises_instead_of_looking_empty(status):
    error = {"messages": [{"type": "FATAL", "text": "Unknown search command 'notabel'."}]}
    client, _ = make_client(lambda r: httpx.Response(status, json=error))
    with pytest.raises(httpx.HTTPStatusError):
        await client.fetch_events(SINCE)


async def test_search_error_in_a_200_raises_instead_of_looking_empty():
    body = {"messages": [{"type": "FATAL", "text": "Error in 'search' command: macro not found"}], "results": []}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    with pytest.raises(RuntimeError, match="macro not found"):
        await client.fetch_events(SINCE)


async def test_connection_and_health():
    info = {"entry": [{"name": "server-info", "content": {"version": "9.4.1", "serverName": "es-sh01"}}]}
    client, rec = make_client(lambda r: httpx.Response(200, json=info))
    assert await client.test_connection() == {"success": True, "message": "Connected to Splunk 9.4.1"}
    assert rec.paths() == ["GET /services/server/info"]
    assert rec.last.url.params["output_mode"] == "json"
    assert rec.last.headers["authorization"] == "Bearer splunk-secret"
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make_client(lambda r: httpx.Response(401, json={"messages": [{"type": "WARN", "text": "call not properly authenticated"}]}))
    result = await client.test_connection()
    assert result["success"] is False and "splunk-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
