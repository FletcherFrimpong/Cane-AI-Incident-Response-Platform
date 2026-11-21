from datetime import datetime, timezone

import httpx
import pytest

from app.integrations.elastic import ElasticClient
from app.services.log_normalizer import normalize_log_event
from tests.integrations.helpers import Recorder

CREDS = {"base_url": "https://es.example.org:9200/", "api_key": "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=="}
SINCE = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def alert_hit(doc_id, timestamp, rule, severity="high", group_id=None, host="FIN-01", source_ip="203.0.113.7"):
    # An Elastic Security detection alert: kibana.alert.* fields are stored as flat dotted
    # keys, ECS fields of the original event as nested objects (Elastic alert schema docs).
    source = {
        "@timestamp": timestamp,
        "kibana.alert.uuid": doc_id,
        "kibana.alert.rule.name": rule,
        "kibana.alert.rule.uuid": "6b1c2d3e-0000-4000-8000-000000000001",
        "kibana.alert.rule.description": "Identifies a high number of failed logon attempts.",
        "kibana.alert.severity": severity,
        "kibana.alert.risk_score": 73,
        "kibana.alert.reason": f"authentication event with source {source_ip} on {host} created {severity} alert {rule}.",
        "kibana.alert.workflow_status": "open",
        "kibana.alert.original_time": "2026-11-21T07:59:30.000Z",
        "host": {"name": host, "os": {"family": "windows"}},
        "source": {"ip": source_ip},
        "user": {"name": "j.doe"},
        "event": {"kind": "signal"},
    }
    if group_id:
        source["kibana.alert.group.id"] = group_id
    return {"_index": ".internal.alerts-security.alerts-default-000001", "_id": doc_id, "_score": None,
            "_source": source, "sort": [1795248000000]}


def search_response(*hits):
    return {"took": 3, "timed_out": False, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": len(hits), "relation": "eq"}, "max_score": None, "hits": list(hits)}}


def make_client(handler, config=None):
    rec = Recorder(handler)
    client = ElasticClient(CREDS, config)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert ElasticClient.platform_name == "elastic"
    assert ElasticClient.category == "source"
    assert ElasticClient.required_credentials == ["base_url", "api_key"]
    assert ElasticClient.optional_config == ["index"]
    assert ElasticClient.auth_type == "api_key"


async def test_search_request_with_default_index():
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response()))
    await client.fetch_events(SINCE, limit=200)
    assert rec.last.method == "POST"
    assert str(rec.last.url) == "https://es.example.org:9200/.alerts-security.alerts-default/_search"
    assert rec.last.headers["authorization"] == f"ApiKey {CREDS['api_key']}"
    body = rec.json(rec.last)
    assert body["size"] == 200
    assert body["sort"] == [{"@timestamp": {"order": "asc"}}]
    assert body["query"] == {"bool": {"filter": [{"range": {"@timestamp": {"gt": "2026-11-20T12:00:00+00:00"}}}]}}


async def test_configured_index_is_one_path_segment_and_size_is_capped():
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response()),
                              {"index": ".alerts-security.alerts-soc/../_all"})
    await client.fetch_events(SINCE, limit=50000)
    assert rec.last.url.raw_path == b"/.alerts-security.alerts-soc%2F..%2F_all/_search"
    assert rec.json(rec.last)["size"] == 10000


async def test_alerts_map_to_security_alert_envelopes_in_order():
    first = alert_hit("a1", "2026-11-21T08:00:00.000Z", "Multiple Logon Failure from the same Source Address",
                      group_id="grp-77")
    second = alert_hit("a2", "2026-11-21T09:30:00.000Z", "Potential Credential Access via Windows Utilities",
                       severity="critical", group_id="grp-77")
    client, _ = make_client(lambda r: httpx.Response(200, json=search_response(first, second)))
    events = await client.fetch_events(SINCE)

    assert [e["schemaId"] for e in events] == ["securityalert", "securityalert"]
    assert [e["data"]["TimeGenerated"] for e in events] == ["2026-11-21T08:00:00.000Z", "2026-11-21T09:30:00.000Z"]
    data = events[0]["data"]
    assert data["DisplayName"] == "Multiple Logon Failure from the same Source Address"
    assert data["AlertSeverity"] == "high"
    assert data["Description"].startswith("authentication event with source 203.0.113.7")
    assert data["CompromisedEntity"] == "FIN-01"
    assert data["Entities"] == [
        {"Type": "ip", "Address": "203.0.113.7"},
        {"Type": "host", "HostName": "FIN-01"},
        {"Type": "account", "Name": "j.doe"},
    ]
    assert data["CorrelationId"] == "grp-77"
    assert data["SystemAlertId"] == "a1"
    assert data["ExtendedProperties"]["risk_score"] == 73
    assert "ApiKey" not in str(events) and CREDS["api_key"] not in str(events)

    normalized = [normalize_log_event(e["schemaId"], e["data"]) for e in events]
    assert [n["time_generated"] for n in normalized] == sorted(n["time_generated"] for n in normalized)
    assert [n["severity"] for n in normalized] == ["high", "critical"]
    assert normalized[0]["summary"] == "Multiple Logon Failure from the same Source Address"
    assert normalized[0]["source_ip"] == "203.0.113.7"
    assert normalized[0]["host"] == "FIN-01"
    assert normalized[0]["user_identity"] == "j.doe"
    assert normalized[0]["correlation_id"] == "grp-77" and normalized[1]["correlation_id"] == "grp-77"


async def test_sparse_alert_still_normalises():
    hit = {"_index": "x", "_id": "doc-9", "_source": {
        "@timestamp": "2026-11-21T08:00:00.000Z",
        "kibana": {"alert": {"rule": {"name": "Nested Rule", "description": "From nested source"}, "severity": "low"}},
        "source": {"ip": ["198.51.100.4", "198.51.100.5"]},
    }}
    client, _ = make_client(lambda r: httpx.Response(200, json=search_response(hit)))
    data = (await client.fetch_events(SINCE))[0]["data"]
    assert data["DisplayName"] == "Nested Rule" and data["Description"] == "From nested source"
    assert data["CorrelationId"] is None and data["CompromisedEntity"] is None
    assert data["SystemAlertId"] == "doc-9"
    assert data["Entities"] == [{"Type": "ip", "Address": "198.51.100.4"}]
    normalized = normalize_log_event("securityalert", data)
    assert normalized["severity"] == "low" and normalized["correlation_id"] is None


async def test_no_alerts_is_empty_list():
    client, _ = make_client(lambda r: httpx.Response(200, json=search_response()))
    assert await client.fetch_events(SINCE) == []


@pytest.mark.parametrize("status", [401, 403, 404, 500])
async def test_vendor_error_raises_instead_of_looking_empty(status):
    error = {"error": {"type": "security_exception", "reason": "unable to authenticate"}, "status": status}
    client, _ = make_client(lambda r: httpx.Response(status, json=error))
    with pytest.raises(httpx.HTTPStatusError):
        await client.fetch_events(SINCE)


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response()))
    assert (await client.test_connection())["success"] is True
    assert rec.paths() == ["POST /.alerts-security.alerts-default/_search"]
    assert rec.json(rec.last)["size"] == 0
    assert (await client.get_health())["status"] == "healthy"

    for status, hint in [(401, "rejected the API key"), (403, "not allowed"), (404, "not found")]:
        client, _ = make_client(lambda r, s=status: httpx.Response(s, json={"status": s}))
        result = await client.test_connection()
        assert result["success"] is False and hint in result["message"]
        assert CREDS["api_key"] not in result["message"]
        assert (await client.get_health())["status"] == "error"
