import httpx
import pytest

from app.integrations.misp import MispClient
from tests.integrations.helpers import Recorder

CREDS = {"base_url": "https://misp.example.org/", "api_key": "misp-secret"}


def attribute(attr_id, event_id, to_ids, tags=(), info="OSINT - Emotet C2 infrastructure", attr_type="ip-dst"):
    # Shape of one item of response.Attribute from POST /attributes/restSearch (MISP OpenAPI spec).
    return {
        "id": str(attr_id), "event_id": str(event_id), "object_id": "0", "object_relation": None,
        "category": "Network activity", "type": attr_type, "to_ids": to_ids,
        "uuid": "c99506a6-1255-4b71-afa5-7b8ba48c3b1b", "timestamp": "1617875568", "distribution": "0",
        "sharing_group_id": "0", "comment": "", "deleted": False, "disable_correlation": False,
        "first_seen": None, "last_seen": None, "value": "203.0.113.7",
        "Event": {"id": str(event_id), "org_id": "1", "orgc_id": "1", "distribution": "0", "info": info,
                  "uuid": "c99506a6-1255-4b71-afa5-7b8ba48c3b1b"},
        "Tag": [{"id": "1", "name": name, "colour": "#ffffff", "exportable": True} for name in tags],
    }


def search_response(*attributes):
    return {"response": {"Attribute": list(attributes)}}


def make_client(handler):
    rec = Recorder(handler)
    client = MispClient(CREDS)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert MispClient.platform_name == "misp"
    assert MispClient.category == "enrichment"
    assert MispClient.enriches == ("ip", "domain", "url", "file_hash")
    assert MispClient.required_credentials == ["base_url", "api_key"]
    assert MispClient.auth_type == "api_key"


async def test_rest_search_request():
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response()))
    await client.enrich("ip", "203.0.113.7")
    assert rec.last.method == "POST"
    assert str(rec.last.url) == "https://misp.example.org/attributes/restSearch"
    assert rec.last.headers["authorization"] == "misp-secret"   # bare key, no "Bearer"
    assert rec.last.headers["accept"] == "application/json"
    body = rec.json(rec.last)
    assert body["returnFormat"] == "json"
    assert body["value"] == "203.0.113.7"
    assert body["includeEventTags"] is True
    assert body["limit"] == 100


async def test_to_ids_match_is_malicious_with_events_and_tags():
    response = search_response(
        attribute(1, 10, True, ["tlp:amber", "misp-galaxy:malware=\"Emotet\""]),
        attribute(2, 10, False, ["tlp:amber"]),
        attribute(3, 11, False, ["type:OSINT"], info="Phishing campaign March"),
    )
    client, _ = make_client(lambda r: httpx.Response(200, json=response))
    result = await client.enrich("ip", "203.0.113.7")
    assert result["verdict"] == "malicious"
    assert result["event_count"] == 2
    assert result["attribute_count"] == 3
    assert result["to_ids_count"] == 1
    assert result["tags"] == ["tlp:amber", "misp-galaxy:malware=\"Emotet\"", "type:OSINT"]
    assert result["events"] == [
        {"id": "10", "info": "OSINT - Emotet C2 infrastructure"},
        {"id": "11", "info": "Phishing campaign March"},
    ]
    assert result["attribute_types"] == ["ip-dst"]
    assert "2 MISP events" in result["summary"] and "to_ids" in result["summary"]
    assert "misp-secret" not in str(result)


async def test_matches_without_to_ids_are_suspicious():
    response = search_response(attribute(1, 10, False, ["tlp:green"]))
    client, _ = make_client(lambda r: httpx.Response(200, json=response))
    result = await client.enrich("domain", "evil.example")
    assert result["verdict"] == "suspicious"
    assert result["event_count"] == 1 and result["to_ids_count"] == 0
    assert "1 MISP event " in result["summary"] and "context only" in result["summary"]


@pytest.mark.parametrize("kind,value", [
    ("url", "https://evil.example/login"),
    ("file_hash", "44d88612fea8a8f36de82e1278abb02f"),
])
async def test_all_kinds_search_by_value(kind, value):
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response(attribute(1, 10, True))))
    result = await client.enrich(kind, value)
    assert rec.json(rec.last)["value"] == value
    assert result["verdict"] == "malicious"


@pytest.mark.parametrize("body", [{"response": {"Attribute": []}}, {"response": []}, {}])
async def test_no_match_is_none(body):
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    assert await client.enrich("ip", "203.0.113.7") is None


async def test_unsupported_kind_makes_no_call():
    client, rec = make_client(lambda r: httpx.Response(200, json=search_response()))
    assert await client.enrich("email", "a@example.com") is None
    assert rec.requests == []


@pytest.mark.parametrize("status", [403, 500])
async def test_vendor_error_raises_instead_of_looking_like_no_match(status):
    error = {"name": "Authentication failed.", "message": "Authentication failed.", "url": "/attributes/restSearch"}
    client, _ = make_client(lambda r: httpx.Response(status, json=error))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("ip", "203.0.113.7")


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json={"version": "2.4.188", "perm_sync": False}))
    result = await client.test_connection()
    assert result == {"success": True, "message": "Connected to MISP 2.4.188"}
    assert rec.paths() == ["GET /servers/getVersion"]
    assert rec.last.headers["authorization"] == "misp-secret"
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make_client(lambda r: httpx.Response(403, json={"message": "Authentication failed."}))
    result = await client.test_connection()
    assert result["success"] is False and "misp-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
