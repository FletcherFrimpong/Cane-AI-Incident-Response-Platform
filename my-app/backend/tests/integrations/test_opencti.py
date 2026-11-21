import httpx
import pytest

from app.integrations.opencti import OpenCtiClient
from tests.integrations.helpers import Recorder

CREDS = {"base_url": "https://opencti.example.org/", "api_token": "octi-secret"}
SHA256 = "98983e00b47bcbe9ebbaf5f28ea6cdbf619dd88c91f481b18fec7ffdb68ab741"


def indicator(ind_id, value, score, revoked=False, labels=("c2",)):
    # Fields of the Indicator type in OpenCTI's GraphQL schema.
    return {
        "id": ind_id, "name": value, "pattern": f"[ipv4-addr:value = '{value}']",
        "x_opencti_score": score, "valid_until": "2027-01-01T00:00:00.000Z", "revoked": revoked,
        "objectLabel": [{"value": label} for label in labels],
    }


def observable(value, score, labels=("emotet",), indicators=(), entity_type="IPv4-Addr", hashes=None):
    # Fields of the StixCyberObservable interface in OpenCTI's GraphQL schema.
    node = {
        "id": "obs-1", "entity_type": entity_type, "observable_value": value, "x_opencti_score": score,
        "x_opencti_description": "Seen in Emotet epoch 5", "created_at": "2026-03-01T09:00:00.000Z",
        "objectLabel": [{"value": label} for label in labels],
        "indicators": {"edges": [{"node": i} for i in indicators]},
    }
    if hashes is not None:
        node["hashes"] = hashes
    return node


def graphql(observables=(), indicators=()):
    return {"data": {
        "stixCyberObservables": {"edges": [{"node": o} for o in observables]},
        "indicators": {"edges": [{"node": i} for i in indicators]},
    }}


def make_client(handler):
    rec = Recorder(handler)
    client = OpenCtiClient(CREDS)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert OpenCtiClient.platform_name == "opencti"
    assert OpenCtiClient.category == "enrichment"
    assert OpenCtiClient.enriches == ("ip", "domain", "url", "file_hash")
    assert OpenCtiClient.required_credentials == ["base_url", "api_token"]
    assert OpenCtiClient.auth_type == "bearer_token"


async def test_graphql_request():
    client, rec = make_client(lambda r: httpx.Response(200, json=graphql()))
    await client.enrich("ip", "203.0.113.7")
    assert rec.last.method == "POST"
    assert str(rec.last.url) == "https://opencti.example.org/graphql"
    assert rec.last.headers["authorization"] == "Bearer octi-secret"
    body = rec.json(rec.last)
    # The value travels as a GraphQL variable, never spliced into the query text.
    assert body["variables"] == {"search": "203.0.113.7", "first": 25}
    assert "203.0.113.7" not in body["query"]
    for field in ("stixCyberObservables(search: $search", "indicators(search: $search", "observable_value",
                  "x_opencti_score", "objectLabel { value }", "... on StixFile { hashes { algorithm hash } }"):
        assert field in body["query"]


async def test_high_score_observable_is_malicious_with_labels():
    obs = observable("203.0.113.7", 85, labels=("emotet", "c2"), indicators=[indicator("ind-1", "203.0.113.7", 90)])
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql([obs], [indicator("ind-1", "203.0.113.7", 90)])))
    result = await client.enrich("ip", "203.0.113.7")
    assert result["verdict"] == "malicious"
    assert result["score"] == 90   # highest of the observable and its active indicators
    assert result["labels"] == ["emotet", "c2"]
    assert result["observable_id"] == "obs-1" and result["observable_type"] == "IPv4-Addr"
    assert result["indicator_count"] == 1 and result["active_indicator_count"] == 1
    assert result["indicators"][0]["pattern"] == "[ipv4-addr:value = '203.0.113.7']"
    assert "score 90/100" in result["summary"] and "emotet" in result["summary"]
    assert "octi-secret" not in str(result)


@pytest.mark.parametrize("score,verdict", [(70, "malicious"), (69, "suspicious"), (40, "suspicious"), (39, "unknown"), (None, "unknown")])
async def test_score_thresholds(score, verdict):
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql([observable("evil.example", score)])))
    result = await client.enrich("domain", "Evil.Example")
    assert result["verdict"] == verdict and result["score"] == score


async def test_full_text_near_misses_are_ignored():
    near = observable("203.0.113.70", 95)
    other = indicator("ind-9", "203.0.113.77", 95)
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql([near], [other])))
    assert await client.enrich("ip", "203.0.113.7") is None


async def test_file_is_matched_by_any_of_its_hashes():
    obs = observable("invoice.exe", 75, entity_type="StixFile", hashes=[
        {"algorithm": "MD5", "hash": "44d88612fea8a8f36de82e1278abb02f"},
        {"algorithm": "SHA-256", "hash": SHA256},
    ])
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql([obs])))
    result = await client.enrich("file_hash", SHA256.upper())
    assert result["verdict"] == "malicious" and result["observable_type"] == "StixFile"


async def test_indicator_only_match_and_revoked_indicators_do_not_score():
    live = indicator("ind-1", "203.0.113.7", 50, labels=("phishing",))
    revoked = indicator("ind-2", "203.0.113.7", 100, revoked=True)
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql([], [live, revoked])))
    result = await client.enrich("ip", "203.0.113.7")
    assert result["verdict"] == "suspicious" and result["score"] == 50
    assert result["observable_id"] is None
    assert result["indicator_count"] == 2 and result["active_indicator_count"] == 1
    assert "an indicator" in result["summary"]


async def test_not_found_is_none():
    client, _ = make_client(lambda r: httpx.Response(200, json=graphql()))
    assert await client.enrich("url", "https://evil.example/login") is None


async def test_unsupported_kind_makes_no_call():
    client, rec = make_client(lambda r: httpx.Response(200, json=graphql()))
    assert await client.enrich("email", "a@example.com") is None
    assert rec.requests == []


async def test_graphql_errors_raise_instead_of_looking_like_not_found():
    # OpenCTI answers a bad token with HTTP 200 and an errors list.
    body = {"errors": [{"message": "You must be logged in to do this.", "name": "AUTH_REQUIRED"}], "data": None}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    with pytest.raises(RuntimeError, match="You must be logged in"):
        await client.enrich("ip", "203.0.113.7")


async def test_http_error_raises():
    client, _ = make_client(lambda r: httpx.Response(502, text="bad gateway"))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("ip", "203.0.113.7")


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json={"data": {"about": {"version": "6.4.2"}}}))
    assert await client.test_connection() == {"success": True, "message": "Connected to OpenCTI 6.4.2"}
    assert rec.paths() == ["POST /graphql"]
    assert "about { version }" in rec.json(rec.last)["query"]
    assert (await client.get_health())["status"] == "healthy"

    body = {"errors": [{"message": "You must be logged in to do this."}]}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    result = await client.test_connection()
    assert result["success"] is False and "octi-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
