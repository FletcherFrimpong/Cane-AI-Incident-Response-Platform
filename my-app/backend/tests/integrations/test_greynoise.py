import httpx
import pytest

from app.integrations.greynoise import GreyNoiseClient
from tests.integrations.helpers import Recorder

# Response shapes from https://docs.greynoise.io/docs/using-the-greynoise-community-api
NOISE = {
    "ip": "51.91.185.74", "noise": True, "riot": False, "classification": "malicious", "name": "unknown",
    "link": "https://viz.greynoise.io/ip/51.91.185.74", "last_seen": "2021-03-18", "message": "Success",
}
RIOT = {
    "ip": "1.1.1.1", "noise": False, "riot": True, "classification": "benign", "name": "Cloudflare",
    "link": "https://viz.greynoise.io/riot/1.1.1.1", "last_seen": "2020-01-01", "message": "Success",
}
# Real response (HTTP 404) from the live Community API for 8.8.8.8.
NOT_FOUND = {"ip": "8.8.8.8", "noise": False, "riot": False, "message": "IP not observed scanning the internet."}
RATE_LIMITED = {"plan": "unauthenticated", "rate-limit": "10 IP lookups per day", "message": "You have hit your daily rate limit"}


def make_client(handler, credentials=None):
    rec = Recorder(handler)
    client = GreyNoiseClient(credentials or {})
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert GreyNoiseClient.platform_name == "greynoise"
    assert GreyNoiseClient.category == "enrichment"
    assert GreyNoiseClient.enriches == ("ip",)
    assert GreyNoiseClient.required_credentials == []
    assert GreyNoiseClient.auth_type == "api_key"


async def test_request_without_key_sends_no_key_header():
    client, rec = make_client(lambda r: httpx.Response(200, json=RIOT))
    await client.enrich("ip", "1.1.1.1")
    assert rec.last.method == "GET"
    assert str(rec.last.url) == "https://api.greynoise.io/v3/community/1.1.1.1"
    assert "key" not in rec.last.headers


async def test_request_with_key_sends_key_header():
    client, rec = make_client(lambda r: httpx.Response(200, json=RIOT), {"api_key": "gn-secret"})
    await client.enrich("ip", "1.1.1.1")
    assert rec.last.headers["key"] == "gn-secret"


async def test_ip_is_encoded_as_one_path_segment():
    client, rec = make_client(lambda r: httpx.Response(404, json=NOT_FOUND))
    await client.enrich("ip", "1.1.1.1/../../ping")
    assert rec.last.url.raw_path == b"/v3/community/1.1.1.1%2F..%2F..%2Fping"


async def test_riot_ip_is_benign_and_says_false_positive():
    client, _ = make_client(lambda r: httpx.Response(200, json=RIOT))
    result = await client.enrich("ip", "1.1.1.1")
    assert result["verdict"] == "benign"
    assert result["riot"] is True and result["noise"] is False
    assert result["name"] == "Cloudflare"
    assert "known benign service" in result["summary"] and "Cloudflare" in result["summary"]
    assert "false positive" in result["summary"]
    assert result["last_seen"] == "2020-01-01"


async def test_malicious_noise_ip_is_malicious_background_noise():
    client, _ = make_client(lambda r: httpx.Response(200, json=NOISE))
    result = await client.enrich("ip", "51.91.185.74")
    assert result["verdict"] == "malicious"
    assert result["noise"] is True
    assert result["classification"] == "malicious"
    assert result["name"] is None   # "unknown" is not a name
    assert "background noise" in result["summary"]
    assert result["link"] == "https://viz.greynoise.io/ip/51.91.185.74"


async def test_benign_scanner_is_benign():
    body = {**NOISE, "classification": "benign", "name": "Shodan.io"}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    result = await client.enrich("ip", "51.91.185.74")
    assert result["verdict"] == "benign"
    assert "Shodan.io" in result["summary"] and "false positive" in result["summary"]


async def test_unclassified_noise_is_unknown():
    body = {**NOISE, "classification": "unknown"}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    result = await client.enrich("ip", "51.91.185.74")
    assert result["verdict"] == "unknown"
    assert "background noise" in result["summary"]


async def test_not_found_is_none():
    client, _ = make_client(lambda r: httpx.Response(404, json=NOT_FOUND))
    assert await client.enrich("ip", "8.8.8.8") is None


async def test_other_kinds_make_no_call():
    client, rec = make_client(lambda r: httpx.Response(200, json=RIOT))
    assert await client.enrich("domain", "example.com") is None
    assert rec.requests == []


@pytest.mark.parametrize("status", [429, 401, 500])
async def test_vendor_error_raises_instead_of_looking_clean(status):
    client, _ = make_client(lambda r: httpx.Response(status, json=RATE_LIMITED))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("ip", "8.8.8.8")


async def test_connection_ok_on_404_and_reports_rate_limit():
    client, rec = make_client(lambda r: httpx.Response(404, json=NOT_FOUND))
    assert (await client.test_connection())["success"] is True
    assert rec.last.url.path == "/v3/community/8.8.8.8"

    client, _ = make_client(lambda r: httpx.Response(429, json=RATE_LIMITED))
    result = await client.test_connection()
    assert result["success"] is False and "rate limit" in result["message"]
    assert (await client.get_health())["status"] == "error"


async def test_key_never_appears_in_results_or_messages():
    client, _ = make_client(lambda r: httpx.Response(401, json={"message": "bad key"}), {"api_key": "gn-secret"})
    result = await client.test_connection()
    assert result["success"] is False and "gn-secret" not in result["message"]
    client, _ = make_client(lambda r: httpx.Response(200, json=RIOT), {"api_key": "gn-secret"})
    assert "gn-secret" not in str(await client.enrich("ip", "1.1.1.1"))
