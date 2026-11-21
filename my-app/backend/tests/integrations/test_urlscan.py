import httpx
import pytest

from app.integrations.urlscan import UrlscanClient
from tests.integrations.helpers import Recorder

SCAN_ID = "01a1feca-9b82-7465-9db0-da521c015ce3"

# Trimmed real response from GET https://urlscan.io/api/v1/search/?q=page.domain:example.com&size=1
SEARCH_HIT = {
    "results": [{
        "task": {
            "visibility": "public", "method": "api", "domain": "www.example.com", "apexDomain": "example.com",
            "time": "2026-11-21T15:47:38.926Z", "uuid": SCAN_ID, "url": "https://www.example.com/i3610rid2",
        },
        "stats": {"uniqIPs": 1, "uniqCountries": 1, "dataLength": 2540, "encodedDataLength": 2110, "requests": 2},
        "page": {
            "server": "cloudflare", "ip": "172.66.147.243", "mimeType": "text/html", "title": "Example Domain",
            "url": "https://www.example.com/i3610rid2", "domain": "www.example.com", "apexDomain": "example.com",
            "asnname": "CLOUDFLARENET - Cloudflare, Inc., US", "asn": "AS13335", "status": "404",
        },
        "labels": [],
        "_id": SCAN_ID,
        "sort": [1795276058926, SCAN_ID],
        "result": f"https://urlscan.io/api/v1/result/{SCAN_ID}/",
        "screenshot": f"https://urlscan.io/screenshots/{SCAN_ID}.png",
    }],
    "total": 1923, "took": 11, "has_more": False,
}
SEARCH_EMPTY = {"results": [], "total": 0, "took": 3, "has_more": False}
# Real response (HTTP 403) from the result API when called without an API key.
RESULT_ANONYMOUS = {"warning": "You're not logged in!"}


def result_doc(malicious=False, score=0):
    # Shape of the Result API's `verdicts` block (written from knowledge of the API: the
    # live endpoint refuses anonymous callers, so it could not be captured).
    return {"verdicts": {"overall": {
        "score": score, "categories": ["phishing"] if malicious else [], "brands": [], "tags": [],
        "malicious": malicious, "hasVerdicts": malicious or score > 0,
    }}}


def make_client(result_response, search=SEARCH_HIT, credentials=None):
    def handler(request):
        if request.url.path.startswith("/api/v1/search"):
            return httpx.Response(200, json=search)
        return result_response

    rec = Recorder(handler)
    client = UrlscanClient(credentials or {})
    rec.attach(client)
    return client, rec


def test_declares_contract_and_says_it_never_submits():
    assert UrlscanClient.platform_name == "urlscan"
    assert UrlscanClient.category == "enrichment"
    assert UrlscanClient.enriches == ("url", "domain")
    assert UrlscanClient.required_credentials == []
    assert "never submits" in UrlscanClient.description


async def test_domain_search_request():
    client, rec = make_client(httpx.Response(200, json=result_doc()), credentials={"api_key": "us-secret"})
    await client.enrich("domain", "Example.com")
    search = rec.requests[0]
    assert search.method == "GET"
    assert search.url.host == "urlscan.io" and search.url.path == "/api/v1/search/"
    assert search.url.params["q"] == 'page.domain:"example.com"'
    assert search.url.params["size"] == "1"
    assert search.headers["api-key"] == "us-secret"


async def test_url_search_quotes_and_escapes_the_value():
    client, rec = make_client(httpx.Response(200, json=result_doc()))
    await client.enrich("url", 'https://example.com/a?b="c"')
    quoted = '"https://example.com/a?b=\\"c\\""'
    assert rec.requests[0].url.params["q"] == f"page.url:{quoted} OR task.url:{quoted}"
    assert "api-key" not in rec.requests[0].headers


async def test_only_reads_and_never_submits_a_scan():
    client, rec = make_client(httpx.Response(200, json=result_doc(malicious=True, score=100)))
    await client.enrich("url", "https://www.example.com/i3610rid2")
    assert rec.paths() == ["GET /api/v1/search/", f"GET /api/v1/result/{SCAN_ID}/"]
    assert all(r.method == "GET" and "/scan" not in r.url.path for r in rec.requests)


async def test_malicious_verdict_mapping():
    client, _ = make_client(httpx.Response(200, json=result_doc(malicious=True, score=100)))
    result = await client.enrich("domain", "example.com")
    assert result["verdict"] == "malicious"
    assert result["score"] == 100 and result["categories"] == ["phishing"]
    assert result["verdict_available"] is True
    assert result["scan_id"] == SCAN_ID
    assert result["scanned_at"] == "2026-11-21T15:47:38.926Z"
    assert result["final_url"] == "https://www.example.com/i3610rid2"
    assert result["page_ip"] == "172.66.147.243" and result["page_asn"] == "AS13335"
    assert result["report_url"] == f"https://urlscan.io/result/{SCAN_ID}/"
    assert "malicious" in result["summary"]


async def test_score_without_malicious_flag_is_suspicious():
    client, _ = make_client(httpx.Response(200, json=result_doc(score=40)))
    assert (await client.enrich("domain", "example.com"))["verdict"] == "suspicious"


async def test_clean_scan_is_unknown_not_benign():
    client, _ = make_client(httpx.Response(200, json=result_doc()))
    result = await client.enrich("domain", "example.com")
    assert result["verdict"] == "unknown"
    assert "not proof" in result["summary"]


async def test_no_existing_scan_is_none():
    client, rec = make_client(httpx.Response(200, json=result_doc()), search=SEARCH_EMPTY)
    assert await client.enrich("domain", "example.com") is None
    assert len(rec.requests) == 1


async def test_refused_result_does_not_masquerade_as_clean():
    client, _ = make_client(httpx.Response(403, json=RESULT_ANONYMOUS))
    result = await client.enrich("domain", "example.com")
    assert result["verdict"] == "unknown"
    assert result["verdict_available"] is False
    assert "could not be read" in result["summary"] and "API key" in result["summary"]
    assert result["scan_id"] == SCAN_ID


@pytest.mark.parametrize("status", [429, 500])
async def test_result_error_raises(status):
    client, _ = make_client(httpx.Response(status, json={"message": "nope"}))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("domain", "example.com")


@pytest.mark.parametrize("status", [429, 400, 500])
async def test_search_error_raises_instead_of_looking_like_no_scans(status):
    rec = Recorder(lambda r: httpx.Response(status, json={"message": "Rate limit exceeded", "status": status}))
    client = UrlscanClient({})
    rec.attach(client)
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("domain", "example.com")


async def test_other_kinds_make_no_call():
    client, rec = make_client(httpx.Response(200, json=result_doc()))
    assert await client.enrich("ip", "192.0.2.1") is None
    assert rec.requests == []


async def test_connection_and_health():
    client, rec = make_client(httpx.Response(200, json=result_doc()), credentials={"api_key": "us-secret"})
    assert (await client.test_connection())["success"] is True
    assert rec.paths() == ["GET /api/v1/search/"]
    assert (await client.get_health())["status"] == "healthy"

    rec = Recorder(lambda r: httpx.Response(401, json={"message": "bad key"}))
    client = UrlscanClient({"api_key": "us-secret"})
    rec.attach(client)
    result = await client.test_connection()
    assert result["success"] is False and "us-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
