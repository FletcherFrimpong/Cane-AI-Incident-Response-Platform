import httpx
import pytest

from app.integrations.hybrid_analysis import HybridAnalysisClient
from tests.integrations.helpers import Recorder

SHA256 = "98983e00b47bcbe9ebbaf5f28ea6cdbf619dd88c91f481b18fec7ffdb68ab741"
MD5 = "44d88612fea8a8f36de82e1278abb02f"
CREDS = {"api_key": "ha-secret"}

# Shape of GET /api/v2/overview/{sha256} (field names as used by the public integrations
# of this API: sha256, last_file_name, threat_score, verdict, vx_family, type, size, ...).
OVERVIEW = {
    "sha256": SHA256,
    "last_file_name": "invoice.pdf.exe",
    "other_file_name": ["payload.exe"],
    "threat_score": 100,
    "verdict": "malicious",
    "url_analysis": False,
    "size": 232960,
    "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "type_short": ["peexe", "executable"],
    "analysis_start_time": "2024-03-05T11:16:38+00:00",
    "last_multi_scan": "2024-03-05T11:16:40+00:00",
    "tags": ["ransomware"],
    "architecture": "WINDOWS",
    "vx_family": "Trojan.Ransom.WannaCryptor",
    "multiscan_result": 91,
}


def make_client(handler):
    rec = Recorder(handler)
    client = HybridAnalysisClient(CREDS)
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert HybridAnalysisClient.platform_name == "hybrid_analysis"
    assert HybridAnalysisClient.category == "enrichment"
    assert HybridAnalysisClient.enriches == ("file_hash",)
    assert HybridAnalysisClient.required_credentials == ["api_key"]
    assert HybridAnalysisClient.auth_type == "api_key"


async def test_sha256_lookup_request():
    client, rec = make_client(lambda r: httpx.Response(200, json=OVERVIEW))
    await client.enrich("file_hash", SHA256.upper())
    assert len(rec.requests) == 1
    assert rec.last.method == "GET"   # a lookup; nothing is uploaded
    assert str(rec.last.url) == f"https://www.hybrid-analysis.com/api/v2/overview/{SHA256}"
    assert rec.last.headers["api-key"] == "ha-secret"
    assert rec.last.headers["user-agent"] == "Falcon Sandbox"


async def test_malicious_report_mapping():
    client, _ = make_client(lambda r: httpx.Response(200, json=OVERVIEW))
    result = await client.enrich("file_hash", SHA256)
    assert result["verdict"] == "malicious"
    assert result["sandbox_verdict"] == "malicious"
    assert result["threat_score"] == 100
    assert result["malware_family"] == "Trojan.Ransom.WannaCryptor"
    assert result["av_detection_percent"] == 91
    assert result["file_name"] == "invoice.pdf.exe"
    assert result["tags"] == ["ransomware"]
    assert result["report_url"] == f"https://www.hybrid-analysis.com/sample/{SHA256}"
    assert "malicious" in result["summary"] and "100/100" in result["summary"]
    assert "ha-secret" not in str(result)


@pytest.mark.parametrize("raw,expected", [
    ("suspicious", "suspicious"),
    ("whitelisted", "benign"),
    ("no specific threat", "unknown"),
    ("no verdict", "unknown"),
    (None, "unknown"),
])
async def test_verdict_mapping(raw, expected):
    body = {**OVERVIEW, "verdict": raw, "threat_score": None, "vx_family": None}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    result = await client.enrich("file_hash", SHA256)
    assert result["verdict"] == expected
    assert result["threat_score"] is None


async def test_md5_is_resolved_to_sha256_first():
    def handler(request):
        if request.url.path == "/api/v2/search/hash":
            return httpx.Response(200, json=[{"sha256": SHA256, "verdict": "malicious", "threat_score": 100}])
        return httpx.Response(200, json=OVERVIEW)

    client, rec = make_client(handler)
    result = await client.enrich("file_hash", MD5)
    assert rec.paths() == ["GET /api/v2/search/hash", f"GET /api/v2/overview/{SHA256}"]
    assert rec.requests[0].url.params["hash"] == MD5
    assert rec.requests[0].headers["api-key"] == "ha-secret"
    assert result["verdict"] == "malicious"


async def test_md5_with_no_report_is_none():
    client, rec = make_client(lambda r: httpx.Response(200, json=[]))
    assert await client.enrich("file_hash", MD5) is None
    assert rec.paths() == ["GET /api/v2/search/hash"]


async def test_not_found_is_none():
    client, _ = make_client(lambda r: httpx.Response(404, json={"message": "Not Found"}))
    assert await client.enrich("file_hash", SHA256) is None


async def test_non_hash_values_and_other_kinds_make_no_call():
    client, rec = make_client(lambda r: httpx.Response(200, json=OVERVIEW))
    assert await client.enrich("file_hash", "../../submit/file") is None
    assert await client.enrich("ip", "192.0.2.1") is None
    assert rec.requests == []


@pytest.mark.parametrize("status", [401, 429, 500])
async def test_vendor_error_raises_instead_of_looking_clean(status):
    client, _ = make_client(lambda r: httpx.Response(status, json={"message": "Exceeded maximum API requests"}))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("file_hash", SHA256)


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json={"api_key": "x", "auth_level": 100}))
    assert (await client.test_connection())["success"] is True
    assert rec.paths() == ["GET /api/v2/key/current"]
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make_client(lambda r: httpx.Response(401, json={"message": "bad key"}))
    result = await client.test_connection()
    assert result["success"] is False and "ha-secret" not in result["message"]
    assert (await client.get_health())["status"] == "error"
