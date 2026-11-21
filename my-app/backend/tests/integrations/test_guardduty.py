import hashlib
from datetime import datetime, timezone

import httpx
import pytest

from app.integrations.guardduty import GuardDutyClient, severity_label, sigv4_headers, sigv4_signing_key
from app.services.log_normalizer import normalize_log_event
from tests.integrations.helpers import Recorder

# ---- SigV4 signer, checked against AWS's own published Signature Version 4 test suite ----
# (https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4)
SUITE = dict(
    access_key_id="AKIDEXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
    service="service",
    now=datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc),
)
SUITE_SCOPE = "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"


def test_sigv4_get_vanilla():
    signed = sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"", **SUITE)
    assert signed == {
        "X-Amz-Date": "20150830T123600Z",
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={SUITE_SCOPE}, SignedHeaders=host;x-amz-date, "
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        ),
    }


def test_sigv4_sorts_query_parameters():
    # suite case get-vanilla-query-order-key-case
    signed = sigv4_headers("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", {}, b"", **SUITE)
    assert signed["Authorization"].endswith(
        "SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")


def test_sigv4_post_with_body_and_extra_signed_headers():
    # suite case post-x-www-form-urlencoded: covers the payload hash and header canonicalisation
    body = b"Param1=value1"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "13",
        "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
    }
    assert headers["x-amz-content-sha256"] == "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"
    signed = sigv4_headers("POST", "https://example.amazonaws.com/", headers, body, **SUITE)
    assert signed["Authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={SUITE_SCOPE}, "
        "SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, "
        "Signature=d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b"
    )


def test_sigv4_signature_depends_on_every_input():
    base = sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"", **SUITE)["Authorization"]
    assert sigv4_headers("POST", "https://example.amazonaws.com/", {}, b"", **SUITE)["Authorization"] != base
    assert sigv4_headers("GET", "https://example.amazonaws.com/x", {}, b"", **SUITE)["Authorization"] != base
    assert sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"{}", **SUITE)["Authorization"] != base
    assert sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"", **{**SUITE, "region": "eu-west-1"})["Authorization"] != base
    assert sigv4_signing_key("a", "20150830", "us-east-1", "service") != sigv4_signing_key("b", "20150830", "us-east-1", "service")


def test_sigv4_session_token_is_signed_and_returned():
    signed = sigv4_headers("GET", "https://example.amazonaws.com/", {}, b"", session_token="tok", **SUITE)
    assert signed["X-Amz-Security-Token"] == "tok"
    assert "SignedHeaders=host;x-amz-date;x-amz-security-token" in signed["Authorization"]


# ---- connector -------------------------------------------------------------------------
CREDS = {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
         "region": "eu-west-1"}
DETECTOR = "12abc34d567e8fa901bc2d34e56789f0"
CONFIG = {"detector_id": DETECTOR}
SINCE = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
BASE = f"/detector/{DETECTOR}"


def finding(finding_id, updated_at, title, severity, **overrides):
    # Field names follow the GetFindings response syntax in the GuardDuty API reference.
    data = {
        "accountId": "123456789012",
        "arn": f"arn:aws:guardduty:eu-west-1:123456789012:detector/{DETECTOR}/finding/{finding_id}",
        "createdAt": "2026-11-21T07:00:00.000Z",
        "updatedAt": updated_at,
        "description": f"{title} (description).",
        "id": finding_id,
        "partition": "aws",
        "region": "eu-west-1",
        "schemaVersion": "2.0",
        "severity": severity,
        "title": title,
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0abc123def4567890", "instanceType": "t3.micro"},
        },
        "service": {
            "serviceName": "guardduty", "detectorId": DETECTOR, "count": 4, "archived": False,
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "connectionDirection": "INBOUND", "protocol": "TCP",
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.23", "country": {"countryName": "Netherlands"}},
                    "localPortDetails": {"port": 22, "portName": "SSH"},
                },
            },
        },
    }
    data.update(overrides)
    return data


IAM_FINDING = finding(
    "f-iam", "2026-11-21T09:30:00.000Z", "API GetCallerIdentity was invoked from a Tor exit node.", 8.0,
    type="Recon:IAMUser/TorIPCaller",
    resource={"resourceType": "AccessKey", "accessKeyDetails": {
        "accessKeyId": "AKIAI44QH8DHBEXAMPLE", "principalId": "AIDACKCEVSQ6C2EXAMPLE",
        "userName": "deploy-bot", "userType": "IAMUser"}},
    service={"serviceName": "guardduty", "count": 1, "action": {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {"api": "GetCallerIdentity", "serviceName": "sts.amazonaws.com",
                             "remoteIpDetails": {"ipAddressV4": "203.0.113.50"}}}},
)
EC2_FINDING = finding("f-ec2", "2026-11-21T08:00:00.000Z", "198.51.100.23 is performing SSH brute force attacks against i-0abc123def4567890.", 2.0)


def make_client(handler, config=CONFIG, credentials=CREDS):
    rec = Recorder(handler)
    client = GuardDutyClient(credentials, config)
    rec.attach(client)
    return client, rec


def api(findings, list_pages=None):
    """Fake GuardDuty: ListFindings pages, then GetFindings (returned newest first on purpose)."""
    pages = list_pages or [{"findingIds": [f["id"] for f in findings]}]
    state = {"page": 0}

    def handler(request):
        if request.url.path == f"{BASE}/findings":
            page = pages[state["page"]]
            state["page"] += 1
            return httpx.Response(200, json=page)
        if request.url.path == f"{BASE}/findings/get":
            wanted = Recorder.json(request)["findingIds"]
            return httpx.Response(200, json={"findings": [f for f in reversed(findings) if f["id"] in wanted]})
        return httpx.Response(404)

    return handler


def test_declares_contract():
    assert GuardDutyClient.platform_name == "aws_guardduty"
    assert GuardDutyClient.category == "source"
    assert GuardDutyClient.required_credentials == ["access_key_id", "secret_access_key", "region"]
    assert GuardDutyClient.optional_config == ["detector_id"]
    assert GuardDutyClient.auth_type == "api_key"


@pytest.mark.parametrize("score,label", [
    (1.0, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"), (8.9, "high"),
    (9.0, "critical"), (10.0, "critical"), (None, "medium"),
])
def test_severity_label(score, label):
    assert severity_label(score) == label


async def test_list_then_get_requests():
    client, rec = make_client(api([EC2_FINDING, IAM_FINDING]))
    await client.fetch_events(SINCE, limit=200)
    assert rec.paths() == [f"POST {BASE}/findings", f"POST {BASE}/findings/get"]
    assert all(r.url.host == "guardduty.eu-west-1.amazonaws.com" and r.url.scheme == "https" for r in rec.requests)

    listing = rec.json(rec.requests[0])
    assert listing["findingCriteria"] == {"criterion": {"updatedAt": {"greaterThan": int(SINCE.timestamp() * 1000)}}}
    assert listing["sortCriteria"] == {"attributeName": "updatedAt", "orderBy": "ASC"}
    assert listing["maxResults"] == 50
    assert "nextToken" not in listing
    assert rec.json(rec.requests[1])["findingIds"] == ["f-ec2", "f-iam"]


async def test_requests_are_sigv4_signed_and_verifiable():
    client, rec = make_client(api([EC2_FINDING]))
    await client.fetch_events(SINCE)
    for request in rec.requests:
        auth = request.headers["authorization"]
        amz_date = request.headers["x-amz-date"]
        assert auth.startswith(
            f"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/{amz_date[:8]}/eu-west-1/guardduty/aws4_request, "
            "SignedHeaders=content-type;host;x-amz-date, Signature=")
        assert request.headers["content-type"] == "application/json"
        assert CREDS["secret_access_key"] not in str(request.headers)
        # Re-sign exactly what went over the wire: the signature must match.
        expected = sigv4_headers(
            request.method, str(request.url), {"Content-Type": request.headers["content-type"]}, request.content,
            access_key_id=CREDS["access_key_id"], secret_access_key=CREDS["secret_access_key"],
            region="eu-west-1", service="guardduty",
            now=datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc),
        )
        assert auth == expected["Authorization"]


async def test_findings_map_to_security_alerts_oldest_first():
    client, _ = make_client(api([EC2_FINDING, IAM_FINDING]))
    events = await client.fetch_events(SINCE)

    assert [e["schemaId"] for e in events] == ["securityalert", "securityalert"]
    assert [e["data"]["SystemAlertId"] for e in events] == ["f-ec2", "f-iam"]
    assert [e["data"]["TimeGenerated"] for e in events] == ["2026-11-21T08:00:00.000Z", "2026-11-21T09:30:00.000Z"]

    ec2 = events[0]["data"]
    assert ec2["DisplayName"].startswith("198.51.100.23 is performing SSH brute force")
    assert ec2["AlertSeverity"] == "low"
    assert ec2["CompromisedEntity"] == "i-0abc123def4567890"
    assert ec2["Entities"] == [{"Type": "ip", "Address": "198.51.100.23"},
                               {"Type": "host", "HostName": "i-0abc123def4567890"}]
    assert ec2["CorrelationId"] == "f-ec2"
    assert ec2["ExtendedProperties"]["severity_score"] == 2.0 and ec2["ExtendedProperties"]["count"] == 4

    iam = events[1]["data"]
    assert iam["AlertSeverity"] == "high"
    assert iam["CompromisedEntity"] == "AKIAI44QH8DHBEXAMPLE"   # access key ID (an identifier, not the secret)
    assert iam["Entities"] == [{"Type": "ip", "Address": "203.0.113.50"}, {"Type": "account", "Name": "deploy-bot"}]
    assert CREDS["secret_access_key"] not in str(events)

    normalized = [normalize_log_event(e["schemaId"], e["data"]) for e in events]
    assert [n["severity"] for n in normalized] == ["low", "high"]
    assert normalized[0]["time_generated"] < normalized[1]["time_generated"]
    assert normalized[0]["source_ip"] == "198.51.100.23" and normalized[0]["host"] == "i-0abc123def4567890"
    assert normalized[1]["source_ip"] == "203.0.113.50" and normalized[1]["user_identity"] == "deploy-bot"
    assert normalized[1]["host"] == "AKIAI44QH8DHBEXAMPLE"
    assert normalized[1]["correlation_id"] == "f-iam"


async def test_port_probe_ip_and_attack_sequence_correlation():
    probe = finding("f-probe", "2026-11-21T08:00:00.000Z", "Unprotected port is being probed.", 9.5,
                    associatedAttackSequenceArn="arn:aws:guardduty:eu-west-1:123456789012:attack-sequence/seq-1",
                    service={"action": {"actionType": "PORT_PROBE", "portProbeAction": {"portProbeDetails": [
                        {"remoteIpDetails": {"ipAddressV4": "198.51.100.99"}}]}}})
    client, _ = make_client(api([probe]))
    data = (await client.fetch_events(SINCE))[0]["data"]
    assert data["AlertSeverity"] == "critical"
    assert data["Entities"][0] == {"Type": "ip", "Address": "198.51.100.99"}
    assert data["CorrelationId"].endswith("attack-sequence/seq-1")
    assert normalize_log_event("securityalert", data)["severity"] == "critical"


async def test_pagination_and_limit():
    findings = [finding(f"f-{i:03d}", f"2026-11-21T08:{i // 60:02d}:{i % 60:02d}.000Z", f"Finding {i}", 5.0) for i in range(70)]
    pages = [{"findingIds": [f["id"] for f in findings[:50]], "nextToken": "page-2"},
             {"findingIds": [f["id"] for f in findings[50:70]]}]
    client, rec = make_client(api(findings, pages))
    events = await client.fetch_events(SINCE, limit=60)

    assert rec.paths() == [f"POST {BASE}/findings"] * 2 + [f"POST {BASE}/findings/get"] * 2
    first, second = rec.json(rec.requests[0]), rec.json(rec.requests[1])
    assert first["maxResults"] == 50 and "nextToken" not in first
    assert second["maxResults"] == 10 and second["nextToken"] == "page-2"
    assert [len(rec.json(r)["findingIds"]) for r in rec.requests[2:]] == [50, 10]   # GetFindings takes 50 at most
    assert [e["data"]["SystemAlertId"] for e in events] == [f"f-{i:03d}" for i in range(60)]


async def test_no_findings_is_empty_list_and_skips_get():
    client, rec = make_client(api([]))
    assert await client.fetch_events(SINCE) == []
    assert rec.paths() == [f"POST {BASE}/findings"]


@pytest.mark.parametrize("status", [400, 403, 500])
async def test_vendor_error_raises_instead_of_looking_empty(status):
    error = {"message": "The request is rejected because the input detectorId is not owned by the current account.",
             "__type": "BadRequestException"}
    client, _ = make_client(lambda r: httpx.Response(status, json=error))
    with pytest.raises(httpx.HTTPStatusError):
        await client.fetch_events(SINCE)


async def test_get_findings_error_raises():
    def handler(request):
        if request.url.path.endswith("/findings"):
            return httpx.Response(200, json={"findingIds": ["f-1"]})
        return httpx.Response(500, json={"message": "Internal server error"})

    client, _ = make_client(handler)
    with pytest.raises(httpx.HTTPStatusError):
        await client.fetch_events(SINCE)


async def test_missing_detector_id_is_a_clear_error():
    client, rec = make_client(api([]), config={})
    with pytest.raises(ValueError, match="detector_id"):
        await client.fetch_events(SINCE)
    result = await client.test_connection()
    assert result["success"] is False and "detector_id" in result["message"]
    assert rec.requests == []


async def test_detector_id_is_one_path_segment():
    client, rec = make_client(lambda r: httpx.Response(200, json={"findingIds": []}), config={"detector_id": "abc/../../x"})
    await client.fetch_events(SINCE)
    assert rec.last.url.raw_path == b"/detector/abc%2F..%2F..%2Fx/findings"


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json={"status": "ENABLED", "serviceRole": "arn:aws:iam::1:role/x"}))
    assert await client.test_connection() == {"success": True, "message": "Connected to GuardDuty (detector status: ENABLED)"}
    assert rec.paths() == [f"GET {BASE}"]
    assert rec.last.headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make_client(lambda r: httpx.Response(403, json={"message": "The security token included in the request is invalid."}))
    result = await client.test_connection()
    assert result["success"] is False and CREDS["secret_access_key"] not in result["message"]
    assert (await client.get_health())["status"] == "error"
