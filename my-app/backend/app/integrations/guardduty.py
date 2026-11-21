"""Amazon GuardDuty as an alert source, with a small standard-library SigV4 request signer."""

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.guardduty")

_UNRESERVED = "-_.~"   # with letters and digits, the only bytes SigV4 leaves unencoded


# ---- AWS Signature Version 4 ---------------------------------------------------------
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def sigv4_signing_key(secret_access_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """Derive the per-day, per-region, per-service key: a chain of four HMACs."""
    k_date = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sigv4_headers(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service: str,
    now: datetime | None = None,
    session_token: str | None = None,
) -> dict[str, str]:
    """Sign one request. Returns the headers to ADD to it: X-Amz-Date, Authorization
    and, for temporary credentials, X-Amz-Security-Token.

    `url` must be the exact URL that will be sent, with its path already percent-encoded.
    Every header in `headers` is signed (plus Host and the X-Amz-* ones added here), so
    pass only headers that reach AWS unchanged: for this connector just Content-Type.
    """
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    parts = urlsplit(url)

    # 1. Canonical request -------------------------------------------------------------
    # Path: every service except S3 encodes the (already encoded) path once more.
    canonical_uri = quote(parts.path or "/", safe="/" + _UNRESERVED)
    # Query: encode each name and value, then sort by name (and value for repeats).
    pairs = [
        (quote(name, safe=_UNRESERVED), quote(value, safe=_UNRESERVED))
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    canonical_query = "&".join(f"{name}={value}" for name, value in sorted(pairs))
    # Headers: lowercase names, trimmed values with runs of spaces collapsed, sorted by name.
    to_sign = {name.lower(): re.sub(r"\s+", " ", str(value).strip()) for name, value in headers.items()}
    to_sign["host"] = parts.netloc
    to_sign["x-amz-date"] = amz_date
    if session_token:
        to_sign["x-amz-security-token"] = session_token
    names = sorted(to_sign)
    canonical_headers = "".join(f"{name}:{to_sign[name]}\n" for name in names)
    signed_headers = ";".join(names)
    payload_hash = hashlib.sha256(body or b"").hexdigest()
    canonical_request = "\n".join(
        [method.upper(), canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )

    # 2. String to sign: algorithm, time, credential scope, hash of the canonical request
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )

    # 3. Signature: HMAC of the string to sign with the derived key
    signing_key = sigv4_signing_key(secret_access_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    result = {
        "X-Amz-Date": amz_date,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    if session_token:
        result["X-Amz-Security-Token"] = session_token
    return result


# ---- GuardDuty -----------------------------------------------------------------------

def severity_label(score: Any) -> str:
    """GuardDuty's numeric severity (1.0-10.0) as its console label."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _remote_ip(finding: dict) -> str | None:
    """The attacker-side IP, wherever this finding type keeps it."""
    action = ((finding.get("service") or {}).get("action")) or {}
    for key in ("networkConnectionAction", "awsApiCallAction", "kubernetesApiCallAction", "rdsLoginAttemptAction"):
        details = (action.get(key) or {}).get("remoteIpDetails") or {}
        if details.get("ipAddressV4") or details.get("ipAddressV6"):
            return details.get("ipAddressV4") or details.get("ipAddressV6")
    for probe in (action.get("portProbeAction") or {}).get("portProbeDetails") or []:
        details = (probe or {}).get("remoteIpDetails") or {}
        if details.get("ipAddressV4") or details.get("ipAddressV6"):
            return details.get("ipAddressV4") or details.get("ipAddressV6")
    return None


class GuardDutyClient(BaseIntegrationClient):
    platform_name = "aws_guardduty"
    display_name = "Amazon GuardDuty"
    description = (
        "Pulls threat findings from Amazon GuardDuty for one detector and ingests them. "
        "Read-only; the IAM user needs guardduty:ListFindings, GetFindings and GetDetector."
    )
    auth_type = "api_key"
    category = "source"
    required_credentials = ["access_key_id", "secret_access_key", "region"]
    optional_credentials = ["session_token"]
    optional_config = ["detector_id"]
    capabilities = ["fetch_events"]

    SERVICE = "guardduty"
    PAGE_SIZE = 50   # API maximum for both ListFindings and GetFindings

    def _detector_path(self) -> str:
        detector_id = self.config.get("detector_id")
        if not detector_id:
            raise ValueError("No detector_id configured: find it on the GuardDuty console's Settings page")
        return f"/detector/{seg(detector_id)}"

    async def _request(self, method: str, path: str, payload: dict | None = None):
        region = str(self.credentials["region"]).strip()
        url = f"https://guardduty.{region}.amazonaws.com{path}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        headers = {"Content-Type": "application/json"}
        headers.update(sigv4_headers(
            method, url, headers, body,
            access_key_id=self.credentials["access_key_id"],
            secret_access_key=self.credentials["secret_access_key"],
            region=region,
            service=self.SERVICE,
            session_token=self.credentials.get("session_token"),
        ))
        client = await self.get_http_client()
        return await client.request(method, url, headers=headers, content=body)

    async def test_connection(self) -> dict:
        try:
            response = await self._request("GET", self._detector_path())
            if response.status_code in (401, 403):
                return {"success": False, "message": "AWS rejected the credentials or they lack GuardDuty read permissions"}
            response.raise_for_status()
            status = response.json().get("status", "unknown")
            return {"success": True, "message": f"Connected to GuardDuty (detector status: {status})"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    @staticmethod
    def _to_envelope(finding: dict) -> dict:
        resource = finding.get("resource") or {}
        instance_id = (resource.get("instanceDetails") or {}).get("instanceId")
        access_key = resource.get("accessKeyDetails") or {}
        remote_ip = _remote_ip(finding)

        entities = []
        if remote_ip:
            entities.append({"Type": "ip", "Address": remote_ip})
        if instance_id:
            entities.append({"Type": "host", "HostName": instance_id})
        if access_key.get("userName"):
            entities.append({"Type": "account", "Name": access_key["userName"]})

        data = {
            "TimeGenerated": finding.get("updatedAt") or finding.get("createdAt"),
            "DisplayName": finding.get("title") or finding.get("type") or "GuardDuty finding",
            "AlertSeverity": severity_label(finding.get("severity")),
            "Description": finding.get("description"),
            "CompromisedEntity": instance_id or access_key.get("accessKeyId"),
            "Entities": entities,
            # GuardDuty updates one finding as the activity recurs, and ties findings
            # into attack sequences: either way related updates share this id.
            "CorrelationId": finding.get("associatedAttackSequenceArn") or finding.get("id"),
            "SystemAlertId": finding.get("id"),
            "AlertType": finding.get("type"),
            "ProviderName": "Amazon GuardDuty",
            "SourceSystem": "Amazon GuardDuty",
            "ExtendedProperties": {
                "severity_score": finding.get("severity"),
                "account_id": finding.get("accountId"),
                "region": finding.get("region"),
                "arn": finding.get("arn"),
                "resource_type": resource.get("resourceType"),
                "count": (finding.get("service") or {}).get("count"),
                "created_at": finding.get("createdAt"),
            },
        }
        return {"schemaId": "securityalert", "data": data}

    async def fetch_events(self, since: datetime, limit: int = 500) -> list[dict]:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        limit = max(int(limit), 1)
        base = self._detector_path()
        oldest_first = {"attributeName": "updatedAt", "orderBy": "ASC"}

        # 1. ListFindings: ids of findings updated after `since` (epoch milliseconds), oldest first.
        finding_ids: list[str] = []
        next_token = None
        while len(finding_ids) < limit:
            payload: dict[str, Any] = {
                "findingCriteria": {"criterion": {"updatedAt": {"greaterThan": int(since.timestamp() * 1000)}}},
                "sortCriteria": oldest_first,
                "maxResults": min(self.PAGE_SIZE, limit - len(finding_ids)),
            }
            if next_token:
                payload["nextToken"] = next_token
            response = await self._request("POST", f"{base}/findings", payload)
            response.raise_for_status()
            page = response.json()
            finding_ids.extend(page.get("findingIds") or [])
            next_token = page.get("nextToken")
            if not next_token:
                break
        finding_ids = finding_ids[:limit]
        if not finding_ids:
            return []

        # 2. GetFindings: the full findings, 50 ids at a time.
        findings: list[dict] = []
        for start in range(0, len(finding_ids), self.PAGE_SIZE):
            response = await self._request(
                "POST", f"{base}/findings/get",
                {"findingIds": finding_ids[start:start + self.PAGE_SIZE], "sortCriteria": oldest_first},
            )
            response.raise_for_status()
            findings.extend(f for f in response.json().get("findings") or [] if isinstance(f, dict))

        findings.sort(key=lambda f: str(f.get("updatedAt") or f.get("createdAt") or ""))
        return [self._to_envelope(f) for f in findings]
