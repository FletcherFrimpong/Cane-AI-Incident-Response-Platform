from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.integrations.rdap import RdapClient
from tests.integrations.helpers import Recorder

# Trimmed real response for example.com (rdap.org redirected to Verisign's RDAP server).
EXAMPLE_COM = {
    "objectClassName": "domain",
    "handle": "2336799_DOMAIN_COM-VRSN",
    "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
    "entities": [{
        "objectClassName": "entity", "handle": "376", "roles": ["registrar"],
        "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                 ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
        "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", ""]]]}],
    }],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43Z"},
        {"eventAction": "last update of RDAP database", "eventDate": "2026-11-21T15:58:27Z"},
    ],
    "nameservers": [{"objectClassName": "nameserver", "ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"},
                    {"objectClassName": "nameserver", "ldhName": "HERA.NS.CLOUDFLARE.COM"}],
}


def registered_days_ago(days: int) -> dict:
    when = (datetime.now(timezone.utc) - timedelta(days=days, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {**EXAMPLE_COM, "ldhName": "NEW.EXAMPLE",
            "events": [{"eventAction": "registration", "eventDate": when}]}


def make_client(handler):
    rec = Recorder(handler)
    client = RdapClient({})
    rec.attach(client)
    return client, rec


def test_declares_contract():
    assert RdapClient.platform_name == "rdap"
    assert RdapClient.category == "enrichment"
    assert RdapClient.enriches == ("domain",)
    assert RdapClient.required_credentials == []
    assert RdapClient.auth_type == "api_key"


async def test_request_goes_to_rdap_org_bootstrap():
    client, rec = make_client(lambda r: httpx.Response(200, json=EXAMPLE_COM))
    await client.enrich("domain", "Example.COM.")
    assert rec.last.method == "GET"
    assert str(rec.last.url) == "https://rdap.org/domain/example.com"
    assert rec.last.headers["accept"] == "application/rdap+json"


async def test_follows_the_bootstrap_redirect_to_the_registry():
    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"})
        return httpx.Response(200, json=EXAMPLE_COM)

    client, rec = make_client(handler)
    result = await client.enrich("domain", "example.com")
    assert [r.url.host for r in rec.requests] == ["rdap.org", "rdap.verisign.com"]
    assert result["registrar"] == "RESERVED-Internet Assigned Numbers Authority"


async def test_old_domain_maps_to_unknown_with_age_and_registrar():
    client, _ = make_client(lambda r: httpx.Response(200, json=EXAMPLE_COM))
    result = await client.enrich("domain", "example.com")
    expected_age = (datetime.now(timezone.utc) - datetime(1995, 8, 14, 4, tzinfo=timezone.utc)).days
    assert result["verdict"] == "unknown"   # age alone is never proof of benign
    assert result["age_days"] == expected_age
    assert result["registered_at"] == "1995-08-14T04:00:00+00:00"
    assert result["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert result["expires_at"] == "2027-08-13T04:00:00Z"
    assert result["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    assert "1995-08-14" in result["summary"] and "does not prove" in result["summary"]


async def test_domain_under_30_days_is_suspicious():
    client, _ = make_client(lambda r: httpx.Response(200, json=registered_days_ago(3)))
    result = await client.enrich("domain", "new.example")
    assert result["verdict"] == "suspicious"
    assert result["age_days"] == 3
    assert "3 day(s) ago" in result["summary"]


@pytest.mark.parametrize("days,verdict", [(29, "suspicious"), (30, "unknown")])
async def test_30_day_boundary(days, verdict):
    client, _ = make_client(lambda r: httpx.Response(200, json=registered_days_ago(days)))
    assert (await client.enrich("domain", "new.example"))["verdict"] == verdict


async def test_missing_registration_date_is_unknown_not_a_crash():
    body = {**EXAMPLE_COM, "events": [{"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}]}
    client, _ = make_client(lambda r: httpx.Response(200, json=body))
    result = await client.enrich("domain", "example.com")
    assert result["verdict"] == "unknown" and result["age_days"] is None


async def test_404_is_none():
    client, rec = make_client(lambda r: httpx.Response(404, json={"errorCode": 404, "title": "Not Found"}))
    assert await client.enrich("domain", "unregistered-example.com") is None
    assert rec.paths() == ["GET /domain/unregistered-example.com"]   # never queries the bare TLD


async def test_hostname_falls_back_to_its_registered_domain():
    def handler(request):
        if request.url.path == "/domain/example.com":
            return httpx.Response(200, json=EXAMPLE_COM)
        return httpx.Response(404)

    client, rec = make_client(handler)
    result = await client.enrich("domain", "mail.example.com")
    assert rec.paths() == ["GET /domain/mail.example.com", "GET /domain/example.com"]
    assert result["domain"] == "example.com"


async def test_other_kinds_make_no_call():
    client, rec = make_client(lambda r: httpx.Response(200, json=EXAMPLE_COM))
    assert await client.enrich("ip", "192.0.2.1") is None
    assert rec.requests == []


@pytest.mark.parametrize("status", [429, 500])
async def test_vendor_error_raises_instead_of_looking_unregistered(status):
    client, _ = make_client(lambda r: httpx.Response(status, text="slow down"))
    with pytest.raises(httpx.HTTPStatusError):
        await client.enrich("domain", "example.com")


async def test_connection_and_health():
    client, rec = make_client(lambda r: httpx.Response(200, json=EXAMPLE_COM))
    assert (await client.test_connection())["success"] is True
    assert rec.last.url.path == "/domain/example.com"
    assert (await client.get_health())["status"] == "healthy"

    client, _ = make_client(lambda r: httpx.Response(503))
    assert (await client.test_connection())["success"] is False
    assert (await client.get_health())["status"] == "error"
