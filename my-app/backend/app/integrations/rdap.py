"""RDAP (the structured successor to WHOIS): when was this domain registered, and by whom?"""

import logging
from datetime import datetime, timezone

from app.integrations.base_client import BaseIntegrationClient, seg

logger = logging.getLogger("cane_ai.integrations.rdap")


def _parse_date(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _vcard_name(entity: dict) -> str | None:
    """The `fn` (formatted name) of an RDAP entity's jCard: ["vcard", [["fn", {}, "text", "Name"], ...]]."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn" and prop[3]:
            return str(prop[3])
    return None


class RdapClient(BaseIntegrationClient):
    platform_name = "rdap"
    display_name = "RDAP (domain registration)"
    description = (
        "Looks up a domain's registration date and registrar through the public RDAP "
        "bootstrap (rdap.org). Newly registered domains (under 30 days) are flagged as "
        "suspicious; age alone never proves a domain is benign. No account needed."
    )
    auth_type = "api_key"   # no credentials; the enum has no "none" value
    category = "enrichment"
    required_credentials: list[str] = []
    optional_config: list[str] = []
    capabilities = ["enrich_domain"]
    enriches = ("domain",)

    BASE_URL = "https://rdap.org"
    NEW_DOMAIN_DAYS = 30
    MAX_LOOKUPS = 3
    TEST_DOMAIN = "example.com"

    async def _get_domain(self, domain: str):
        client = await self.get_http_client()
        # rdap.org answers with a redirect to the registry's own RDAP server.
        return await client.get(
            f"{self.BASE_URL}/domain/{seg(domain)}",
            headers={"Accept": "application/rdap+json"},
            follow_redirects=True,
        )

    async def test_connection(self) -> dict:
        try:
            response = await self._get_domain(self.TEST_DOMAIN)
            response.raise_for_status()
            return {"success": True, "message": "RDAP bootstrap (rdap.org) is reachable"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {e}"}

    async def get_health(self) -> dict:
        result = await self.test_connection()
        return {"status": "healthy" if result["success"] else "error", "message": result["message"]}

    async def enrich(self, kind: str, value: str) -> dict | None:
        if kind != "domain":
            return None
        domain = str(value).strip().strip(".").lower()
        if not domain or "." not in domain:
            return None

        # Registries only know registered domains, not hostnames under them, so on 404
        # drop the leftmost label and retry (www.example.com -> example.com).
        data = None
        for _ in range(self.MAX_LOOKUPS):
            response = await self._get_domain(domain)
            if response.status_code == 404:
                parent = domain.split(".", 1)[1]
                if "." not in parent:
                    return None
                domain = parent
                continue
            response.raise_for_status()   # 429 / 5xx: an error, never "nothing found"
            data = response.json()
            break
        if not isinstance(data, dict):
            return None

        events = {
            str(e.get("eventAction", "")).lower(): e.get("eventDate")
            for e in data.get("events") or [] if isinstance(e, dict)
        }
        registered = _parse_date(events.get("registration"))
        registrar = None
        for entity in data.get("entities") or []:
            if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
                registrar = _vcard_name(entity) or entity.get("handle")
                break

        age_days = None
        if registered:
            age_days = max((datetime.now(timezone.utc) - registered).days, 0)

        registrar_text = f" through {registrar}" if registrar else ""
        if age_days is None:
            verdict = "unknown"
            summary = f"{domain} is registered{registrar_text}, but the registry does not publish its registration date."
        elif age_days < self.NEW_DOMAIN_DAYS:
            verdict = "suspicious"
            summary = (
                f"{domain} was registered only {age_days} day(s) ago{registrar_text}: "
                "newly registered domains are common in phishing and malware campaigns."
            )
        else:
            verdict = "unknown"
            summary = (
                f"{domain} was registered {age_days} days ago ({registered.date().isoformat()}){registrar_text}; "
                "an established domain, which on its own does not prove it is safe."
            )

        return {
            "verdict": verdict,
            "summary": summary,
            "domain": domain,
            "registered_at": registered.isoformat() if registered else None,
            "age_days": age_days,
            "registrar": registrar,
            "expires_at": events.get("expiration"),
            "last_changed_at": events.get("last changed"),
            "status": data.get("status") or [],
            "nameservers": [
                str(ns.get("ldhName")).lower()
                for ns in data.get("nameservers") or [] if isinstance(ns, dict) and ns.get("ldhName")
            ],
        }
