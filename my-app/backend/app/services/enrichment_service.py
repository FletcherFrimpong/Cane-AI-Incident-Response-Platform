"""
Enrichment: what do outside sources know about the things in this incident?

Two kinds of lookup, each sent to every connected integration that supports it:
  indicators  IPs, domains, URLs, file hashes -> reputation (VirusTotal, AbuseIPDB,
              GreyNoise, urlscan, RDAP domain age, GeoIP, Hybrid Analysis, MISP, OpenCTI)
  context     accounts and hosts -> who/what they are (Entra ID, Okta, Intune, EDR)

The result is stored on the incident, shown to the analyst, and given to the LLM.
Everything here is best-effort: a slow or failing source is skipped, never fatal.
"""

import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.integration_service import active_clients, close_clients

logger = logging.getLogger("cane_ai.enrichment")

_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
LOOKUP_TIMEOUT_SECONDS = 12
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}

_HASH_FIELDS = [
    "FileHash", "SHA256", "SHA1", "MD5", "FileHashSha256", "FileHashSha1",
    "FileHashMd5", "InitiatingProcessSHA256", "InitiatingProcessSHA1",
]
_DOMAIN_FIELDS = [
    "DomainName", "DestinationHostName", "UrlDomain", "SenderMailFromDomain", "QueryName", "Name",
]
_URL_FIELDS = [
    "Url", "RemoteUrl", "FileOriginUrl", "ClickUrl", "RequestURL",
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable public address."""
    try:
        return ipaddress.ip_address(ip_str).is_global
    except (ValueError, TypeError):
        return False


def _looks_like_domain(value: str) -> bool:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or " " in value or "/" in value or "@" in value:
        return False
    if _is_ip(value):
        return False
    labels = value.split(".")
    return len(labels) >= 2 and labels[-1].isalpha() and all(label for label in labels)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_iocs(events_data: list[dict]) -> dict:
    """Extract unique IOCs from log event data (pure function, no I/O)."""
    ips, hashes, domains, urls = set(), set(), set(), set()

    for event in events_data:
        for field in ("source_ip", "destination_ip"):
            val = event.get(field)
            if val and _is_public_ip(str(val)):
                ips.add(str(val))

        raw = event.get("raw_data") or {}

        for field in _HASH_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and _HASH_RE.fullmatch(val):
                hashes.add(val.lower())

        for field in _URL_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and val.startswith("http"):
                urls.add(val)
                host = urlparse(val).hostname
                if host and _looks_like_domain(host):
                    domains.add(host.lower())

        for field in _DOMAIN_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and _looks_like_domain(val):
                domains.add(val.strip().lower().rstrip("."))

    return {
        "ips": sorted(ips),
        "file_hashes": sorted(hashes),
        "domains": sorted(domains),
        "urls": sorted(urls),
    }


def extract_entities(events_data: list[dict]) -> dict:
    """Accounts and hosts the incident involves (the organisation's own assets)."""
    users, hosts = set(), set()
    for event in events_data:
        user = event.get("user_identity")
        if isinstance(user, str) and "@" in user:
            users.add(user.strip().lower())
        host = event.get("host")
        if isinstance(host, str) and host.strip():
            hosts.add(host.strip().lower())
    return {"users": sorted(users), "hosts": sorted(hosts)}


def worst_verdict(sources: list[dict]) -> str:
    return max((s.get("verdict") or "unknown" for s in sources), key=lambda v: VERDICT_RANK.get(v, 0), default="unknown")


async def _ask(client, call, label: str) -> dict | None:
    try:
        reply = await asyncio.wait_for(call, timeout=LOOKUP_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("%s timed out on %s", client.integration_name, label)
        return None
    except NotImplementedError:
        return None
    except Exception as e:  # noqa: BLE001 - connectors raise httpx and vendor-specific errors
        logger.warning("%s failed on %s: %s", client.integration_name, label, e)
        return None
    if not isinstance(reply, dict) or not reply:
        return None
    return {"source": client.integration_name, "platform": client.platform_name, **reply}


async def enrich_incident_data(db: AsyncSession, events_data: list[dict], max_per_type: int = 4) -> dict | None:
    """Look up the incident's indicators and entities. Returns None when no connected
    integration can enrich anything (so callers can tell "nothing found" from "not set up")."""
    iocs = extract_iocs(events_data)
    entities = extract_entities(events_data)
    kinds = [("ip", iocs["ips"]), ("domain", iocs["domains"]), ("url", iocs["urls"]), ("file_hash", iocs["file_hashes"])]
    context_kinds = [("user", entities["users"]), ("host", entities["hosts"])]

    opened: list = []
    indicators: list[dict] = []
    context: list[dict] = []
    used: set[str] = set()
    try:
        for kind, values in kinds:
            if not values:
                continue
            clients = await active_clients(db, enriches=kind)
            opened.extend(clients)
            if not clients:
                continue
            for value in values[:max_per_type]:
                replies = await asyncio.gather(*[
                    _ask(c, c.enrich(kind, value), f"{kind} {value}") for c in clients
                ])
                sources = [r for r in replies if r]
                used.update(s["source"] for s in sources)
                indicators.append({"kind": kind, "value": value, "verdict": worst_verdict(sources), "sources": sources})

        for kind, values in context_kinds:
            if not values:
                continue
            clients = await active_clients(db, context=kind)
            opened.extend(clients)
            if not clients:
                continue
            for value in values[:max_per_type]:
                method = "describe_user" if kind == "user" else "describe_host"
                replies = await asyncio.gather(*[
                    _ask(c, getattr(c, method)(value), f"{kind} {value}") for c in clients
                ])
                sources = [r for r in replies if r]
                used.update(s["source"] for s in sources)
                if sources:
                    context.append({"kind": kind, "value": value, "sources": sources})
    finally:
        await close_clients(opened)

    if not opened:
        return None
    result = {
        "indicators": indicators,
        "context": context,
        "sources": sorted(used),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("Enrichment: %d indicators, %d entities described, sources %s",
                len(indicators), len(context), result["sources"])
    return result
