"""
Auto-enrichment service: extracts IOCs from log events and queries
threat intelligence platforms (VirusTotal, AbuseIPDB) before AI triage.
"""

import ipaddress
import logging
import re
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.integration_service import get_integration_client_by_platform
from app.exceptions import NotFoundError

logger = logging.getLogger("cane_ai.enrichment")

# Regex patterns for IOC extraction
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_URL_RE = re.compile(r"https?://[^\s\"'>]+")

_HASH_FIELDS = [
    "FileHash", "SHA256", "SHA1", "MD5", "FileHashSha256", "FileHashSha1",
    "FileHashMd5", "InitiatingProcessSHA256", "InitiatingProcessSHA1",
]
_DOMAIN_FIELDS = [
    "DomainName", "DestinationHostName", "RemoteDnsCryptoLengthDomainName",
    "UrlDomain", "SenderMailFromDomain",
]
_URL_FIELDS = [
    "Url", "RemoteUrl", "FileOriginUrl", "ClickUrl",
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable public address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global
    except (ValueError, TypeError):
        return False


def extract_iocs(events_data: list[dict]) -> dict:
    """Extract unique IOCs from log event data (pure function, no I/O)."""
    ips = set()
    hashes = set()
    domains = set()
    urls = set()

    for event in events_data:
        # IPs from normalized fields
        for field in ("source_ip", "destination_ip"):
            val = event.get(field)
            if val and _is_public_ip(str(val)):
                ips.add(str(val))

        raw = event.get("raw_data") or {}

        # File hashes
        for field in _HASH_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and _HASH_RE.fullmatch(val):
                hashes.add(val.lower())

        # Domains
        for field in _DOMAIN_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and "." in val:
                domains.add(val.lower())

        # URLs
        for field in _URL_FIELDS:
            val = raw.get(field)
            if val and isinstance(val, str) and val.startswith("http"):
                urls.add(val)

    return {
        "ips": sorted(ips),
        "file_hashes": sorted(hashes),
        "domains": sorted(domains),
        "urls": sorted(urls),
    }


async def enrich_iocs(db: AsyncSession, iocs: dict, max_per_type: int = 4) -> dict:
    """Query threat intel platforms for extracted IOCs. Gracefully skips if not configured."""
    results = {
        "ip_results": [],
        "hash_results": [],
        "domain_results": [],
        "url_results": [],
        "enrichment_sources": [],
    }

    # Try to get VirusTotal client
    vt_client = None
    try:
        vt_client = await get_integration_client_by_platform(db, "virustotal")
        results["enrichment_sources"].append("virustotal")
    except NotFoundError:
        logger.debug("VirusTotal not configured, skipping VT enrichment")

    # Try to get AbuseIPDB client
    abuse_client = None
    try:
        abuse_client = await get_integration_client_by_platform(db, "abuseipdb")
        results["enrichment_sources"].append("abuseipdb")
    except NotFoundError:
        logger.debug("AbuseIPDB not configured, skipping AbuseIPDB enrichment")

    if not vt_client and not abuse_client:
        return results

    # Enrich IPs
    for ip in iocs["ips"][:max_per_type]:
        entry = {"ip": ip}
        if vt_client:
            try:
                entry["virustotal"] = await vt_client.lookup_ip(ip)
            except Exception as e:
                logger.warning("VT IP lookup failed for %s: %s", ip, e)
        if abuse_client:
            try:
                entry["abuseipdb"] = await abuse_client.check_ip(ip)
            except Exception as e:
                logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
        results["ip_results"].append(entry)

    # Enrich file hashes
    if vt_client:
        for h in iocs["file_hashes"][:max_per_type]:
            try:
                vt_result = await vt_client.lookup_hash(h)
                results["hash_results"].append({"hash": h, "virustotal": vt_result})
            except Exception as e:
                logger.warning("VT hash lookup failed for %s: %s", h, e)

    # Enrich domains
    if vt_client:
        for d in iocs["domains"][:max_per_type]:
            try:
                vt_result = await vt_client.lookup_domain(d)
                results["domain_results"].append({"domain": d, "virustotal": vt_result})
            except Exception as e:
                logger.warning("VT domain lookup failed for %s: %s", d, e)

    # Enrich URLs
    if vt_client:
        for u in iocs["urls"][:max_per_type]:
            try:
                vt_result = await vt_client.lookup_url(u)
                results["url_results"].append({"url": u, "virustotal": vt_result})
            except Exception as e:
                logger.warning("VT URL lookup failed for %s: %s", u, e)

    # Clean up clients
    if vt_client:
        await vt_client.close()
    if abuse_client:
        await abuse_client.close()

    total = sum(len(results[k]) for k in ["ip_results", "hash_results", "domain_results", "url_results"])
    logger.info("Enrichment complete: %d IOCs queried across %s", total, results["enrichment_sources"])

    return results
