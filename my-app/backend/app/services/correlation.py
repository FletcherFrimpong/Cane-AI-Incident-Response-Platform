"""
Correlation engine: groups log events by CorrelationId and detects related events.
"""

from datetime import datetime, timedelta
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

import logging
from app.models.log_event import LogEvent
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimeline

logger = logging.getLogger("cane_ai.correlation")


SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _highest_severity(events: list[dict]) -> str:
    """Return the highest severity among events."""
    best = "info"
    for event in events:
        sev = event.get("severity", "info")
        if SEVERITY_PRIORITY.get(sev, 0) > SEVERITY_PRIORITY.get(best, 0):
            best = sev
    return best


def _detect_attack_type(events: list[dict]) -> str | None:
    """Detect attack type from correlated events."""
    indicators = {
        "ransomware": ["ransomware", "wcry", "encrypted", "ransom", "wannacry", "encryption"],
        "phishing": ["phishing", "credential harvesting", "spoofed", "suspicious email", "phish"],
        "data_exfiltration": ["exfiltration", "data transfer", "large transfer", "sqlcmd", "data volume"],
        "ddos": ["ddos", "denial of service", "flood", "volumetric"],
        "brute_force": ["brute force", "multiple failed", "failed logon", "password spray"],
        "malware": ["malware", "trojan", "virus", "payload", "backdoor", "c2", "command and control"],
        "lateral_movement": ["lateral movement", "pass the hash", "remote execution"],
        "unauthorized_access": ["unauthorized", "privilege escalation", "elevation"],
        "sql_injection": ["sql injection", "sqli", "union select"],
    }

    all_text = ""
    for event in events:
        raw = event.get("raw_data", {})
        all_text += " ".join(str(v).lower() for v in [
            event.get("summary", ""),
            raw.get("AlertName", ""),
            raw.get("DisplayName", ""),
            raw.get("Description", ""),
            raw.get("ThreatTypes", ""),
            raw.get("ThreatCategory", ""),
            raw.get("IndicatorThreatType", ""),
            raw.get("Activity", ""),
        ]) + " "

    for attack_type, keywords in indicators.items():
        for keyword in keywords:
            if keyword in all_text:
                return attack_type
    return None


async def find_or_create_incident_for_correlation(
    db: AsyncSession,
    correlation_id: str,
    normalized_events: list[dict],
) -> Incident | None:
    """Find existing incident for correlation_id, or create a new one."""
    if not correlation_id:
        return None

    # Check if incident already exists for this correlation_id
    result = await db.execute(
        select(Incident).where(Incident.correlation_id == correlation_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    # Create a new incident from correlated events
    severity_str = _highest_severity(normalized_events)
    attack_type = _detect_attack_type(normalized_events)
    try:
        severity = IncidentSeverity(severity_str)
    except ValueError:
        severity = IncidentSeverity.MEDIUM

    # Build title from the most informative event
    title = f"Correlated Incident: {correlation_id}"
    for event in normalized_events:
        if event.get("log_type") == "SecurityAlert":
            title = event.get("summary", title)
            break

    # Extract entities
    source_entities = {"ips": [], "hosts": [], "users": []}
    for event in normalized_events:
        if event.get("source_ip"):
            source_entities["ips"].append(event["source_ip"])
        if event.get("host"):
            source_entities["hosts"].append(event["host"])
        if event.get("user_identity"):
            source_entities["users"].append(event["user_identity"])
    # Deduplicate
    for key in source_entities:
        source_entities[key] = list(set(source_entities[key]))

    incident = Incident(
        tenant_id=normalized_events[0].get("tenant_id", "unknown") if normalized_events else "unknown",
        title=title,
        description=f"Auto-created from {len(normalized_events)} correlated log events",
        severity=severity,
        status=IncidentStatus.NEW,
        attack_type=attack_type,
        correlation_id=correlation_id,
        source_entities=source_entities,
    )
    db.add(incident)
    await db.flush()

    # Add timeline entry
    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        actor="system",
        description=f"Incident auto-created from {len(normalized_events)} correlated events (correlation_id: {correlation_id})",
        extra_data={"correlation_id": correlation_id, "event_count": len(normalized_events)},
        timestamp=datetime.utcnow(),
    )
    db.add(timeline)
    await db.flush()

    # Fire auto-triage in background
    try:
        from app.config import get_settings
        settings = get_settings()
        if settings.auto_triage_enabled and settings.auto_triage_api_key:
            from app.workers.triage_tasks import auto_triage_incident_task
            auto_triage_incident_task.delay(str(incident.id))
            logger.info("Auto-triage task queued for incident %s", incident.id)
    except Exception as e:
        logger.warning("Failed to queue auto-triage for incident %s: %s", incident.id, e)

    return incident


async def correlate_events_by_time_window(
    db: AsyncSession,
    source_ip: str | None,
    host: str | None,
    time_window_minutes: int = 30,
    reference_time: datetime | None = None,
) -> list[LogEvent]:
    """Find potentially related events within a time window based on common entities."""
    if not source_ip and not host:
        return []

    ref_time = reference_time or datetime.utcnow()
    start = ref_time - timedelta(minutes=time_window_minutes)
    end = ref_time + timedelta(minutes=time_window_minutes)

    conditions = [
        LogEvent.time_generated.between(start, end),
    ]
    if source_ip:
        conditions.append(LogEvent.source_ip == source_ip)
    if host:
        conditions.append(LogEvent.host == host)

    result = await db.execute(
        select(LogEvent).where(and_(*conditions)).order_by(LogEvent.time_generated)
    )
    return list(result.scalars().all())
