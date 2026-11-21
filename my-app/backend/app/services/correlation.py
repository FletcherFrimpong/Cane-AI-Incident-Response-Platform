"""
Correlation engine: groups log events into incidents.

Events that share a CorrelationId belong to one incident. A group only becomes an
incident once it is worth an analyst's attention (see `should_open_incident`);
quieter events stay as searchable logs and are pulled in if the group escalates later.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimeline
from app.models.log_event import LogEvent

logger = logging.getLogger("cane_ai.correlation")

SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# How many events of a group are examined when deciding severity / attack type.
_GROUP_SAMPLE_LIMIT = 500

ATTACK_INDICATORS = {
    "ransomware": ["ransomware", "wcry", "encrypted", "ransom", "wannacry", "encryption"],
    "phishing": ["phishing", "credential harvesting", "spoofed", "suspicious email", "phish"],
    "data_exfiltration": ["exfiltration", "data transfer", "large transfer", "sqlcmd", "data volume"],
    "ddos": ["ddos", "denial of service", "flood", "volumetric"],
    "brute_force": ["brute force", "multiple failed", "failed logon", "password spray"],
    "malware": ["malware", "trojan", "virus", "payload", "backdoor", "command and control"],
    "lateral_movement": ["lateral movement", "pass the hash", "remote execution"],
    "unauthorized_access": ["unauthorized", "privilege escalation", "elevation"],
    "sql_injection": ["sql injection", "sqli", "union select"],
}


def severity_rank(severity: str | None) -> int:
    return SEVERITY_PRIORITY.get(str(severity or "").lower(), 0)


def _highest_severity(events: list[dict]) -> str:
    """Return the highest severity among events."""
    best = "info"
    for event in events:
        sev = event.get("severity", "info")
        if severity_rank(sev) > severity_rank(best):
            best = sev
    return best


def _detect_attack_type(events: list[dict]) -> str | None:
    """Detect attack type from correlated events by keyword."""
    parts = []
    for event in events:
        raw = event.get("raw_data") or {}
        parts.extend(str(v).lower() for v in [
            event.get("summary", ""),
            raw.get("AlertName", ""),
            raw.get("DisplayName", ""),
            raw.get("Description", ""),
            raw.get("ThreatTypes", ""),
            raw.get("ThreatCategory", ""),
            raw.get("IndicatorThreatType", ""),
            raw.get("Activity", ""),
        ] if v)
    all_text = " ".join(parts)

    for attack_type, keywords in ATTACK_INDICATORS.items():
        if any(keyword in all_text for keyword in keywords):
            return attack_type
    return None


def should_open_incident(events: list[dict], min_severity: str) -> bool:
    """Decide whether a group of events deserves an incident.

    Yes when the worst event reaches `min_severity`, when a security product already
    raised an alert, or when a known attack pattern is recognised. Otherwise the
    events are just logs: opening an incident (and spending an LLM call) on every
    informational sign-in buries the real ones.
    """
    if not events:
        return False
    if severity_rank(_highest_severity(events)) >= severity_rank(min_severity):
        return True
    if any(e.get("log_type") == "SecurityAlert" for e in events):
        return True
    return _detect_attack_type(events) is not None


def _entities(events: list[dict]) -> dict:
    ips, hosts, users = set(), set(), set()
    for event in events:
        if event.get("source_ip"):
            ips.add(str(event["source_ip"]))
        if event.get("host"):
            hosts.add(event["host"])
        if event.get("user_identity"):
            users.add(event["user_identity"])
    return {"ips": sorted(ips), "hosts": sorted(hosts), "users": sorted(users)}


def _event_to_dict(event: LogEvent) -> dict:
    return {
        "tenant_id": event.tenant_id,
        "log_type": event.log_type,
        "severity": event.severity,
        "summary": event.summary,
        "source_ip": str(event.source_ip) if event.source_ip else None,
        "host": event.host,
        "user_identity": event.user_identity,
        "raw_data": event.raw_data or {},
    }


def _title_for(events: list[dict], fallback: str) -> str:
    for event in events:
        if event.get("log_type") == "SecurityAlert" and event.get("summary"):
            return str(event["summary"])[:500]
    worst = max(events, key=lambda e: severity_rank(e.get("severity")), default=None)
    if worst and worst.get("summary"):
        return str(worst["summary"])[:500]
    return fallback[:500]


def _to_severity(value: str) -> IncidentSeverity:
    try:
        return IncidentSeverity(value)
    except ValueError:
        return IncidentSeverity.MEDIUM


async def find_or_create_incident_for_correlation(
    db: AsyncSession,
    correlation_id: str,
) -> tuple[Incident | None, bool]:
    """Find the incident for a correlation ID, or open one if the group warrants it.

    Works from the events already stored (and flushed) for that correlation ID, so
    call it after adding the new events. Returns (incident, created).
    The caller queues auto-triage for created incidents *after* committing.
    """
    if not correlation_id:
        return None, False

    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.correlation_id == correlation_id)
        .order_by(LogEvent.time_generated.asc())
        .limit(_GROUP_SAMPLE_LIMIT)
    )
    events = [_event_to_dict(e) for e in result.scalars().all()]
    if not events:
        return None, False

    result = await db.execute(
        select(Incident)
        .where(Incident.correlation_id == correlation_id)
        .order_by(Incident.created_at.asc())
        .limit(1)
    )
    incident = result.scalars().first()
    created = False

    if incident is None:
        if not should_open_incident(events, get_settings().incident_min_severity):
            return None, False

        incident = Incident(
            tenant_id=events[0].get("tenant_id") or "unknown",
            title=_title_for(events, f"Correlated incident: {correlation_id}"),
            description=f"Auto-created from {len(events)} correlated log events",
            severity=_to_severity(_highest_severity(events)),
            status=IncidentStatus.NEW,
            attack_type=_detect_attack_type(events),
            correlation_id=correlation_id,
            source_entities=_entities(events),
        )
        try:
            # Savepoint: if another request opened the incident for this correlation ID
            # a moment ago, the unique index rejects ours and we join theirs instead.
            async with db.begin_nested():
                db.add(incident)
                await db.flush()
        except IntegrityError:
            result = await db.execute(select(Incident).where(Incident.correlation_id == correlation_id).limit(1))
            incident = result.scalars().first()
            if incident is None:
                raise
            await db.execute(
                update(LogEvent)
                .where(LogEvent.correlation_id == correlation_id, LogEvent.incident_id.is_(None))
                .values(incident_id=incident.id)
                .execution_options(synchronize_session=False)
            )
            await db.flush()
            return incident, False
        db.add(IncidentTimeline(
            incident_id=incident.id,
            event_type="incident_created",
            actor="system",
            description=f"Incident auto-created from {len(events)} correlated events (correlation_id: {correlation_id})",
            extra_data={"correlation_id": correlation_id, "event_count": len(events)},
            timestamp=datetime.now(timezone.utc),
        ))
        created = True
    else:
        # New evidence on an open incident: keep its picture current.
        worst = _highest_severity(events)
        if incident.resolved_at is None and severity_rank(worst) > severity_rank(incident.severity.value):
            previous = incident.severity.value
            incident.severity = _to_severity(worst)
            db.add(IncidentTimeline(
                incident_id=incident.id,
                event_type="severity_raised",
                actor="system",
                description=f"Severity raised from {previous} to {worst} by newly correlated events",
                extra_data={"from": previous, "to": worst},
                timestamp=datetime.now(timezone.utc),
            ))
        incident.source_entities = _entities(events)
        if not incident.attack_type:
            incident.attack_type = _detect_attack_type(events)

    # Link every event of the group, including quiet ones stored before it escalated.
    await db.execute(
        update(LogEvent)
        .where(LogEvent.correlation_id == correlation_id, LogEvent.incident_id.is_(None))
        .values(incident_id=incident.id)
        .execution_options(synchronize_session=False)
    )
    await db.flush()
    return incident, created


async def create_standalone_incident(db: AsyncSession, event: LogEvent) -> Incident | None:
    """Open an incident for a serious event that carries no correlation ID
    (e.g. a lone Defender alert). Returns None if it is below the threshold."""
    data = _event_to_dict(event)
    is_alert = event.log_type == "SecurityAlert"
    threshold = get_settings().incident_min_severity_uncorrelated
    if not is_alert and severity_rank(event.severity) < severity_rank(threshold):
        return None
    if is_alert and severity_rank(event.severity) < severity_rank(get_settings().incident_min_severity):
        return None

    incident = Incident(
        tenant_id=event.tenant_id or "unknown",
        title=_title_for([data], f"{event.log_type} event"),
        description="Auto-created from a single uncorrelated log event",
        severity=_to_severity(event.severity),
        status=IncidentStatus.NEW,
        attack_type=_detect_attack_type([data]),
        correlation_id=None,
        source_entities=_entities([data]),
    )
    db.add(incident)
    await db.flush()
    event.incident_id = incident.id
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        actor="system",
        description=f"Incident auto-created from an uncorrelated {event.severity} {event.log_type} event",
        extra_data={"event_count": 1},
        timestamp=datetime.now(timezone.utc),
    ))
    await db.flush()
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

    ref_time = reference_time or datetime.now(timezone.utc)
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
