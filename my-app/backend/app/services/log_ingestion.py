"""
Log ingestion service: processes log events through normalization and correlation.

Nothing here talks to the task queue. Each function reports which incidents it
opened; the caller commits and then queues auto-triage for them, so a worker can
never pick up an incident that is not in the database yet.
"""

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log_event import LogEvent
from app.services.correlation import create_standalone_incident, find_or_create_incident_for_correlation
from app.services.log_normalizer import normalize_log_event

logger = logging.getLogger("cane_ai.ingestion")


def _to_log_event(normalized: dict) -> LogEvent:
    return LogEvent(
        tenant_id=normalized["tenant_id"],
        time_generated=normalized["time_generated"],
        source_system=normalized["source_system"],
        log_type=normalized["log_type"],
        schema_id=normalized["schema_id"],
        correlation_id=normalized["correlation_id"],
        severity=normalized["severity"],
        summary=normalized["summary"],
        source_ip=normalized["source_ip"],
        destination_ip=normalized["destination_ip"],
        user_identity=normalized["user_identity"],
        host=normalized["host"],
        raw_data=normalized["raw_data"],
    )


def _split_envelope(event: Any) -> tuple[str, dict]:
    """Accept both `{schemaId, data}` envelopes and bare events carrying a Type field."""
    if not isinstance(event, dict):
        raise ValueError("Each event must be a JSON object")
    if "schemaId" in event and isinstance(event.get("data"), dict):
        return str(event["schemaId"]), event["data"]
    return str(event.get("Type", event.get("type", "unknown"))), event


async def ingest_single_event(
    db: AsyncSession,
    schema_id: str,
    data: dict[str, Any],
) -> tuple[LogEvent, list[str]]:
    """Ingest one event: normalize, store, correlate.

    Returns the stored event and the IDs of any incidents this call opened.
    Raises ValueError if the event cannot be normalized."""
    log_event = _to_log_event(normalize_log_event(schema_id, data))
    db.add(log_event)
    await db.flush()

    created: list[str] = []
    if log_event.correlation_id:
        incident, was_created = await find_or_create_incident_for_correlation(db, log_event.correlation_id)
        if incident:
            log_event.incident_id = incident.id
    else:
        incident = await create_standalone_incident(db, log_event)
        was_created = incident is not None
    if incident and was_created:
        created.append(str(incident.id))
    await db.flush()

    logger.info("Ingested %s event (id=%s, correlation=%s)", log_event.log_type, log_event.id, log_event.correlation_id)
    return log_event, created


async def ingest_batch(db: AsyncSession, events: list[Any]) -> dict:
    """Ingest a batch of events. A bad event is reported and skipped; it never
    takes the rest of the batch down with it."""
    results: dict = {
        "ingested": 0, "errors": 0, "incidents_created": 0,
        "incident_ids_created": [], "error_details": [],
    }

    stored: list[LogEvent] = []
    for i, event in enumerate(events):
        try:
            schema_id, data = _split_envelope(event)
            stored.append(_to_log_event(normalize_log_event(schema_id, data)))
        except ValueError as e:
            results["errors"] += 1
            if len(results["error_details"]) < 50:
                results["error_details"].append({"index": i, "error": str(e)})

    db.add_all(stored)
    await db.flush()
    results["ingested"] = len(stored)

    # Correlated groups: one lookup per distinct correlation ID.
    for cid in dict.fromkeys(e.correlation_id for e in stored if e.correlation_id):
        incident, created = await find_or_create_incident_for_correlation(db, cid)
        if incident:
            for e in stored:
                if e.correlation_id == cid:
                    e.incident_id = incident.id
            if created:
                results["incident_ids_created"].append(str(incident.id))

    # Serious events with no correlation ID each stand on their own.
    for e in stored:
        if not e.correlation_id:
            incident = await create_standalone_incident(db, e)
            if incident:
                results["incident_ids_created"].append(str(incident.id))

    results["incidents_created"] = len(results["incident_ids_created"])
    await db.flush()
    return results


async def ingest_json_file(db: AsyncSession, content: str | bytes) -> dict:
    """Ingest events from a JSON file (an array of events, or a single event)."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"File is not valid JSON: {e.msg} (line {e.lineno})")

    if isinstance(data, dict) and isinstance(data.get("events"), list):
        data = data["events"]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of events or a single event object")
    return await ingest_batch(db, data)
