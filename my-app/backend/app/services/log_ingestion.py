"""
Log ingestion service: processes log events through normalization and correlation.
"""

import json
import logging
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log_event import LogEvent
from app.services.log_normalizer import normalize_log_event
from app.services.correlation import find_or_create_incident_for_correlation

logger = logging.getLogger("cane_ai.ingestion")


async def ingest_single_event(
    db: AsyncSession,
    schema_id: str,
    data: dict[str, Any],
) -> LogEvent:
    """Ingest a single log event: normalize, store, and correlate."""
    normalized = normalize_log_event(schema_id, data)

    log_event = LogEvent(
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
    db.add(log_event)
    await db.flush()

    # Correlate if correlation_id exists
    if normalized["correlation_id"]:
        incident = await find_or_create_incident_for_correlation(
            db, normalized["correlation_id"], [normalized]
        )
        if incident:
            log_event.incident_id = incident.id
            await db.flush()

    logger.info("Ingested %s event (id=%s, correlation=%s)", normalized["log_type"], log_event.id, normalized["correlation_id"])
    return log_event


async def ingest_batch(
    db: AsyncSession,
    events: list[dict[str, Any]],
) -> dict:
    """Ingest a batch of log events."""
    results = {"ingested": 0, "errors": 0, "incidents_created": 0, "error_details": []}
    correlation_groups: dict[str, list[dict]] = {}

    # First pass: normalize all events and group by correlation_id
    normalized_events = []
    for i, event in enumerate(events):
        try:
            schema_id = event.get("schemaId", "")
            data = event.get("data", event)

            # If the event doesn't have the envelope format, try to detect schema
            if not schema_id and "data" not in event:
                schema_id = event.get("Type", event.get("type", "unknown")).lower()
                data = event

            normalized = normalize_log_event(schema_id, data)
            normalized_events.append(normalized)

            if normalized["correlation_id"]:
                cid = normalized["correlation_id"]
                if cid not in correlation_groups:
                    correlation_groups[cid] = []
                correlation_groups[cid].append(normalized)

        except Exception as e:
            results["errors"] += 1
            results["error_details"].append({"index": i, "error": str(e)})
            logger.error("Error normalizing event %d: %s", i, e)

    # Second pass: create incidents for correlation groups
    incidents_map: dict[str, any] = {}
    for cid, group in correlation_groups.items():
        try:
            incident = await find_or_create_incident_for_correlation(db, cid, group)
            if incident:
                incidents_map[cid] = incident
                results["incidents_created"] += 1
        except Exception as e:
            logger.error("Error creating incident for correlation %s: %s", cid, e)

    # Third pass: store all normalized events
    for normalized in normalized_events:
        try:
            log_event = LogEvent(
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

            # Link to incident if correlation exists
            cid = normalized.get("correlation_id")
            if cid and cid in incidents_map:
                log_event.incident_id = incidents_map[cid].id

            db.add(log_event)
            results["ingested"] += 1
        except Exception as e:
            results["errors"] += 1
            logger.error("Error storing event: %s", e)

    await db.flush()
    return results


async def ingest_json_file(db: AsyncSession, content: str | bytes) -> dict:
    """Ingest events from a JSON file (array of events or single event)."""
    if isinstance(content, bytes):
        content = content.decode("utf-8")

    data = json.loads(content)

    if isinstance(data, list):
        return await ingest_batch(db, data)
    elif isinstance(data, dict):
        if "schemaId" in data:
            event = await ingest_single_event(db, data["schemaId"], data.get("data", data))
            return {"ingested": 1, "errors": 0, "incidents_created": 0, "event_id": str(event.id)}
        else:
            event = await ingest_single_event(db, data.get("Type", "unknown").lower(), data)
            return {"ingested": 1, "errors": 0, "incidents_created": 0, "event_id": str(event.id)}
    else:
        return {"ingested": 0, "errors": 1, "error_details": [{"error": "Invalid JSON format"}]}
