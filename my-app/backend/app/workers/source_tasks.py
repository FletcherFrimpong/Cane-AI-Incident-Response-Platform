"""Celery beat task: pull new events from connected log/alert sources
(Splunk, Elastic, AWS GuardDuty...) and run them through normal ingestion."""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from app.database import task_session_factory
from app.workers.celery_app import celery_app

logger = logging.getLogger("cane_ai.workers.sources")

FIRST_LOOKBACK = timedelta(minutes=15)
MAX_EVENTS_PER_POLL = 500
REMEMBERED_FINGERPRINTS = 2000


@celery_app.task(name="app.workers.source_tasks.poll_sources")
def poll_sources():
    asyncio.run(_run())


def _fingerprint(envelope: dict) -> str:
    return hashlib.sha256(json.dumps(envelope, sort_keys=True, default=str).encode()).hexdigest()[:24]


async def poll_one(session, integration, client) -> dict:
    """Fetch and ingest one source. Remembers where it got to and which events it has
    already taken, so an event that falls on a polling boundary is not ingested twice."""
    from sqlalchemy.orm.attributes import flag_modified

    from app.services.log_ingestion import ingest_batch

    state = dict(integration.state or {})
    now = datetime.now(timezone.utc)
    since = datetime.fromisoformat(state["cursor"]) if state.get("cursor") else now - FIRST_LOOKBACK
    seen = list(state.get("seen", []))
    seen_set = set(seen)

    envelopes = await client.fetch_events(since, MAX_EVENTS_PER_POLL)
    fresh = []
    for envelope in envelopes:
        fp = _fingerprint(envelope)
        if fp not in seen_set:
            seen_set.add(fp)
            seen.append(fp)
            fresh.append(envelope)

    result = {"ingested": 0, "incident_ids_created": [], "errors": 0}
    if fresh:
        result = await ingest_batch(session, fresh)

    # Advance to the newest event seen; with no events keep the cursor, so a source
    # that is briefly behind does not have a window skipped.
    newest = since
    for envelope in envelopes:
        stamp = (envelope.get("data") or {}).get("TimeGenerated")
        try:
            parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
            parsed = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            newest = max(newest, parsed)
        except (TypeError, ValueError):
            continue
    state.update({
        "cursor": newest.isoformat(), "seen": seen[-REMEMBERED_FINGERPRINTS:],
        "last_poll": now.isoformat(), "last_count": len(fresh), "last_error": None,
    })
    integration.state = state
    flag_modified(integration, "state")
    return result


async def _run():
    from sqlalchemy import select
    from sqlalchemy.orm.attributes import flag_modified

    from app.integrations.registry import get_integration_class
    from app.models.integration import PlatformIntegration
    from app.services import events
    from app.services.integration_service import _build_client
    from app.workers.dispatch import queue_auto_triage

    engine, session_factory = task_session_factory()
    try:
        async with session_factory() as session:
            rows = (await session.execute(
                select(PlatformIntegration).where(PlatformIntegration.is_active == True)
            )).scalars().all()
            for integration in rows:
                cls = get_integration_class(integration.platform)
                if cls is None or cls.category != "source":
                    continue
                client = None
                try:
                    client = _build_client(integration)
                    result = await poll_one(session, integration, client)
                    await session.commit()
                    if result["ingested"]:
                        logger.info("%s: %d events ingested, %d incidents opened", integration.display_name,
                                    result["ingested"], len(result["incident_ids_created"]))
                    await queue_auto_triage(result["incident_ids_created"])
                except Exception as e:  # noqa: BLE001 - one failing source must not stop the others
                    await session.rollback()
                    logger.error("Polling %s failed: %s", integration.display_name, e)
                    state = dict(integration.state or {})
                    state["last_error"] = str(e)[:300]
                    integration.state = state
                    flag_modified(integration, "state")
                    await session.commit()
                finally:
                    if client is not None:
                        await client.close()
    finally:
        await events.drain()
        await engine.dispose()
