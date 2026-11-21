"""Celery tasks: notifications and ticket sync, driven by incident timeline events."""

import asyncio
import logging
import uuid

from app.database import task_session_factory
from app.workers.celery_app import celery_app

logger = logging.getLogger("cane_ai.workers.followup")


@celery_app.task(name="app.workers.followup_tasks.handle_timeline_event", max_retries=0)
def handle_timeline_event(incident_id: str, event_type: str, extra: dict):
    asyncio.run(_run(incident_id, event_type, extra))


async def _run(incident_id: str, event_type: str, extra: dict):
    from app.services import events
    from app.services.followup_service import handle_timeline_event as handle

    engine, session_factory = task_session_factory()
    try:
        async with session_factory() as session:
            try:
                await handle(session, uuid.UUID(incident_id), event_type, extra)
                await session.commit()
            except Exception as e:  # noqa: BLE001
                await session.rollback()
                logger.error("Follow-up for %s (%s) failed: %s", incident_id, event_type, e)
    finally:
        await events.drain()
        await engine.dispose()
