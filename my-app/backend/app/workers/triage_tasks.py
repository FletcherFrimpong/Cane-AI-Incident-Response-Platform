"""Celery tasks for automated incident triage."""

import asyncio
import logging
import uuid

from app.database import task_session_factory
from app.workers.celery_app import celery_app

logger = logging.getLogger("cane_ai.workers.triage")

# The provider rejected the request itself (bad key, no credit, bad model name).
# Retrying will not help; a person needs to know.
_PERMANENT_STATUS = (400, 401, 403, 404)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def auto_triage_incident_task(self, incident_id: str):
    """Background task: automatically triage a newly created incident."""
    logger.info("Auto-triage task started for incident %s", incident_id)
    try:
        asyncio.run(_run_auto_triage(incident_id))
    except Exception as e:  # noqa: BLE001 - provider SDKs raise their own error types
        permanent = getattr(e, "status_code", None) in _PERMANENT_STATUS
        if permanent or self.request.retries >= self.max_retries:
            logger.error("Auto-triage gave up on incident %s: %s", incident_id, e)
            asyncio.run(_record_error(incident_id, _describe(e)))
            return
        logger.warning("Auto-triage failed for incident %s (will retry): %s", incident_id, e)
        raise self.retry(exc=e)


def _describe(error: Exception) -> str:
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        message = (body.get("error") or {}).get("message") if isinstance(body.get("error"), dict) else None
        if message:
            return f"LLM provider error: {message}"
    return f"LLM provider error: {type(error).__name__}: {error}"


async def _run_auto_triage(incident_id: str):
    from app.services.triage_service import auto_triage_incident

    engine, session_factory = task_session_factory()
    try:
        async with session_factory() as session:
            try:
                # The service commits its own progress (analysis first, then each
                # action) so a late failure never erases a record of what already ran.
                result = await auto_triage_incident(session, uuid.UUID(incident_id))
                await session.commit()
                logger.info("Auto-triage %s for incident %s",
                            "completed" if result else "skipped", incident_id)
            except Exception:
                await session.rollback()
                raise
    finally:
        from app.services import events
        await events.drain()
        await engine.dispose()


async def _record_error(incident_id: str, reason: str):
    from app.services.triage_service import record_triage_error

    engine, session_factory = task_session_factory()
    try:
        async with session_factory() as session:
            await record_triage_error(session, uuid.UUID(incident_id), reason)
            await session.commit()
    finally:
        from app.services import events
        await events.drain()
        await engine.dispose()
