"""Celery tasks for automated incident triage."""

import asyncio
import logging
from app.workers.celery_app import celery_app
from app.database import async_session_factory

logger = logging.getLogger("cane_ai.workers.triage")


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def auto_triage_incident_task(self, incident_id: str):
    """Background task: automatically triage a newly created incident."""
    logger.info("Auto-triage task started for incident %s", incident_id)
    try:
        asyncio.run(_run_auto_triage(incident_id))
    except Exception as e:
        logger.error("Auto-triage task failed for incident %s: %s", incident_id, e)
        raise self.retry(exc=e)


async def _run_auto_triage(incident_id: str):
    import uuid
    from app.services.triage_service import auto_triage_incident

    async with async_session_factory() as session:
        try:
            result = await auto_triage_incident(session, uuid.UUID(incident_id))
            await session.commit()
            if result:
                logger.info("Auto-triage completed for incident %s", incident_id)
            else:
                logger.info("Auto-triage skipped for incident %s", incident_id)
        except Exception as e:
            await session.rollback()
            logger.error("Auto-triage error for incident %s: %s", incident_id, e)
            raise
