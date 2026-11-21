"""Celery beat task: periodic health check of every active integration."""

import asyncio
import logging

from app.database import task_session_factory
from app.workers.celery_app import celery_app

logger = logging.getLogger("cane_ai.workers.health")


@celery_app.task(name="app.workers.health_checks.check_integration_health")
def check_integration_health():
    asyncio.run(_run())


async def _run():
    from app.services.integration_service import check_all_integration_health

    engine, session_factory = task_session_factory()
    try:
        async with session_factory() as session:
            checked = await check_all_integration_health(session)
            await session.commit()
            logger.info("Integration health check complete (%s integrations)", checked)
    finally:
        from app.services import events
        await events.drain()
        await engine.dispose()
