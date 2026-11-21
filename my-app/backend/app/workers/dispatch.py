"""Hand work to Celery from the API process.

Call these only after the database transaction has committed: the worker opens its
own connection and must be able to see the rows it is asked to work on.
"""

import asyncio
import logging

from app.config import get_settings

logger = logging.getLogger("cane_ai.dispatch")


def auto_triage_configured() -> bool:
    from app.ai.provider_factory import system_provider_configured
    return bool(get_settings().auto_triage_enabled and system_provider_configured())


def _send(incident_ids: list[str], countdown: int) -> None:
    from app.workers.triage_tasks import auto_triage_incident_task

    for incident_id in incident_ids:
        auto_triage_incident_task.apply_async(args=[incident_id], countdown=countdown)


async def queue_auto_triage(incident_ids: list[str]) -> int:
    """Queue automated triage for newly opened incidents. Returns how many were queued.
    Never raises: a broker outage must not fail the ingestion that already committed."""
    # Queued even without an LLM: the task still enriches the incident for the analyst.
    if not incident_ids:
        return 0
    try:
        # The Celery client is blocking; keep it off the event loop.
        await asyncio.to_thread(_send, incident_ids, get_settings().auto_triage_delay_seconds)
        logger.info("Queued auto-triage for %d incident(s)", len(incident_ids))
        return len(incident_ids)
    except Exception as e:  # noqa: BLE001 - broker errors vary by transport
        logger.error("Could not queue auto-triage for %s: %s", incident_ids, e)
        return 0
