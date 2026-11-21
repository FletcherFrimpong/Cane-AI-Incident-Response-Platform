"""
Change feed: tells browsers, notifiers and ticket sync that something happened.

It hangs off the database session rather than off individual endpoints. Every
significant thing the platform does to an incident is written to that incident's
timeline, so new timeline rows are the single source of "what just happened":

    flush   -> remember the new timeline rows (and touched incidents) on the session
    commit  -> publish a live update to Redis for open browsers (SSE), and queue the
               follow-up work (notifications, ticket sync) on Celery

Nothing is announced for work that rolled back, and code paths that forget to
announce themselves cannot exist: API requests and Celery tasks are covered alike.
"""

import asyncio
import json
import logging

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.action import ActionLog
from app.models.incident import Incident, IncidentTimeline

logger = logging.getLogger("cane_ai.events")

CHANNEL = "cane:events"

# Timeline event types that trigger follow-up work outside the request
FOLLOW_UP_EVENTS = {
    "incident_created", "auto_triage", "ai_analysis", "ai_analysis_failed", "action_proposed",
    "escalation", "incident_closed", "analyst_note", "severity_raised",
}

_background: set[asyncio.Task] = set()
_redis = None


def _client():
    global _redis
    if _redis is None:
        import redis.asyncio as aioredis

        _redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis


async def publish(message: dict) -> None:
    """Send a live update to every connected browser. Never raises."""
    try:
        await _client().publish(CHANNEL, json.dumps(message, default=str))
    except Exception as e:  # noqa: BLE001 - live updates are best-effort; the UI also polls
        logger.debug("Could not publish live update: %s", e)


def _queue_follow_ups(items: list[dict]) -> None:
    from app.workers.followup_tasks import handle_timeline_event

    for item in items:
        handle_timeline_event.delay(item["incident_id"], item["event_type"], item.get("extra") or {})


async def _announce(incident_ids: set[str], action_changed: bool, follow_ups: list[dict]) -> None:
    for incident_id in incident_ids:
        await publish({"type": "incident", "incident_id": incident_id})
    if action_changed:
        await publish({"type": "actions"})
    if follow_ups:
        try:
            await asyncio.to_thread(_queue_follow_ups, follow_ups)  # Celery client is blocking
        except Exception as e:  # noqa: BLE001 - a broker outage must not surface to the user
            logger.error("Could not queue follow-up work: %s", e)


@event.listens_for(Session, "after_flush")
def _collect(session: Session, flush_context) -> None:
    pending = session.info.setdefault("cane_pending", {"incidents": set(), "actions": False, "follow_ups": []})
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, Incident) and obj.id:
            pending["incidents"].add(str(obj.id))
        elif isinstance(obj, ActionLog):
            pending["actions"] = True
            pending["incidents"].add(str(obj.incident_id))
    for obj in session.new:
        if isinstance(obj, IncidentTimeline):
            pending["incidents"].add(str(obj.incident_id))
            if obj.event_type in FOLLOW_UP_EVENTS:
                pending["follow_ups"].append({
                    "incident_id": str(obj.incident_id),
                    "event_type": obj.event_type,
                    "extra": {**(obj.extra_data or {}), "description": obj.description[:1000], "actor": obj.actor},
                })


@event.listens_for(Session, "after_rollback")
def _discard(session: Session) -> None:
    session.info.pop("cane_pending", None)


@event.listens_for(Session, "after_commit")
def _announce_after_commit(session: Session) -> None:
    pending = session.info.pop("cane_pending", None)
    if not pending or not (pending["incidents"] or pending["actions"] or pending["follow_ups"]):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # synchronous use (e.g. a migration script): nothing to announce to
    task = loop.create_task(_announce(pending["incidents"], pending["actions"], pending["follow_ups"]))
    _background.add(task)
    task.add_done_callback(_background.discard)


async def drain() -> None:
    """Wait for announcements still in flight. Call before a short-lived event loop
    closes (Celery tasks, scripts), or their last updates are lost."""
    if _background:
        await asyncio.gather(*list(_background), return_exceptions=True)
    global _redis
    if _redis is not None:
        try:
            await _redis.aclose()
        except Exception:  # noqa: BLE001
            pass
        _redis = None
