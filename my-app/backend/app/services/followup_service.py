"""
Follow-up work after something happens on an incident: tell people (chat, paging,
webhooks) and keep external tickets in step. Runs in Celery, driven by the
incident timeline (see app.services.events).
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.config import get_settings
from app.integrations.base_client import NotificationEvent
from app.models.action import ActionLog
from app.models.incident import Incident, IncidentTimeline
from app.models.triage import AiAnalysis
from app.services.correlation import severity_rank
from app.services.integration_service import active_clients, close_clients

logger = logging.getLogger("cane_ai.followup")

_OPENING_EVENTS = {"incident_created", "auto_triage", "ai_analysis", "severity_raised"}


def incident_url(incident_id) -> str:
    return f"{get_settings().public_url.rstrip('/')}/incidents/{incident_id}"


def _refs(incident: Incident) -> dict:
    refs = dict(incident.external_refs or {})
    refs.setdefault("tickets", {})
    return refs


def _save_refs(incident: Incident, refs: dict) -> None:
    incident.external_refs = refs
    flag_modified(incident, "external_refs")


def _base_fields(incident: Incident) -> dict[str, str]:
    fields = {"Severity": incident.severity.value.capitalize(), "Status": incident.status.value.replace("_", " ")}
    if incident.attack_type:
        fields["Attack type"] = incident.attack_type.replace("_", " ")
    entities = incident.source_entities or {}
    if entities.get("hosts"):
        fields["Hosts"] = ", ".join(entities["hosts"][:3])
    if entities.get("users"):
        fields["Accounts"] = ", ".join(entities["users"][:3])
    return fields


async def _latest_summary(db: AsyncSession, incident: Incident) -> str | None:
    analysis = (await db.execute(
        select(AiAnalysis)
        .where(AiAnalysis.incident_id == incident.id, AiAnalysis.analysis_type.in_(["triage", "auto_triage"]))
        .order_by(AiAnalysis.created_at.desc()).limit(1)
    )).scalars().first()
    return (analysis.output or {}).get("summary") if analysis else None


async def _build_notification(db: AsyncSession, incident: Incident, event_type: str, extra: dict,
                              refs: dict) -> NotificationEvent | None:
    """Decide whether this timeline event is worth interrupting someone for."""
    settings = get_settings()
    serious = severity_rank(incident.severity.value) >= severity_rank(settings.notify_min_severity)
    sev = incident.severity.value
    common = dict(severity=sev, incident_id=str(incident.id), incident_url=incident_url(incident.id))

    if event_type in _OPENING_EVENTS:
        # Announce an incident once, when it first reaches the notify threshold. That may
        # be at creation, or later when triage or new evidence raises its severity.
        if not serious or refs.get("notified"):
            return None
        refs["notified"] = True
        summary = await _latest_summary(db, incident) or incident.description or "New incident."
        return NotificationEvent(kind="incident_opened", title=f"{sev.capitalize()} incident: {incident.title}",
                                 summary=summary, fields=_base_fields(incident), **common)

    if event_type == "ai_analysis_failed":
        if not serious:
            return None
        return NotificationEvent(kind="triage_failed", title=f"AI triage failed: {incident.title}",
                                 summary=extra.get("description") or "AI triage could not complete. Manual review required.",
                                 fields=_base_fields(incident), **common)

    if event_type == "action_proposed":
        action_id = extra.get("action_id")
        action = None
        if action_id:
            action = (await db.execute(select(ActionLog).where(ActionLog.id == uuid.UUID(action_id)))).scalar_one_or_none()
        if not action:
            return None
        target = next(iter((action.action_params or {}).values()), "")
        fields = {"Action": action.action_type.replace("_", " "), "Target": str(target), **_base_fields(incident)}
        return NotificationEvent(kind="action_pending",
                                 title=f"Approval needed: {action.action_type.replace('_', ' ')} on {target}",
                                 summary=f"Proposed for incident \"{incident.title}\". Nothing runs until an analyst approves.",
                                 fields=fields, action_id=str(action.id), **common)

    if event_type == "escalation":
        return NotificationEvent(kind="incident_escalated", title=f"Escalated: {incident.title}",
                                 summary=extra.get("description") or "This incident was escalated.",
                                 fields=_base_fields(incident), **common)

    if event_type == "incident_closed":
        if not refs.get("notified"):
            return None  # never announced, so there is nothing to stand down
        return NotificationEvent(kind="incident_closed", title=f"Closed: {incident.title}",
                                 summary=extra.get("description") or "Incident closed.",
                                 fields=_base_fields(incident), **common)
    return None


async def _send_notifications(db: AsyncSession, event: NotificationEvent) -> None:
    clients = await active_clients(db, category="notification")
    try:
        for client in clients:
            try:
                reply = await client.notify(event)
                if isinstance(reply, dict) and reply.get("success") is False:
                    logger.warning("Notification via %s failed: %s", client.integration_name, reply.get("message"))
            except Exception as e:  # noqa: BLE001 - one broken notifier must not block the others
                logger.warning("Notification via %s raised: %s", client.integration_name, e)
    finally:
        await close_clients(clients)


async def _sync_tickets(db: AsyncSession, incident: Incident, event_type: str, extra: dict, refs: dict) -> None:
    settings = get_settings()
    clients = await active_clients(db, category="ticketing")
    if not clients:
        return
    tickets: dict = refs["tickets"]
    serious = severity_rank(incident.severity.value) >= severity_rank(settings.ticket_min_severity)
    try:
        for client in clients:
            key = str(client.integration_id)
            ticket = tickets.get(key)
            try:
                if ticket is None and event_type in _OPENING_EVENTS and serious:
                    reply = await client.create_ticket({
                        "id": str(incident.id), "title": incident.title,
                        "description": (await _latest_summary(db, incident)) or incident.description or "",
                        "severity": incident.severity.value, "status": incident.status.value,
                        "attack_type": incident.attack_type, "url": incident_url(incident.id),
                    })
                    if reply.get("success"):
                        tickets[key] = {
                            "platform": client.platform_name, "integration": client.integration_name,
                            "ticket_id": str(reply.get("ticket_id") or ""), "ticket_url": reply.get("ticket_url"),
                            "label": str(reply.get("ticket_key") or reply.get("ticket_number") or reply.get("ticket_id") or ""),
                            "dry_run": bool(reply.get("dry_run")), "closed": False,
                        }
                        db.add(IncidentTimeline(
                            incident_id=incident.id, event_type="ticket_created", actor="system",
                            description=(f"Ticket {tickets[key]['label']} opened in {client.integration_name}"
                                         + (" (dry run: nothing was created)" if reply.get("dry_run") else "")),
                            extra_data={"ticket": tickets[key]}, timestamp=datetime.now(timezone.utc),
                        ))
                    else:
                        logger.warning("Ticket creation in %s failed: %s", client.integration_name, reply.get("message"))
                elif ticket and not ticket.get("closed") and not ticket.get("dry_run"):
                    if event_type == "analyst_note":
                        await client.add_ticket_comment(ticket["ticket_id"], f"{extra.get('actor', 'analyst')}: {extra.get('description', '')}")
                    elif event_type == "incident_closed":
                        reply = await client.close_ticket(ticket["ticket_id"], extra.get("description") or "Closed in Cane AI")
                        if reply.get("success"):
                            ticket["closed"] = True
            except Exception as e:  # noqa: BLE001
                logger.warning("Ticket sync with %s raised: %s", client.integration_name, e)
    finally:
        await close_clients(clients)


async def handle_timeline_event(db: AsyncSession, incident_id: uuid.UUID, event_type: str, extra: dict) -> None:
    # Row lock: several events for one incident can be processed at once, and both
    # "already notified?" and "already has a ticket?" must be answered consistently.
    incident = (await db.execute(
        select(Incident).where(Incident.id == incident_id).with_for_update()
    )).scalar_one_or_none()
    if not incident:
        return
    refs = _refs(incident)

    notification = await _build_notification(db, incident, event_type, extra, refs)
    await _sync_tickets(db, incident, event_type, extra, refs)
    _save_refs(incident, refs)
    await db.commit()  # record "notified" / ticket refs before sending, so a retry cannot double-send

    if notification:
        await _send_notifications(db, notification)
