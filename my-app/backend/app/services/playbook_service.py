"""
Playbook service: manages playbook execution, step progression, and matching.
"""

import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook import Playbook, PlaybookStep, StepType, PlaybookPhase
from app.models.incident import Incident, IncidentTimeline, IncidentStatus
from app.exceptions import NotFoundError, ValidationError

import uuid

logger = logging.getLogger("cane_ai.playbook")


async def get_playbook_with_steps(db: AsyncSession, playbook_id: uuid.UUID) -> Playbook:
    """Get a playbook with all its steps loaded."""
    result = await db.execute(
        select(Playbook).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise NotFoundError("Playbook not found")
    # Load steps
    await db.execute(
        select(PlaybookStep)
        .where(PlaybookStep.playbook_id == playbook_id)
        .order_by(PlaybookStep.step_order)
    )
    return playbook


async def match_playbook(db: AsyncSession, attack_type: str | None, severity: str | None = None) -> Playbook | None:
    """Find the best matching playbook for an incident."""
    if not attack_type:
        return None

    # Try exact attack type match
    result = await db.execute(
        select(Playbook).where(
            Playbook.is_active == True,
            Playbook.attack_types.contains([attack_type]),
        )
    )
    playbook = result.scalar_one_or_none()
    if playbook:
        return playbook

    # Try partial match
    result = await db.execute(
        select(Playbook).where(Playbook.is_active == True)
    )
    all_playbooks = result.scalars().all()
    for pb in all_playbooks:
        if pb.attack_types:
            for at in pb.attack_types:
                if attack_type.lower() in at.lower() or at.lower() in attack_type.lower():
                    return pb

    return None


async def attach_playbook_to_incident(
    db: AsyncSession,
    incident_id: uuid.UUID,
    playbook_id: uuid.UUID,
    actor: str = "system",
) -> Incident:
    """Attach a playbook to an incident and start execution."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise NotFoundError("Playbook not found")

    incident.playbook_id = playbook_id
    incident.current_playbook_step = 0

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="playbook_attached",
        actor=actor,
        description=f"Playbook '{playbook.name}' attached to incident",
        extra_data={"playbook_id": str(playbook_id), "playbook_name": playbook.name},
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


async def get_current_step(db: AsyncSession, incident_id: uuid.UUID) -> PlaybookStep | None:
    """Get the current playbook step for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident or not incident.playbook_id or incident.current_playbook_step is None:
        return None

    result = await db.execute(
        select(PlaybookStep).where(
            PlaybookStep.playbook_id == incident.playbook_id,
            PlaybookStep.step_order == incident.current_playbook_step,
        )
    )
    return result.scalar_one_or_none()


async def advance_step(
    db: AsyncSession,
    incident_id: uuid.UUID,
    actor: str,
    decision: str | None = None,
) -> PlaybookStep | None:
    """Advance to the next playbook step."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident or not incident.playbook_id:
        raise NotFoundError("Incident has no playbook attached")

    current_step_num = incident.current_playbook_step or 0

    # Get all steps
    result = await db.execute(
        select(PlaybookStep)
        .where(PlaybookStep.playbook_id == incident.playbook_id)
        .order_by(PlaybookStep.step_order)
    )
    all_steps = result.scalars().all()

    # Find next step
    next_step = None
    for step in all_steps:
        if step.step_order > current_step_num:
            # Check conditions
            if step.conditions and not _evaluate_conditions(step.conditions, incident, decision):
                continue
            next_step = step
            break

    if next_step:
        incident.current_playbook_step = next_step.step_order

        # Update incident status based on phase
        phase_status_map = {
            PlaybookPhase.CONTAINMENT: IncidentStatus.CONTAINMENT,
            PlaybookPhase.ERADICATION: IncidentStatus.ERADICATION,
            PlaybookPhase.RECOVERY: IncidentStatus.RECOVERY,
        }
        if next_step.phase in phase_status_map:
            incident.status = phase_status_map[next_step.phase]

        timeline = IncidentTimeline(
            incident_id=incident.id,
            event_type="playbook_step_advanced",
            actor=actor,
            description=f"Advanced to step {next_step.step_order}: {next_step.title}",
            extra_data={
                "step_order": next_step.step_order,
                "step_type": next_step.step_type.value,
                "phase": next_step.phase.value,
                "decision": decision,
            },
            timestamp=datetime.now(timezone.utc),
        )
        db.add(timeline)
    else:
        # No more steps — playbook complete
        incident.current_playbook_step = None
        timeline = IncidentTimeline(
            incident_id=incident.id,
            event_type="playbook_completed",
            actor=actor,
            description="Playbook execution completed",
            timestamp=datetime.now(timezone.utc),
        )
        db.add(timeline)

    await db.flush()
    return next_step


def _evaluate_conditions(conditions: dict, incident: Incident, decision: str | None) -> bool:
    """Evaluate step conditions against incident state."""
    if "if_severity" in conditions:
        if incident.severity and incident.severity.value != conditions["if_severity"]:
            return False
    if "if_attack_type" in conditions:
        if incident.attack_type != conditions["if_attack_type"]:
            return False
    if "if_decision" in conditions:
        if decision != conditions["if_decision"]:
            return False
    return True
