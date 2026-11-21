"""
Playbook service: manages playbook execution, step progression, and matching.
"""

import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.playbook import Playbook, PlaybookFramework, PlaybookStep, StepType, PlaybookPhase
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
    """Find the best matching active playbook for an attack type.
    Built-in playbooks win ties, then the oldest, so the choice is stable."""
    if not attack_type:
        return None
    wanted = attack_type.strip().lower().replace(" ", "_")

    result = await db.execute(
        select(Playbook).where(Playbook.is_active == True)
        .order_by(Playbook.is_builtin.desc(), Playbook.created_at.asc())
    )
    playbooks = result.scalars().all()

    for pb in playbooks:
        if wanted in [a.lower() for a in (pb.attack_types or [])]:
            return pb
    for pb in playbooks:
        for at in pb.attack_types or []:
            if wanted in at.lower() or at.lower() in wanted:
                return pb
    return None


async def first_step_order(db: AsyncSession, playbook_id: uuid.UUID) -> int | None:
    """The step_order of a playbook's first step (None if it has no steps)."""
    result = await db.execute(
        select(PlaybookStep.step_order)
        .where(PlaybookStep.playbook_id == playbook_id)
        .order_by(PlaybookStep.step_order.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def seed_builtin_playbooks(db: AsyncSession) -> int:
    """Load the built-in NIST 800-61 playbooks that are not in the database yet.
    Idempotent: safe to call on every startup. Returns how many were added."""
    from app.data.seed_playbooks import get_seed_playbooks

    existing = set((await db.execute(select(Playbook.name).where(Playbook.is_builtin == True))).scalars().all())
    added = 0
    for spec in get_seed_playbooks():
        if spec["name"] in existing:
            continue
        steps = spec.get("steps", [])
        playbook = Playbook(
            name=spec["name"],
            description=spec.get("description"),
            framework=PlaybookFramework(spec.get("framework", "nist_800_61")),
            attack_types=spec.get("attack_types"),
            is_builtin=True,
            is_active=True,
        )
        db.add(playbook)
        await db.flush()
        for step in steps:
            db.add(PlaybookStep(
                playbook_id=playbook.id,
                **{**step, "phase": PlaybookPhase(step["phase"]), "step_type": StepType(step["step_type"])},
            ))
        added += 1
    await db.flush()
    return added


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
    incident.current_playbook_step = await first_step_order(db, playbook_id)

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
        ).limit(1)
    )
    return result.scalars().first()


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


# --------------------------------------------------------------------------------
# Automated steps
#
# A step of type "automated" names a response action (isolate_host, block_ip, ...).
# When an incident arrives at such a step, the engine proposes that action for each
# matching entity in the incident's own evidence. The proposals go through the same
# approval queue as AI recommendations: a playbook is a plan, not a permission.
# The only actions that run without a person are ones the step does not mark
# "requires approval" AND that are on the platform's auto-execute allow-list.
# --------------------------------------------------------------------------------

async def run_current_step(db: AsyncSession, incident_id: uuid.UUID, actor: str = "system") -> list:
    """If the incident's current playbook step is automated, propose its actions.
    Returns the actions created. Safe to call repeatedly (existing actions are not duplicated)."""
    from app.config import get_settings
    from app.models.action import ActionSource
    from app.models.log_event import LogEvent
    from app.services.action_service import ACTION_PARAM_KEYS, create_action, find_active_duplicate
    from app.services.triage_guard import AI_PROPOSABLE_ACTIONS, RecommendedAction, observed_entities, plan_action

    step = await get_current_step(db, incident_id)
    if not step or step.step_type != StepType.AUTOMATED or not step.auto_action_type:
        return []
    action_type = step.auto_action_type
    kind = AI_PROPOSABLE_ACTIONS.get(action_type)
    if kind is None or action_type not in ACTION_PARAM_KEYS:
        return []

    events = (await db.execute(select(LogEvent).where(LogEvent.incident_id == incident_id))).scalars().all()
    observed = observed_entities([
        {"source_ip": str(e.source_ip) if e.source_ip else None,
         "destination_ip": str(e.destination_ip) if e.destination_ip else None,
         "host": e.host, "user_identity": e.user_identity, "raw_data": e.raw_data}
        for e in events
    ])
    settings = get_settings()
    may_auto = not step.requires_approval

    created = []
    skipped = 0
    for target in sorted(observed.get(kind, set())):
        # Reuse the AI guard: same target checks (in the evidence, public IPs only),
        # same allow-list for what may run unattended.
        plan = plan_action(
            RecommendedAction(action=action_type, target=target, can_auto_execute=True),
            observed, confidence=1.0, requires_human_review=False,
            auto_types=settings.auto_execute_action_types, threshold=0.0, allow_auto=may_auto,
        )
        if plan.disposition == "skip":
            skipped += 1
            continue
        if await find_active_duplicate(db, incident_id, action_type, plan.params):
            continue
        action = await create_action(
            db=db, incident_id=incident_id, action_type=action_type, action_params=plan.params,
            source=ActionSource.AUTO, requested_by=f"playbook:{actor}",
            auto_execute=plan.disposition == "auto",
            reason=f"playbook step {step.step_order} ({step.title})",
        )
        created.append(action)

    if not created:
        db.add(IncidentTimeline(
            incident_id=incident_id,
            event_type="playbook_step_manual",
            actor="system",
            description=(f"Playbook step {step.step_order} ({step.title}): no "
                         f"{kind.replace('_', ' ')} in this incident's evidence to act on"
                         + (f" ({skipped} ruled out)" if skipped else "")
                         + ". Handle it manually, then mark the step done."),
            timestamp=datetime.now(timezone.utc),
        ))
    await db.flush()
    return created


async def on_action_settled(db: AsyncSession, action) -> None:
    """Called when an action completes, fails or is rejected. If it belonged to the
    incident's current automated step and that step's work is now finished, move the
    playbook on. A step with nothing completed stays put for the analyst to decide."""
    from app.models.action import ActionLog, ActionStatus

    step = await get_current_step(db, action.incident_id)
    if not step or step.step_type != StepType.AUTOMATED or step.auto_action_type != action.action_type:
        return
    rows = (await db.execute(
        select(ActionLog).where(ActionLog.incident_id == action.incident_id, ActionLog.action_type == action.action_type)
    )).scalars().all()
    if any(a.status in (ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED, ActionStatus.EXECUTING) for a in rows):
        return  # still waiting on something
    if not any(a.status == ActionStatus.COMPLETED for a in rows):
        return  # everything failed or was rejected: a person decides what next
    await advance_step(db, action.incident_id, "system")
    await run_current_step(db, action.incident_id)
