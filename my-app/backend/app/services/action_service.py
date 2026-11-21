"""
Action service: manages response actions, the approval workflow, and execution.
"""

import inspect
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError
from app.models.action import ActionLog, ActionSource, ActionStatus
from app.models.incident import Incident, IncidentTimeline

logger = logging.getLogger("cane_ai.actions")

# The parameter each action needs to identify its target. Connectors implement an
# action as a method taking exactly this keyword (see BaseIntegrationClient.actions).
ACTION_PARAM_KEYS = {
    "block_ip": "ip_address",
    "block_url": "url",
    "block_file_hash": "file_hash",
    "isolate_host": "machine_id",
    "release_host": "machine_id",
    "run_av_scan": "machine_id",
    "disable_account": "user_principal_name",
    "enable_account": "user_principal_name",
    "revoke_sessions": "user_principal_name",
    "force_password_reset": "user_principal_name",
    "purge_email": "internet_message_id",
    "run_kql_query": "query",
}

# Extra parameters an action accepts besides its target
ACTION_EXTRA_PARAMS = {
    "purge_email": {"recipients"},
    "run_kql_query": {"timespan"},
}

# Kept for callers that only need to know whether an action type exists
ACTION_INTEGRATION_MAP = {name: {} for name in ACTION_PARAM_KEYS}


def platforms_supporting(action_type: str) -> list[str]:
    """Display names of the connectors able to run an action (for error messages)."""
    from app.integrations.registry import INTEGRATION_REGISTRY

    return sorted(cls.display_name for cls in INTEGRATION_REGISTRY.values() if action_type in cls.actions)


# An action in one of these states already covers the same (type, target).
_ACTIVE_STATUSES = [
    ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED, ActionStatus.EXECUTING, ActionStatus.COMPLETED,
]


def validate_action(action_type: str, action_params: dict | None) -> dict:
    """Check an action is one we can run and names its target. Returns clean params."""
    if action_type not in ACTION_PARAM_KEYS:
        raise ValidationError(
            f"Unknown action type '{action_type}'. Supported: {', '.join(sorted(ACTION_PARAM_KEYS))}"
        )
    params = dict(action_params or {})
    key = ACTION_PARAM_KEYS[action_type]
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Action '{action_type}' requires the parameter '{key}'")
    allowed = {key} | ACTION_EXTRA_PARAMS.get(action_type, set())
    for name, param_value in params.items():
        if name not in allowed:
            raise ValidationError(f"Action '{action_type}' does not take the parameter '{name}'")
        if not isinstance(param_value, (str, int, float, bool)):
            raise ValidationError(f"Parameter '{name}' must be a simple value")
    params[key] = value.strip()
    return params


async def find_active_duplicate(
    db: AsyncSession, incident_id: uuid.UUID, action_type: str, action_params: dict | None,
) -> ActionLog | None:
    """An existing pending/approved/running/completed action with the same type AND target."""
    result = await db.execute(
        select(ActionLog).where(
            ActionLog.incident_id == incident_id,
            ActionLog.action_type == action_type,
            ActionLog.status.in_(_ACTIVE_STATUSES),
        )
    )
    for existing in result.scalars().all():
        if (existing.action_params or {}) == (action_params or {}):
            return existing
    return None


async def create_action(
    db: AsyncSession,
    incident_id: uuid.UUID,
    action_type: str,
    action_params: dict | None,
    source: ActionSource,
    requested_by: str,
    auto_execute: bool = False,
    reason: str | None = None,
) -> ActionLog:
    """Record a response action. It waits for approval unless `auto_execute` is set,
    in which case it is committed first and then executed.

    Whether automation is allowed is the caller's decision (see triage_guard.plan_action
    for AI recommendations); this function only carries it out."""
    params = validate_action(action_type, action_params)
    incident = (await db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    action = ActionLog(
        incident_id=incident_id,
        action_type=action_type,
        action_params=params,
        source=source,
        status=ActionStatus.APPROVED if auto_execute else ActionStatus.PENDING_APPROVAL,
        requested_by=requested_by,
    )
    db.add(action)
    await db.flush()

    if not auto_execute:
        db.add(IncidentTimeline(
            incident_id=incident_id,
            event_type="action_proposed",
            actor=requested_by,
            description=f"Action '{action_type}' on {params[ACTION_PARAM_KEYS[action_type]]} awaiting approval"
                        + (f": {reason}" if reason else ""),
            extra_data={"action_id": str(action.id), "action_type": action_type, "params": params},
            timestamp=datetime.now(timezone.utc),
        ))
        await db.flush()
        return action

    return await execute_action(db, action.id, requested_by)


async def approve_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    approved_by: uuid.UUID,
    approver_label: str | None = None,
    notes: str | None = None,
) -> ActionLog:
    """Approve a pending action and execute it."""
    # Row lock: two analysts clicking Approve at once must not both execute it.
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id).with_for_update())
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ConflictError(f"Action is not pending approval (status: {action.status.value})")

    action.status = ActionStatus.APPROVED
    action.approved_by = approved_by
    await db.flush()

    return await execute_action(db, action.id, approver_label or str(approved_by), notes=notes)


async def reject_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    rejected_by: uuid.UUID,
    reason: str,
    rejecter_label: str | None = None,
) -> ActionLog:
    """Reject a pending action."""
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id).with_for_update())
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ConflictError(f"Action is not pending approval (status: {action.status.value})")

    action.status = ActionStatus.REJECTED
    action.error_message = f"Rejected: {reason}"

    db.add(IncidentTimeline(
        incident_id=action.incident_id,
        event_type="action_rejected",
        actor=rejecter_label or str(rejected_by),
        description=f"Action '{action.action_type}' rejected: {reason}",
        extra_data={"action_id": str(action.id), "reason": reason},
        timestamp=datetime.now(timezone.utc),
    ))
    await db.flush()
    await _settled(db, action)
    return action


async def execute_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    executor: str,
    notes: str | None = None,
) -> ActionLog:
    """Execute an approved action on every connected tool that supports it.

    Blocking an address should reach each firewall and EDR that is connected;
    isolating a host should reach whichever EDR knows that host. So the action is
    sent to all active integrations declaring it, and it counts as done when at
    least one of them succeeds. Each tool's outcome is kept in `result.results`.

    The EXECUTING state is committed before the first external call and the outcome
    right after the last. If anything later in the request or task fails, the record
    that real systems were touched survives, and a retry will not run it twice.
    """
    from app.services.integration_service import active_clients, close_clients

    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id).with_for_update())
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")
    if action.status != ActionStatus.APPROVED:
        raise ForbiddenError(f"Action must be approved before it runs (status: {action.status.value})")

    if action.action_type not in ACTION_PARAM_KEYS:
        action.status = ActionStatus.FAILED
        action.error_message = f"Unknown action type: {action.action_type}"
        await db.commit()
        return action

    action.status = ActionStatus.EXECUTING
    await db.commit()

    params = action.action_params or {}
    clients = await active_clients(db, action=action.action_type)
    outcomes: list[dict] = []
    for client in clients:
        outcome = {"integration": client.integration_name, "platform": client.platform_name}
        try:
            method = getattr(client, type(client).actions[action.action_type])
            try:
                inspect.signature(method).bind(**params)
            except TypeError as e:
                raise ValidationError(f"Invalid parameters for {action.action_type}: {e}")
            reply = await method(**params)
            reply = reply if isinstance(reply, dict) else {"success": True, "data": reply}
            outcome.update({k: v for k, v in reply.items() if k not in ("integration", "platform")})
            outcome["success"] = reply.get("success") is not False
            outcome["dry_run"] = bool(reply.get("dry_run") or getattr(client, "dry_run", False))
        except Exception as e:  # noqa: BLE001 - connectors raise httpx and vendor-specific errors
            detail = getattr(e, "detail", None) or str(e) or type(e).__name__
            outcome.update({"success": False, "message": str(detail)[:500]})
            logger.error("Action %s failed on %s: %s", action.action_type, client.integration_name, detail)
        outcomes.append(outcome)
    await close_clients(clients)

    succeeded = [o for o in outcomes if o["success"]]
    timeline_extra: dict = {"action_id": str(action.id), "results": outcomes}
    if succeeded:
        dry_run = all(o.get("dry_run") for o in succeeded)
        action.status = ActionStatus.COMPLETED
        action.result = {"results": outcomes, "dry_run": dry_run}
        action.executed_at = datetime.now(timezone.utc)
        where = ", ".join(o["integration"] for o in succeeded)
        timeline_type = "action_executed"
        timeline_text = (f"Action '{action.action_type}' "
                         + (f"simulated on {where} (dry-run mode)" if dry_run else f"executed on {where}"))
        failed = [o for o in outcomes if not o["success"]]
        if failed:
            timeline_text += "; not done on " + ", ".join(o["integration"] for o in failed)
        timeline_extra["dry_run"] = dry_run
        if notes:
            timeline_extra["notes"] = notes
    else:
        action.status = ActionStatus.FAILED
        action.result = {"results": outcomes} if outcomes else None
        timeline_type = "action_failed"
        if not outcomes:
            options = platforms_supporting(action.action_type)
            action.error_message = (
                f"No connected integration can run '{action.action_type}'. "
                + (f"Connect one of: {', '.join(options)} (Settings → Integrations)." if options
                   else "No connector supports this action.")
            )
            timeline_text = f"Action '{action.action_type}' could not run: no connected integration supports it"
        else:
            action.error_message = "; ".join(f"{o['integration']}: {o.get('message') or 'failed'}" for o in outcomes)[:1000]
            timeline_text = f"Action '{action.action_type}' failed: {action.error_message[:300]}"

    db.add(IncidentTimeline(
        incident_id=action.incident_id,
        event_type=timeline_type,
        actor=executor,
        description=timeline_text,
        extra_data=timeline_extra,
        timestamp=datetime.now(timezone.utc),
    ))
    await db.commit()
    await _settled(db, action)
    return action


async def _settled(db: AsyncSession, action: ActionLog) -> None:
    """Let the playbook engine react to a finished action. Never fails the action."""
    try:
        from app.services.playbook_service import on_action_settled

        await on_action_settled(db, action)
        await db.commit()
    except Exception as e:  # noqa: BLE001
        await db.rollback()
        logger.error("Playbook follow-up for action %s failed: %s", action.id, e)
