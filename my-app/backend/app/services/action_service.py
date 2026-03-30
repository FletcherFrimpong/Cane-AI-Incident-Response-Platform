"""
Action service: manages auto-response execution and approval workflow.
"""

import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.action import ActionLog, ActionStatus, ActionSource
from app.models.incident import Incident, IncidentTimeline
from app.services.integration_service import get_integration_client_by_platform
from app.exceptions import NotFoundError, ForbiddenError

import uuid

logger = logging.getLogger("cane_ai.actions")

# Map action types to integration platforms and methods
ACTION_INTEGRATION_MAP = {
    "block_ip": {"platform": "microsoft_defender", "method": "block_ip"},
    "block_url": {"platform": "microsoft_defender", "method": "block_url"},
    "block_file_hash": {"platform": "microsoft_defender", "method": "block_file_hash"},
    "isolate_host": {"platform": "microsoft_defender", "method": "isolate_machine"},
    "release_host": {"platform": "microsoft_defender", "method": "release_machine"},
    "run_av_scan": {"platform": "microsoft_defender", "method": "run_av_scan"},
    "disable_account": {"platform": "microsoft_graph", "method": "disable_user"},
    "enable_account": {"platform": "microsoft_graph", "method": "enable_user"},
    "revoke_sessions": {"platform": "microsoft_graph", "method": "revoke_sessions"},
    "force_password_reset": {"platform": "microsoft_graph", "method": "force_password_reset"},
    "quarantine_email": {"platform": "microsoft_defender", "method": "block_file_hash"},
    "run_kql_query": {"platform": "microsoft_sentinel", "method": "run_kql_query"},
}


async def create_action(
    db: AsyncSession,
    incident_id: uuid.UUID,
    action_type: str,
    action_params: dict | None,
    source: ActionSource,
    requested_by: str,
    auto_execute: bool = False,
    confidence: float | None = None,
    auto_threshold: float = 0.95,
) -> ActionLog:
    """Create an action log entry. Auto-execute if confidence is above threshold."""
    action = ActionLog(
        incident_id=incident_id,
        action_type=action_type,
        action_params=action_params,
        source=source,
        status=ActionStatus.PENDING_APPROVAL,
        requested_by=requested_by,
    )

    # Auto-execute if confidence is high enough and auto_execute is requested
    if auto_execute and confidence and confidence >= auto_threshold:
        action.status = ActionStatus.APPROVED
        db.add(action)
        await db.flush()
        return await execute_action(db, action.id, "system")

    db.add(action)
    await db.flush()
    return action


async def approve_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    approved_by: uuid.UUID,
    notes: str | None = None,
) -> ActionLog:
    """Approve a pending action."""
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ForbiddenError(f"Action is not pending approval (status: {action.status.value})")

    action.status = ActionStatus.APPROVED
    action.approved_by = approved_by
    await db.flush()

    # Execute the action
    return await execute_action(db, action.id, str(approved_by))


async def reject_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    rejected_by: uuid.UUID,
    reason: str,
) -> ActionLog:
    """Reject a pending action."""
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")
    if action.status != ActionStatus.PENDING_APPROVAL:
        raise ForbiddenError(f"Action is not pending approval (status: {action.status.value})")

    action.status = ActionStatus.REJECTED
    action.error_message = f"Rejected: {reason}"

    timeline = IncidentTimeline(
        incident_id=action.incident_id,
        event_type="action_rejected",
        actor=str(rejected_by),
        description=f"Action '{action.action_type}' rejected: {reason}",
        extra_data={"action_id": str(action.id), "reason": reason},
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return action


async def execute_action(
    db: AsyncSession,
    action_id: uuid.UUID,
    executor: str,
) -> ActionLog:
    """Execute an approved action via the integration layer."""
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise NotFoundError("Action not found")

    action.status = ActionStatus.EXECUTING
    await db.flush()

    mapping = ACTION_INTEGRATION_MAP.get(action.action_type)
    if not mapping:
        action.status = ActionStatus.FAILED
        action.error_message = f"Unknown action type: {action.action_type}"
        await db.flush()
        return action

    try:
        client = await get_integration_client_by_platform(db, mapping["platform"])
        method = getattr(client, mapping["method"])

        # Build method arguments from action_params
        params = action.action_params or {}
        result_data = await method(**params)

        action.status = ActionStatus.COMPLETED
        action.result = result_data
        action.executed_at = datetime.now(timezone.utc)

        timeline = IncidentTimeline(
            incident_id=action.incident_id,
            event_type="action_executed",
            actor=executor,
            description=f"Action '{action.action_type}' executed successfully",
            extra_data={"action_id": str(action.id), "result": result_data},
            timestamp=datetime.now(timezone.utc),
        )
        db.add(timeline)

        await client.close()
    except NotFoundError:
        action.status = ActionStatus.FAILED
        action.error_message = f"No active {mapping['platform']} integration configured. Set up the integration in Settings → Integrations."
        logger.error("No integration configured for %s", mapping["platform"])
    except Exception as e:
        action.status = ActionStatus.FAILED
        action.error_message = str(e)
        logger.error("Action execution failed: %s", e)

        timeline = IncidentTimeline(
            incident_id=action.incident_id,
            event_type="action_failed",
            actor=executor,
            description=f"Action '{action.action_type}' failed: {str(e)}",
            extra_data={"action_id": str(action.id), "error": str(e)},
            timestamp=datetime.now(timezone.utc),
        )
        db.add(timeline)

    await db.flush()
    return action
