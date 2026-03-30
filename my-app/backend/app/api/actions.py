import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_tier2
from app.models.user import User
from app.models.action import ActionLog, ActionStatus, ActionSource
from app.schemas.action import (
    ActionExecuteRequest,
    ActionApproveRequest,
    ActionRejectRequest,
    ActionLogResponse,
)
from app.services.action_service import create_action, approve_action, reject_action

router = APIRouter()


@router.get("/pending", response_model=list[ActionLogResponse])
async def list_pending_actions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List actions awaiting approval."""
    result = await db.execute(
        select(ActionLog)
        .where(ActionLog.status == ActionStatus.PENDING_APPROVAL)
        .order_by(ActionLog.created_at.desc())
    )
    return result.scalars().all()


@router.post("/execute", response_model=ActionLogResponse)
async def execute_action_endpoint(
    data: ActionExecuteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_tier2),
):
    """Execute an action directly (Tier 2+ only)."""
    action = await create_action(
        db=db,
        incident_id=data.incident_id,
        action_type=data.action_type,
        action_params=data.action_params,
        source=ActionSource.ANALYST,
        requested_by=current_user.email,
        auto_execute=True,
        confidence=1.0,
        auto_threshold=0.0,  # Always execute for direct analyst action
    )
    return action


@router.post("/{action_id}/approve", response_model=ActionLogResponse)
async def approve_action_endpoint(
    action_id: uuid.UUID,
    data: ActionApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_tier2),
):
    """Approve a pending action (Tier 2+ only)."""
    return await approve_action(db, action_id, current_user.id, data.notes)


@router.post("/{action_id}/reject", response_model=ActionLogResponse)
async def reject_action_endpoint(
    action_id: uuid.UUID,
    data: ActionRejectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_tier2),
):
    """Reject a pending action."""
    return await reject_action(db, action_id, current_user.id, data.reason)


@router.get("/history", response_model=list[ActionLogResponse])
async def action_history(
    incident_id: uuid.UUID | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Action audit log."""
    query = select(ActionLog).order_by(ActionLog.created_at.desc())
    if incident_id:
        query = query.where(ActionLog.incident_id == incident_id)
    if status:
        query = query.where(ActionLog.status == status)
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    return result.scalars().all()
