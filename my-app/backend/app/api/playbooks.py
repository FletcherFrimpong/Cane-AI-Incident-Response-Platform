import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_manager
from app.models.user import User
from app.models.playbook import Playbook, PlaybookFramework, PlaybookStep
from app.models.incident import Incident
from app.schemas.playbook import (
    PlaybookAdvance,
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookStepCreate,
    PlaybookStepUpdate,
    PlaybookResponse,
    PlaybookDetailResponse,
    PlaybookStepResponse,
)
from app.services.playbook_service import (
    attach_playbook_to_incident, get_current_step, advance_step, run_current_step,
)
from app.exceptions import NotFoundError

router = APIRouter()


@router.get("/", response_model=list[PlaybookResponse])
async def list_playbooks(
    attack_type: str | None = None,
    framework: str | None = None,
    is_builtin: bool | None = None,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    query = select(Playbook).where(Playbook.is_active == True)
    if framework:
        try:
            query = query.where(Playbook.framework == PlaybookFramework(framework))
        except ValueError:
            return []
    if is_builtin is not None:
        query = query.where(Playbook.is_builtin == is_builtin)
    if attack_type:
        query = query.where(Playbook.attack_types.contains([attack_type]))

    result = await db.execute(query.order_by(Playbook.is_builtin.desc(), Playbook.name))
    playbooks = result.scalars().all()
    counts = dict((await db.execute(
        select(PlaybookStep.playbook_id, func.count(PlaybookStep.id)).group_by(PlaybookStep.playbook_id)
    )).all())
    out = []
    for pb in playbooks:
        item = PlaybookResponse.model_validate(pb)
        item.steps_count = counts.get(pb.id, 0)
        out.append(item)
    return out


@router.post("/", response_model=PlaybookResponse, status_code=201)
async def create_playbook(
    data: PlaybookCreate,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    playbook = Playbook(
        name=data.name,
        description=data.description,
        framework=data.framework,
        attack_types=data.attack_types,
        is_builtin=False,
        created_by=current_user.id,
    )
    db.add(playbook)
    await db.flush()
    return playbook


@router.get("/{playbook_id}", response_model=PlaybookDetailResponse)
async def get_playbook(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise NotFoundError("Playbook not found")

    # Load steps
    steps_result = await db.execute(
        select(PlaybookStep)
        .where(PlaybookStep.playbook_id == playbook_id)
        .order_by(PlaybookStep.step_order)
    )
    steps = steps_result.scalars().all()

    return PlaybookDetailResponse(
        **PlaybookResponse.model_validate(playbook).model_dump(),
        steps=[PlaybookStepResponse.model_validate(s) for s in steps],
    )


@router.put("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: uuid.UUID,
    data: PlaybookUpdate,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise NotFoundError("Playbook not found")

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(playbook, field, value)
    await db.flush()
    return playbook


@router.delete("/{playbook_id}")
async def delete_playbook(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise NotFoundError("Playbook not found")
    if playbook.is_builtin:
        playbook.is_active = False  # Soft delete for builtins
    else:
        await db.delete(playbook)
    await db.flush()
    return {"detail": "Playbook deleted"}


@router.get("/{playbook_id}/steps", response_model=list[PlaybookStepResponse])
async def list_steps(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(PlaybookStep)
        .where(PlaybookStep.playbook_id == playbook_id)
        .order_by(PlaybookStep.step_order)
    )
    return result.scalars().all()


@router.post("/{playbook_id}/steps", response_model=PlaybookStepResponse, status_code=201)
async def add_step(
    playbook_id: uuid.UUID,
    data: PlaybookStepCreate,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    step = PlaybookStep(
        playbook_id=playbook_id,
        step_order=data.step_order,
        phase=data.phase,
        title=data.title,
        description=data.description,
        step_type=data.step_type,
        auto_action_type=data.auto_action_type,
        auto_action_params=data.auto_action_params,
        conditions=data.conditions,
        requires_approval=data.requires_approval,
        timeout_minutes=data.timeout_minutes,
    )
    db.add(step)
    await db.flush()
    return step


@router.put("/{playbook_id}/steps/{step_id}", response_model=PlaybookStepResponse)
async def update_step(
    playbook_id: uuid.UUID,
    step_id: uuid.UUID,
    data: PlaybookStepUpdate,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    result = await db.execute(
        select(PlaybookStep).where(PlaybookStep.id == step_id, PlaybookStep.playbook_id == playbook_id)
    )
    step = result.scalar_one_or_none()
    if not step:
        raise NotFoundError("Step not found")
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(step, field, value)
    await db.flush()
    return step


@router.delete("/{playbook_id}/steps/{step_id}")
async def delete_step(
    playbook_id: uuid.UUID,
    step_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(require_manager),
):
    result = await db.execute(
        select(PlaybookStep).where(PlaybookStep.id == step_id, PlaybookStep.playbook_id == playbook_id)
    )
    step = result.scalar_one_or_none()
    if not step:
        raise NotFoundError("Step not found")
    await db.delete(step)
    return {"detail": "Step deleted"}


@router.post("/{playbook_id}/execute/{incident_id}")
async def execute_playbook(
    playbook_id: uuid.UUID,
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Attach playbook to incident and begin execution."""
    incident = await attach_playbook_to_incident(db, incident_id, playbook_id, current_user.email)
    await run_current_step(db, incident_id, current_user.email)
    step = await get_current_step(db, incident_id)
    return {
        "incident_id": str(incident.id),
        "playbook_id": str(playbook_id),
        "current_step": PlaybookStepResponse.model_validate(step).model_dump(mode="json") if step else None,
    }


@router.post("/advance/{incident_id}")
async def advance_playbook(
    incident_id: uuid.UUID,
    data: PlaybookAdvance | None = None,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Mark the incident's current playbook step done and move to the next one.
    For a decision step, pass the analyst's decision; steps whose condition does
    not match it are skipped. Returns the new current step (null when finished)."""
    step = await advance_step(db, incident_id, current_user.email, data.decision if data else None)
    await run_current_step(db, incident_id, current_user.email)
    return {
        "incident_id": str(incident_id),
        "current_step": PlaybookStepResponse.model_validate(step).model_dump(mode="json") if step else None,
        "completed": step is None,
    }
