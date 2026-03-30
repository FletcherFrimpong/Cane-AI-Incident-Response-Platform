import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_tier2
from app.models.user import User
from app.models.incident import Incident, IncidentTimeline, IncidentStatus
from app.models.log_event import LogEvent
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentListResponse,
    TimelineEntryResponse,
    IncidentAssign,
    IncidentNote,
)
from app.schemas.log_event import LogEventResponse
from app.exceptions import NotFoundError

router = APIRouter()


@router.get("/", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    assigned_to: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    conditions = []
    if status:
        conditions.append(Incident.status == status)
    if severity:
        conditions.append(Incident.severity == severity)
    if attack_type:
        conditions.append(Incident.attack_type == attack_type)
    if assigned_to:
        conditions.append(Incident.assigned_to == assigned_to)

    count_q = select(func.count(Incident.id))
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    severity_rank = case(
        (Incident.severity == "critical", 0),
        (Incident.severity == "high", 1),
        (Incident.severity == "medium", 2),
        (Incident.severity == "low", 3),
        else_=4,
    )
    status_rank = case(
        (Incident.status == "awaiting_analyst", 0),
        (Incident.status == "new", 1),
        (Incident.status == "triaging", 2),
        (Incident.status == "in_progress", 3),
        (Incident.status == "containment", 4),
        (Incident.status == "eradication", 5),
        (Incident.status == "recovery", 6),
        else_=7,
    )

    query = select(Incident).order_by(severity_rank, status_rank, Incident.created_at.desc())
    if conditions:
        query = query.where(and_(*conditions))
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()

    return IncidentListResponse(
        items=[IncidentResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/", response_model=IncidentResponse, status_code=201)
async def create_incident(
    data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    incident = Incident(
        tenant_id=data.tenant_id,
        title=data.title,
        description=data.description,
        severity=data.severity,
        attack_type=data.attack_type,
    )
    db.add(incident)
    await db.flush()

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        actor=current_user.email,
        description=f"Incident manually created by {current_user.full_name}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: uuid.UUID,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    changes = []
    for field, value in data.model_dump(exclude_unset=True).items():
        old_value = getattr(incident, field)
        if old_value != value:
            setattr(incident, field, value)
            changes.append(f"{field}: {old_value} → {value}")

    if changes:
        timeline = IncidentTimeline(
            incident_id=incident.id,
            event_type="status_change",
            actor=current_user.email,
            description=f"Updated: {'; '.join(changes)}",
            timestamp=datetime.now(timezone.utc),
        )
        db.add(timeline)

    await db.flush()
    return incident


@router.put("/{incident_id}/assign", response_model=IncidentResponse)
async def assign_incident(
    incident_id: uuid.UUID,
    data: IncidentAssign,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    incident.assigned_to = data.user_id
    if incident.status == IncidentStatus.NEW:
        incident.status = IncidentStatus.IN_PROGRESS

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="assignment",
        actor=current_user.email,
        description=f"Assigned to user {data.user_id}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.put("/{incident_id}/escalate", response_model=IncidentResponse)
async def escalate_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    incident.status = IncidentStatus.AWAITING_ANALYST

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="escalation",
        actor=current_user.email,
        description=f"Escalated by {current_user.full_name}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.put("/{incident_id}/close", response_model=IncidentResponse)
async def close_incident(
    incident_id: uuid.UUID,
    note: IncidentNote,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    incident.status = IncidentStatus.CLOSED
    incident.resolved_at = datetime.now(timezone.utc)

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_closed",
        actor=current_user.email,
        description=f"Closed: {note.content}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.get("/{incident_id}/timeline", response_model=list[TimelineEntryResponse])
async def get_incident_timeline(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == incident_id)
        .order_by(IncidentTimeline.timestamp.asc())
    )
    return result.scalars().all()


@router.get("/{incident_id}/evidence")
async def get_incident_evidence(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(LogEvent)
        .where(LogEvent.incident_id == incident_id)
        .order_by(LogEvent.time_generated.asc())
    )
    events = result.scalars().all()
    return [LogEventResponse.model_validate(e) for e in events]


@router.post("/{incident_id}/notes")
async def add_incident_note(
    incident_id: uuid.UUID,
    note: IncidentNote,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not result.scalar_one_or_none():
        raise NotFoundError("Incident not found")

    timeline = IncidentTimeline(
        incident_id=incident_id,
        event_type="analyst_note",
        actor=current_user.email,
        description=note.content,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return {"status": "note added"}
