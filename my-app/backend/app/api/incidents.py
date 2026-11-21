import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, select, func, and_, or_, case, cast
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_tier2
from app.models.user import User
from app.models.incident import Incident, IncidentSeverity, IncidentTimeline, IncidentStatus
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
from app.exceptions import NotFoundError, ValidationError

router = APIRouter()


OPEN_STATUSES = [
    IncidentStatus.NEW, IncidentStatus.TRIAGING, IncidentStatus.AWAITING_ANALYST, IncidentStatus.IN_PROGRESS,
    IncidentStatus.CONTAINMENT, IncidentStatus.ERADICATION, IncidentStatus.RECOVERY,
]
_SERIOUS = [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]

# Queue views, in sidebar order: (key, label)
INCIDENT_VIEWS = [
    ("attention", "Needs your attention"),
    ("mine", "Assigned to you"),
    ("unassigned", "Unassigned incidents"),
    ("open", "All open incidents"),
    ("recent", "Recently updated"),
    ("low", "Low priority"),
    ("closed", "Closed incidents"),
    ("false_positive", "False positives"),
]


def _view_conditions(view: str, user: User) -> list:
    is_open = Incident.status.in_(OPEN_STATUSES)
    if view == "attention":
        # Waiting on a person, or serious and not yet picked up
        return [or_(
            Incident.status == IncidentStatus.AWAITING_ANALYST,
            and_(Incident.status.in_([IncidentStatus.NEW, IncidentStatus.TRIAGING]), Incident.severity.in_(_SERIOUS)),
        )]
    if view == "mine":
        return [is_open, Incident.assigned_to == user.id]
    if view == "unassigned":
        return [is_open, Incident.assigned_to.is_(None),
                Incident.severity.notin_([IncidentSeverity.INFO, IncidentSeverity.LOW])]
    if view == "open":
        return [is_open]
    if view == "recent":
        return [Incident.updated_at >= datetime.now(timezone.utc) - timedelta(days=1)]
    if view == "low":
        return [is_open, Incident.severity.in_([IncidentSeverity.INFO, IncidentSeverity.LOW])]
    if view == "closed":
        return [Incident.status == IncidentStatus.CLOSED]
    if view == "false_positive":
        return [Incident.status == IncidentStatus.FALSE_POSITIVE]
    raise ValidationError(f"Unknown view '{view}'")


@router.get("/views")
async def incident_views(
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """The incident queue's views with how many incidents are in each."""
    views = []
    for key, label in INCIDENT_VIEWS:
        count = (await db.execute(
            select(func.count(Incident.id)).where(and_(*_view_conditions(key, current_user)))
        )).scalar() or 0
        views.append({"key": key, "label": label, "count": count})
    return views


@router.get("/", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    view: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    attack_type: str | None = None,
    assigned_to: uuid.UUID | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    conditions = _view_conditions(view, current_user) if view else []
    try:
        if status:
            conditions.append(Incident.status == IncidentStatus(status))
        if severity:
            conditions.append(Incident.severity == IncidentSeverity(severity))
    except ValueError as e:
        raise ValidationError(str(e))
    if attack_type:
        conditions.append(Incident.attack_type == attack_type)
    if assigned_to:
        conditions.append(Incident.assigned_to == assigned_to)
    if search and search.strip():
        like = f"%{search.strip()}%"
        conditions.append(or_(
            Incident.title.ilike(like), Incident.attack_type.ilike(like),
            Incident.correlation_id.ilike(like), cast(Incident.id, String).ilike(like),
        ))

    count_q = select(func.count(Incident.id))
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    severity_rank = case(
        (Incident.severity == IncidentSeverity.CRITICAL, 0),
        (Incident.severity == IncidentSeverity.HIGH, 1),
        (Incident.severity == IncidentSeverity.MEDIUM, 2),
        (Incident.severity == IncidentSeverity.LOW, 3),
        else_=4,
    )
    status_rank = case(
        (Incident.status == IncidentStatus.AWAITING_ANALYST, 0),
        (Incident.status == IncidentStatus.NEW, 1),
        (Incident.status == IncidentStatus.TRIAGING, 2),
        (Incident.status == IncidentStatus.IN_PROGRESS, 3),
        (Incident.status == IncidentStatus.CONTAINMENT, 4),
        (Incident.status == IncidentStatus.ERADICATION, 5),
        (Incident.status == IncidentStatus.RECOVERY, 6),
        else_=7,
    )

    if view == "recent":
        query = select(Incident).order_by(Incident.updated_at.desc())
    else:
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
    db: AsyncSession = Depends(get_db, scope="function"),
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
    db: AsyncSession = Depends(get_db, scope="function"),
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
    db: AsyncSession = Depends(get_db, scope="function"),
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
            show = lambda v: getattr(v, "value", v)  # noqa: E731 - enums print as their value
            changes.append(f"{field.replace('_', ' ')}: {show(old_value)} → {show(value)}")
    if data.status in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE) and incident.resolved_at is None:
        incident.resolved_at = datetime.now(timezone.utc)
    elif data.status is not None and data.status in OPEN_STATUSES:
        incident.resolved_at = None  # reopened

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
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    assignee_name = None
    if data.user_id is not None:
        assignee = (await db.execute(select(User).where(User.id == data.user_id))).scalar_one_or_none()
        if not assignee or not assignee.is_active:
            raise ValidationError("That user does not exist or is deactivated")
        assignee_name = assignee.full_name

    incident.assigned_to = data.user_id
    if data.user_id is not None and incident.status in (IncidentStatus.NEW, IncidentStatus.TRIAGING,
                                                         IncidentStatus.AWAITING_ANALYST):
        incident.status = IncidentStatus.IN_PROGRESS

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="assignment",
        actor=current_user.email,
        description=f"Assigned to {assignee_name}" if assignee_name else "Unassigned",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.put("/{incident_id}/escalate", response_model=IncidentResponse)
async def escalate_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
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
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise NotFoundError("Incident not found")

    incident.status = IncidentStatus.FALSE_POSITIVE if note.false_positive else IncidentStatus.CLOSED
    incident.resolved_at = datetime.now(timezone.utc)

    timeline = IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_closed",
        actor=current_user.email,
        description=f"{'Closed as false positive' if note.false_positive else 'Closed'}: {note.content}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(timeline)
    await db.flush()
    return incident


@router.post("/{incident_id}/enrich", response_model=IncidentResponse)
async def enrich_incident_endpoint(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
    current_user: User = Depends(get_current_active_user),
):
    """Look up this incident's indicators, accounts and hosts in every connected
    threat-intelligence and context source, and store the result on the incident."""
    from app.services.triage_service import enrich_incident

    data = await enrich_incident(db, incident_id)
    if data is None:
        raise ValidationError("No enrichment source is connected. Add one under Settings → Integrations.")
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    return result.scalar_one()


@router.get("/{incident_id}/timeline", response_model=list[TimelineEntryResponse])
async def get_incident_timeline(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db, scope="function"),
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
    db: AsyncSession = Depends(get_db, scope="function"),
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
    db: AsyncSession = Depends(get_db, scope="function"),
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
