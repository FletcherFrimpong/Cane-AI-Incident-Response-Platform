import json
from fastapi import APIRouter, Depends, UploadFile, File, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user
from app.models.user import User
from app.models.log_event import LogEvent
from app.schemas.log_event import (
    LogEventIngest,
    LogEventBatchIngest,
    LogEventResponse,
    LogEventDetailResponse,
    LogEventListResponse,
)
from app.services.log_ingestion import ingest_single_event, ingest_batch, ingest_json_file
from app.services.log_normalizer import get_supported_schemas
from app.exceptions import NotFoundError

import uuid

router = APIRouter()


@router.post("/ingest")
async def ingest_log_event(
    event: LogEventIngest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Ingest a single log event (real-time webhook from Sentinel)."""
    log_event = await ingest_single_event(db, event.schemaId, event.data)
    return {
        "status": "ingested",
        "event_id": str(log_event.id),
        "log_type": log_event.log_type,
        "severity": log_event.severity,
        "correlation_id": log_event.correlation_id,
        "incident_id": str(log_event.incident_id) if log_event.incident_id else None,
    }


@router.post("/batch")
async def ingest_batch_events(
    batch: LogEventBatchIngest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Ingest a batch of log events."""
    events = [{"schemaId": e.schemaId, "data": e.data} for e in batch.events]
    result = await ingest_batch(db, events)
    return result


@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a JSON file containing log events."""
    content = await file.read()
    result = await ingest_json_file(db, content)
    return {
        "filename": file.filename,
        **result,
    }


@router.get("/", response_model=LogEventListResponse)
async def list_log_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    log_type: str | None = None,
    severity: str | None = None,
    correlation_id: str | None = None,
    source_ip: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Query log events with filters."""
    conditions = []
    if log_type:
        conditions.append(LogEvent.log_type == log_type)
    if severity:
        conditions.append(LogEvent.severity == severity)
    if correlation_id:
        conditions.append(LogEvent.correlation_id == correlation_id)
    if source_ip:
        conditions.append(LogEvent.source_ip == source_ip)
    if time_from:
        from dateutil import parser
        conditions.append(LogEvent.time_generated >= parser.isoparse(time_from))
    if time_to:
        from dateutil import parser
        conditions.append(LogEvent.time_generated <= parser.isoparse(time_to))

    # Count
    count_q = select(func.count(LogEvent.id))
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    # Query
    query = select(LogEvent).order_by(LogEvent.time_generated.desc())
    if conditions:
        query = query.where(and_(*conditions))
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()

    return LogEventListResponse(
        items=[LogEventResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/schemas")
async def list_schemas(current_user: User = Depends(get_current_active_user)):
    """List supported log schema types."""
    return {"schemas": get_supported_schemas()}


@router.get("/{event_id}", response_model=LogEventDetailResponse)
async def get_log_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a single log event with full raw data."""
    result = await db.execute(select(LogEvent).where(LogEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise NotFoundError("Log event not found")
    return event
