import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel


class LogEventIngest(BaseModel):
    schemaId: str
    data: dict[str, Any]


class LogEventBatchIngest(BaseModel):
    events: list[LogEventIngest]


class LogEventResponse(BaseModel):
    id: uuid.UUID
    tenant_id: str
    time_generated: datetime
    source_system: str
    log_type: str
    schema_id: str
    correlation_id: str | None
    severity: str
    summary: str | None
    source_ip: str | None
    destination_ip: str | None
    user_identity: str | None
    host: str | None
    incident_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class LogEventDetailResponse(LogEventResponse):
    raw_data: dict

    model_config = {"from_attributes": True}


class LogEventListResponse(BaseModel):
    items: list[LogEventResponse]
    total: int
    page: int
    page_size: int
