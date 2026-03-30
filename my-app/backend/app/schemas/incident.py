import uuid
from datetime import datetime
from pydantic import BaseModel
from app.models.incident import IncidentSeverity, IncidentStatus


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    attack_type: str | None = None
    tenant_id: str = "default"


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    attack_type: str | None = None


class IncidentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: str
    title: str
    description: str | None
    severity: IncidentSeverity
    status: IncidentStatus
    attack_type: str | None
    confidence_score: float | None
    correlation_id: str | None
    assigned_to: uuid.UUID | None
    playbook_id: uuid.UUID | None
    current_playbook_step: int | None
    mitre_tactics: dict | None
    mitre_techniques: dict | None
    source_entities: dict | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    items: list[IncidentResponse]
    total: int
    page: int
    page_size: int


class TimelineEntryResponse(BaseModel):
    id: uuid.UUID
    event_type: str
    actor: str
    description: str
    extra_data: dict | None
    timestamp: datetime

    model_config = {"from_attributes": True}


class IncidentAssign(BaseModel):
    user_id: uuid.UUID


class IncidentNote(BaseModel):
    content: str
