import uuid
from datetime import datetime
from pydantic import BaseModel


class TriageRequest(BaseModel):
    incident_id: uuid.UUID
    provider: str = "claude"
    model: str | None = None


class TriageResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    provider: str
    model: str
    analysis_type: str
    output: dict
    confidence_score: float | None
    recommended_actions: list[dict] | None
    recommended_playbook_id: uuid.UUID | None
    prompt_tokens: int | None
    completion_tokens: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CorrelationRequest(BaseModel):
    correlation_id: str
    provider: str = "claude"
