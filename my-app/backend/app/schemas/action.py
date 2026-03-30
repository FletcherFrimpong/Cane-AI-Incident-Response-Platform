import uuid
from datetime import datetime
from pydantic import BaseModel
from app.models.action import ActionSource, ActionStatus


class ActionExecuteRequest(BaseModel):
    incident_id: uuid.UUID
    action_type: str
    action_params: dict | None = None


class ActionApproveRequest(BaseModel):
    notes: str | None = None


class ActionRejectRequest(BaseModel):
    reason: str


class ActionLogResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    action_type: str
    action_params: dict | None
    source: ActionSource
    status: ActionStatus
    requested_by: str
    approved_by: uuid.UUID | None
    executed_at: datetime | None
    result: dict | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
