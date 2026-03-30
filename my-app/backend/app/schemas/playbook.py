import uuid
from datetime import datetime
from pydantic import BaseModel
from app.models.playbook import PlaybookFramework, PlaybookPhase, StepType


class PlaybookCreate(BaseModel):
    name: str
    description: str | None = None
    framework: PlaybookFramework = PlaybookFramework.CUSTOM
    attack_types: list[str] | None = None


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    framework: PlaybookFramework | None = None
    attack_types: list[str] | None = None
    is_active: bool | None = None


class PlaybookStepCreate(BaseModel):
    step_order: int
    phase: PlaybookPhase
    title: str
    description: str
    step_type: StepType
    auto_action_type: str | None = None
    auto_action_params: dict | None = None
    conditions: dict | None = None
    requires_approval: bool = False
    timeout_minutes: int | None = None


class PlaybookStepUpdate(BaseModel):
    step_order: int | None = None
    phase: PlaybookPhase | None = None
    title: str | None = None
    description: str | None = None
    step_type: StepType | None = None
    auto_action_type: str | None = None
    auto_action_params: dict | None = None
    conditions: dict | None = None
    requires_approval: bool | None = None
    timeout_minutes: int | None = None


class PlaybookStepResponse(BaseModel):
    id: uuid.UUID
    playbook_id: uuid.UUID
    step_order: int
    phase: PlaybookPhase
    title: str
    description: str
    step_type: StepType
    auto_action_type: str | None
    auto_action_params: dict | None
    conditions: dict | None
    requires_approval: bool
    timeout_minutes: int | None

    model_config = {"from_attributes": True}


class PlaybookResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    framework: PlaybookFramework
    attack_types: list[str] | None
    is_active: bool
    is_builtin: bool
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PlaybookDetailResponse(PlaybookResponse):
    steps: list[PlaybookStepResponse]

    model_config = {"from_attributes": True}
