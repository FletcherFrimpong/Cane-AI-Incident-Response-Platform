import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel
from app.models.integration import AuthType, HealthStatus


class IntegrationCreate(BaseModel):
    platform: str
    display_name: str
    auth_type: AuthType
    credentials: dict[str, Any]
    config: dict[str, Any] | None = None
    dry_run: bool = False
    tenant_id: str = "default"


class IntegrationUpdate(BaseModel):
    display_name: str | None = None
    credentials: dict[str, Any] | None = None
    config: dict[str, Any] | None = None
    is_active: bool | None = None
    dry_run: bool | None = None


class IntegrationResponse(BaseModel):
    id: uuid.UUID
    tenant_id: str
    platform: str
    display_name: str
    auth_type: AuthType
    config: dict | None
    is_active: bool
    dry_run: bool
    health_status: HealthStatus
    last_health_check: datetime | None
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PlatformInfo(BaseModel):
    platform: str
    display_name: str
    description: str
    auth_type: AuthType
    required_credentials: list[str]
    optional_config: list[str]
    capabilities: list[str]


class ConnectionTestResult(BaseModel):
    success: bool
    message: str
    details: dict | None = None
