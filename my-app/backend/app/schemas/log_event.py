import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from pydantic import BaseModel, field_serializer


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
    source_ip: str | IPv4Address | IPv6Address | None
    destination_ip: str | IPv4Address | IPv6Address | None
    user_identity: str | None
    host: str | None
    incident_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_serializer("source_ip", "destination_ip")
    def serialize_ip(self, v: Any) -> str | None:
        if v is None:
            return None
        return str(v)


class LogEventDetailResponse(LogEventResponse):
    raw_data: dict

    model_config = {"from_attributes": True}


class LogEventListResponse(BaseModel):
    items: list[LogEventResponse]
    total: int
    page: int
    page_size: int
