import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
import enum

from app.models.base import Base, UUIDMixin, TimestampMixin


class AuthType(str, enum.Enum):
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    WEBHOOK = "webhook"


class HealthStatus(str, enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    UNKNOWN = "unknown"


class PlatformIntegration(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "platform_integrations"

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_type: Mapped[AuthType] = mapped_column(
        Enum(AuthType, name="auth_type"), nullable=False
    )
    encrypted_credentials: Mapped[str] = mapped_column(Text, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    health_status: Mapped[HealthStatus] = mapped_column(
        Enum(HealthStatus, name="health_status"), default=HealthStatus.UNKNOWN, nullable=False
    )
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
