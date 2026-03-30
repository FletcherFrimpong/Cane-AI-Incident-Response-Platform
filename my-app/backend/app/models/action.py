import uuid
from datetime import datetime
from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models.base import Base, UUIDMixin, TimestampMixin


class ActionSource(str, enum.Enum):
    AUTO = "auto"
    ANALYST = "analyst"
    AI_RECOMMENDED = "ai_recommended"


class ActionStatus(str, enum.Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class ActionLog(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "action_logs"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    action_params: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    source: Mapped[ActionSource] = mapped_column(
        Enum(ActionSource, name="action_source"), nullable=False
    )
    status: Mapped[ActionStatus] = mapped_column(
        Enum(ActionStatus, name="action_status"), default=ActionStatus.PENDING_APPROVAL, nullable=False
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="action_logs")
