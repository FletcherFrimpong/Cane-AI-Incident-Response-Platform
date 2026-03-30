import uuid
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin, TimestampMixin


class LogEvent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "log_events"

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False)
    time_generated: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_system: Mapped[str] = mapped_column(String(255), nullable=False)
    log_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    schema_id: Mapped[str] = mapped_column(String(50), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident | None"] = relationship(back_populates="log_events")

    __table_args__ = (
        Index("ix_log_events_tenant_time", "tenant_id", "time_generated"),
        Index("ix_log_events_type_time", "log_type", "time_generated"),
        Index("ix_log_events_raw_data", "raw_data", postgresql_using="gin"),
    )
