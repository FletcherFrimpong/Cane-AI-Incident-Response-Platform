import uuid
from datetime import datetime
from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models.base import Base, UUIDMixin, TimestampMixin


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGING = "triaging"
    AWAITING_ANALYST = "awaiting_analyst"
    IN_PROGRESS = "in_progress"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, name="incident_severity"), default=IncidentSeverity.MEDIUM, nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status"), default=IncidentStatus.NEW, nullable=False
    )
    attack_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True
    )
    current_playbook_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mitre_tactics: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    source_entities: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_user: Mapped["User | None"] = relationship(back_populates="assigned_incidents", foreign_keys=[assigned_to])
    playbook: Mapped["Playbook | None"] = relationship(back_populates="incidents")
    log_events: Mapped[list["LogEvent"]] = relationship(back_populates="incident")
    timeline_entries: Mapped[list["IncidentTimeline"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    ai_analyses: Mapped[list["AiAnalysis"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    action_logs: Mapped[list["ActionLog"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentTimeline(Base, UUIDMixin):
    __tablename__ = "incident_timeline"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extra_data: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="timeline_entries")
