import uuid
from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models.base import Base, UUIDMixin, TimestampMixin


class PlaybookFramework(str, enum.Enum):
    NIST_800_61 = "nist_800_61"
    SANS = "sans"
    CUSTOM = "custom"


class PlaybookPhase(str, enum.Enum):
    PREPARATION = "preparation"
    DETECTION_ANALYSIS = "detection_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"


class StepType(str, enum.Enum):
    AUTOMATED = "automated"
    HUMAN_DECISION = "human_decision"
    HUMAN_ACTION = "human_action"
    INFO = "info"


class Playbook(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "playbooks"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework: Mapped[PlaybookFramework] = mapped_column(
        Enum(PlaybookFramework, name="playbook_framework"), default=PlaybookFramework.NIST_800_61, nullable=False
    )
    attack_types: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    steps: Mapped[list["PlaybookStep"]] = relationship(back_populates="playbook", cascade="all, delete-orphan", order_by="PlaybookStep.step_order")
    incidents: Mapped[list["Incident"]] = relationship(back_populates="playbook")


class PlaybookStep(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "playbook_steps"

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[PlaybookPhase] = mapped_column(
        Enum(PlaybookPhase, name="playbook_phase"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    step_type: Mapped[StepType] = mapped_column(
        Enum(StepType, name="step_type"), nullable=False
    )
    auto_action_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    auto_action_params: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    playbook: Mapped["Playbook"] = relationship(back_populates="steps")
