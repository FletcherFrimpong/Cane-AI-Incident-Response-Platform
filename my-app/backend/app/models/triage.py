import uuid
from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin, TimestampMixin


class AiAnalysis(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ai_analyses"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)
    input_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    output: Mapped[dict] = mapped_column(JSONB, nullable=False)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommended_actions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    recommended_playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident"] = relationship(back_populates="ai_analyses")
