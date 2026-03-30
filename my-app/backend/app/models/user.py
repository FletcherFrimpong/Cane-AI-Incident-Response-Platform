import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.models.base import Base, UUIDMixin, TimestampMixin


class UserRole(str, enum.Enum):
    TIER1_ANALYST = "tier1_analyst"
    TIER2_ANALYST = "tier2_analyst"
    MANAGER = "manager"
    ADMIN = "admin"


class LLMProvider(str, enum.Enum):
    CLAUDE = "claude"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), default=UserRole.TIER1_ANALYST, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    api_keys: Mapped[list["UserApiKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    assigned_incidents: Mapped[list["Incident"]] = relationship(back_populates="assigned_user", foreign_keys="Incident.assigned_to")


class UserApiKey(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "user_api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[LLMProvider] = mapped_column(Enum(LLMProvider, name="llm_provider"), nullable=False)
    encrypted_key: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship(back_populates="api_keys")
