import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr
from app.models.user import UserRole, LLMProvider


class UserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None


class UserRoleUpdate(BaseModel):
    role: UserRole


class ApiKeyCreate(BaseModel):
    provider: LLMProvider
    api_key: str
    label: str
    is_default: bool = False


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    provider: LLMProvider
    label: str
    is_default: bool
    masked_key: str
    created_at: datetime

    model_config = {"from_attributes": True}
