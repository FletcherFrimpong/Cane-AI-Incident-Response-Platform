import uuid
from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import get_settings, Settings
from app.services.auth_service import decode_token, get_user_by_id
from app.models.user import User, UserRole
from app.exceptions import UnauthorizedError, ForbiddenError


async def get_session(session: AsyncSession = Depends(get_db)) -> AsyncSession:
    return session


def get_app_settings() -> Settings:
    return get_settings()


async def get_current_user(
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not authorization.startswith("Bearer "):
        raise UnauthorizedError("Invalid authorization header")
    token = authorization[7:]
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise UnauthorizedError("Invalid token type")
    user_id = uuid.UUID(payload["sub"])
    return await get_user_by_id(db, user_id)


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise UnauthorizedError("Account is deactivated")
    return current_user


def require_role(*roles: UserRole):
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise ForbiddenError(f"Requires one of: {', '.join(r.value for r in roles)}")
        return current_user
    return role_checker


require_admin = require_role(UserRole.ADMIN)
require_manager = require_role(UserRole.MANAGER, UserRole.ADMIN)
require_tier2 = require_role(UserRole.TIER2_ANALYST, UserRole.MANAGER, UserRole.ADMIN)
require_any_analyst = require_role(UserRole.TIER1_ANALYST, UserRole.TIER2_ANALYST, UserRole.MANAGER, UserRole.ADMIN)
