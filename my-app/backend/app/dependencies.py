import hmac
import uuid
from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import get_settings, Settings
from app.services.auth_service import decode_token, get_user_by_id
from app.models.user import User, UserRole
from app.exceptions import UnauthorizedError, ForbiddenError, NotFoundError


async def get_session(session: AsyncSession = Depends(get_db, scope="function")) -> AsyncSession:
    return session


def get_app_settings() -> Settings:
    return get_settings()


async def _user_from_header(authorization: str | None, db: AsyncSession) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("Not authenticated")
    payload = decode_token(authorization[7:])
    if payload.get("type") != "access":
        raise UnauthorizedError("Invalid token type")
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except ValueError:
        raise UnauthorizedError("Invalid token")
    try:
        return await get_user_by_id(db, user_id)
    except NotFoundError:
        raise UnauthorizedError("Invalid token")


async def get_current_user(
    authorization: str | None = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> User:
    return await _user_from_header(authorization, db)


async def get_optional_user(
    authorization: str | None = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> User | None:
    """The caller if they sent a valid token, otherwise None (for endpoints open to both)."""
    if not authorization:
        return None
    user = await _user_from_header(authorization, db)
    return user if user.is_active else None


async def require_ingest_access(
    authorization: str | None = Header(None, alias="Authorization"),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db, scope="function"),
) -> str:
    """Log ingestion accepts either a signed-in user or the machine ingest key.
    Returns a label for whoever is sending."""
    settings = get_settings()
    if x_api_key is not None:
        if settings.ingest_api_key and hmac.compare_digest(x_api_key, settings.ingest_api_key):
            return "ingest-key"
        raise UnauthorizedError("Invalid ingest API key")
    user = await _user_from_header(authorization, db)
    if not user.is_active:
        raise UnauthorizedError("Account is deactivated")
    return user.email


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
