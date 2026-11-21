import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_optional_user
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, RefreshRequest
from app.services.auth_service import (
    authenticate_user,
    register_user,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_user_by_id,
)
from app.exceptions import ForbiddenError, NotFoundError, UnauthorizedError

router = APIRouter()


@router.post("/register", response_model=TokenResponse)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db, scope="function"),
    caller: User | None = Depends(get_optional_user),
):
    """Create an account.

    - The first account ever created bootstraps the platform and becomes the admin.
    - An admin may create accounts with any role.
    - Anyone else may only self-register when CANE_ALLOW_SELF_REGISTRATION is on,
      and always as a tier-1 analyst: the role in the request is ignored.
    """
    user_count = (await db.execute(select(func.count(User.id)))).scalar() or 0

    if user_count == 0:
        role = UserRole.ADMIN.value
    elif caller is not None and caller.role == UserRole.ADMIN:
        role = request.role
    elif get_settings().allow_self_registration:
        role = UserRole.TIER1_ANALYST.value
    else:
        raise ForbiddenError("Registration is closed. Ask an administrator to create your account.")

    user = await register_user(db, request.email, request.password, request.full_name, role)
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db, scope="function")):
    user = await authenticate_user(db, request.email, request.password)
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: AsyncSession = Depends(get_db, scope="function")):
    payload = decode_token(request.refresh_token)
    if payload.get("type") != "refresh":
        raise UnauthorizedError("Invalid refresh token")
    try:
        user = await get_user_by_id(db, uuid.UUID(str(payload.get("sub"))))
    except (ValueError, NotFoundError):
        raise UnauthorizedError("Invalid refresh token")
    if not user.is_active:
        raise UnauthorizedError("Account is deactivated")
    access_token = create_access_token(user.id, user.role.value)
    new_refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)
