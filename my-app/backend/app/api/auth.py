from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, RefreshRequest
from app.services.auth_service import (
    authenticate_user,
    register_user,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_user_by_id,
)
from app.exceptions import UnauthorizedError

router = APIRouter()


@router.post("/register", response_model=TokenResponse)
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    user = await register_user(db, request.email, request.password, request.full_name, request.role)
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, request.email, request.password)
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(request.refresh_token)
    if payload.get("type") != "refresh":
        raise UnauthorizedError("Invalid refresh token")
    import uuid
    user = await get_user_by_id(db, uuid.UUID(payload["sub"]))
    access_token = create_access_token(user.id, user.role.value)
    new_refresh_token = create_refresh_token(user.id)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)
