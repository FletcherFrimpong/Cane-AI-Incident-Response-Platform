import uuid
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_admin
from app.models.user import User, UserApiKey
from app.schemas.user import UserResponse, UserUpdate, UserRoleUpdate, ApiKeyCreate, ApiKeyResponse
from app.services.encryption_service import encrypt_value, decrypt_value
from app.exceptions import NotFoundError

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_me(
    update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    if update.full_name is not None:
        current_user.full_name = update.full_name
    if update.email is not None:
        current_user.email = update.email
    await db.flush()
    return current_user


@router.get("/", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.put("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: uuid.UUID,
    role_update: UserRoleUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise NotFoundError("User not found")
    user.role = role_update.role
    await db.flush()
    return user


@router.post("/me/api-keys", response_model=ApiKeyResponse)
async def add_api_key(
    key_data: ApiKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    encrypted = encrypt_value(key_data.api_key)
    api_key = UserApiKey(
        user_id=current_user.id,
        provider=key_data.provider,
        encrypted_key=encrypted,
        label=key_data.label,
        is_default=key_data.is_default,
    )
    db.add(api_key)
    await db.flush()

    masked = key_data.api_key[:8] + "..." + key_data.api_key[-4:]
    return ApiKeyResponse(
        id=api_key.id,
        provider=api_key.provider,
        label=api_key.label,
        is_default=api_key.is_default,
        masked_key=masked,
        created_at=api_key.created_at,
    )


@router.get("/me/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.user_id == current_user.id)
    )
    keys = result.scalars().all()
    response = []
    for key in keys:
        decrypted = decrypt_value(key.encrypted_key)
        masked = decrypted[:8] + "..." + decrypted[-4:] if len(decrypted) > 12 else "***"
        response.append(ApiKeyResponse(
            id=key.id,
            provider=key.provider,
            label=key.label,
            is_default=key.is_default,
            masked_key=masked,
            created_at=key.created_at,
        ))
    return response


@router.delete("/me/api-keys/{key_id}")
async def delete_api_key(
    key_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserApiKey).where(UserApiKey.id == key_id, UserApiKey.user_id == current_user.id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise NotFoundError("API key not found")
    await db.delete(key)
    return {"detail": "API key deleted"}
