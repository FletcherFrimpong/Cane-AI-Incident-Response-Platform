import uuid
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_active_user, require_admin
from app.models.user import User
from app.models.integration import PlatformIntegration
from app.schemas.integration import (
    IntegrationCreate,
    IntegrationUpdate,
    IntegrationResponse,
    PlatformInfo,
    ConnectionTestResult,
)
from app.services.integration_service import (
    create_integration,
    test_integration_connection,
)
from app.services.encryption_service import encrypt_value
from app.integrations.registry import get_all_platform_info
from app.exceptions import NotFoundError

router = APIRouter()


@router.get("/platforms", response_model=list[PlatformInfo])
async def list_supported_platforms(
    current_user: User = Depends(get_current_active_user),
):
    """List all supported integration platforms and their required configuration."""
    return get_all_platform_info()


@router.get("/", response_model=list[IntegrationResponse])
async def list_integrations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all configured integrations (credentials masked)."""
    result = await db.execute(
        select(PlatformIntegration).order_by(PlatformIntegration.created_at.desc())
    )
    return result.scalars().all()


@router.post("/", response_model=IntegrationResponse, status_code=201)
async def add_integration(
    data: IntegrationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Add a new platform integration (admin only)."""
    integration = await create_integration(
        db=db,
        platform=data.platform,
        display_name=data.display_name,
        auth_type=data.auth_type.value,
        credentials=data.credentials,
        config=data.config,
        dry_run=data.dry_run,
        tenant_id=data.tenant_id,
        created_by=current_user.id,
    )
    return integration


@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise NotFoundError("Integration not found")
    return integration


@router.put("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: uuid.UUID,
    data: IntegrationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise NotFoundError("Integration not found")

    if data.display_name is not None:
        integration.display_name = data.display_name
    if data.credentials is not None:
        import json
        integration.encrypted_credentials = encrypt_value(json.dumps(data.credentials))
    if data.config is not None:
        integration.config = data.config
    if data.is_active is not None:
        integration.is_active = data.is_active
    if data.dry_run is not None:
        integration.dry_run = data.dry_run

    await db.flush()
    return integration


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise NotFoundError("Integration not found")
    await db.delete(integration)
    return {"detail": "Integration deleted"}


@router.post("/{integration_id}/test", response_model=ConnectionTestResult)
async def test_connection(
    integration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Test connection to the configured platform."""
    result = await test_integration_connection(db, integration_id)
    return ConnectionTestResult(**result)


@router.get("/{integration_id}/health")
async def get_health(
    integration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise NotFoundError("Integration not found")
    return {
        "health_status": integration.health_status.value,
        "last_health_check": str(integration.last_health_check) if integration.last_health_check else None,
    }
