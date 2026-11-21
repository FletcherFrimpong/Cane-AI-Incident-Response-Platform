"""Service for managing platform integrations: CRUD, encryption, health checks."""

import json
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.integration import PlatformIntegration, HealthStatus
from app.services.encryption_service import encrypt_value, decrypt_value
from app.integrations.registry import get_integration_class, get_all_platform_info
from app.integrations.base_client import BaseIntegrationClient
from app.exceptions import NotFoundError, ValidationError

import uuid

logger = logging.getLogger("cane_ai.integrations")


async def create_integration(
    db: AsyncSession,
    platform: str,
    display_name: str,
    auth_type: str,
    credentials: dict,
    config: dict | None,
    dry_run: bool,
    tenant_id: str,
    created_by: uuid.UUID,
) -> PlatformIntegration:
    """Create a new platform integration with encrypted credentials."""
    cls = get_integration_class(platform)
    if not cls:
        raise ValidationError(f"Unsupported platform: {platform}. Supported: {list(get_all_platform_info())}")

    # Validate required credentials
    for required in cls.required_credentials:
        if required not in credentials:
            raise ValidationError(f"Missing required credential: {required}")

    encrypted = encrypt_value(json.dumps(credentials))

    integration = PlatformIntegration(
        tenant_id=tenant_id,
        platform=platform,
        display_name=display_name,
        auth_type=auth_type,
        encrypted_credentials=encrypted,
        config=config,
        is_active=True,
        dry_run=dry_run,
        health_status=HealthStatus.UNKNOWN,
        created_by=created_by,
    )
    db.add(integration)
    await db.flush()
    return integration


async def get_integration_client(
    db: AsyncSession,
    integration_id: uuid.UUID,
) -> BaseIntegrationClient:
    """Get an initialized integration client for a specific integration."""
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise NotFoundError("Integration not found")

    return _build_client(integration)


async def get_integration_client_by_platform(
    db: AsyncSession,
    platform: str,
    tenant_id: str = "default",
) -> BaseIntegrationClient:
    """Get the active integration client for a platform."""
    result = await db.execute(
        select(PlatformIntegration).where(
            PlatformIntegration.platform == platform,
            PlatformIntegration.tenant_id == tenant_id,
            PlatformIntegration.is_active == True,
        ).order_by(PlatformIntegration.created_at.desc()).limit(1)
    )
    integration = result.scalars().first()
    if not integration:
        raise NotFoundError(f"No active {platform} integration configured")

    return _build_client(integration)


async def active_clients(
    db: AsyncSession,
    *,
    action: str | None = None,
    enriches: str | None = None,
    context: str | None = None,
    category: str | None = None,
) -> list[BaseIntegrationClient]:
    """Clients for every active integration with the requested ability.

    action    a response action type the connector can execute (e.g. "block_ip")
    enriches  an IOC kind it can look up ("ip", "domain", "url", "file_hash")
    context   an entity kind it can describe ("user", "host")
    category  "notification", "ticketing", "source", ...

    Each client carries `.integration_id` and `.integration_name`. The caller closes them.
    An integration whose credentials cannot be decrypted is skipped, not fatal."""
    result = await db.execute(
        select(PlatformIntegration)
        .where(PlatformIntegration.is_active == True)
        .order_by(PlatformIntegration.created_at.asc())
    )
    clients: list[BaseIntegrationClient] = []
    for integration in result.scalars().all():
        cls = get_integration_class(integration.platform)
        if cls is None:
            continue
        if action is not None and action not in cls.actions:
            continue
        if enriches is not None and enriches not in cls.enriches:
            continue
        if context is not None and context not in cls.provides_context:
            continue
        if category is not None and cls.category != category:
            continue
        try:
            client = _build_client(integration)
        except Exception as e:  # noqa: BLE001 - bad key / corrupt credentials
            logger.error("Cannot build client for integration %s: %s", integration.display_name, e)
            continue
        client.integration_id = integration.id
        client.integration_name = integration.display_name
        clients.append(client)
    return clients


async def close_clients(clients: list[BaseIntegrationClient]) -> None:
    for client in clients:
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            pass


def _build_client(integration: PlatformIntegration) -> BaseIntegrationClient:
    """Build an integration client from a database record."""
    cls = get_integration_class(integration.platform)
    if not cls:
        raise ValidationError(f"Unsupported platform: {integration.platform}")

    credentials = json.loads(decrypt_value(integration.encrypted_credentials))
    return cls(
        credentials=credentials,
        config=integration.config,
        dry_run=integration.dry_run,
    )


async def test_integration_connection(
    db: AsyncSession,
    integration_id: uuid.UUID,
) -> dict:
    """Test connection for an integration."""
    client = await get_integration_client(db, integration_id)
    try:
        result = await client.test_connection()

        # Update health status
        integration_result = await db.execute(
            select(PlatformIntegration).where(PlatformIntegration.id == integration_id)
        )
        integration = integration_result.scalar_one()
        integration.health_status = HealthStatus.HEALTHY if result["success"] else HealthStatus.ERROR
        integration.last_health_check = datetime.now(timezone.utc)
        await db.flush()

        return result
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        await client.close()


async def check_all_integration_health(db: AsyncSession):
    """Check health of all active integrations (called by Celery beat)."""
    result = await db.execute(
        select(PlatformIntegration).where(PlatformIntegration.is_active == True)
    )
    integrations = result.scalars().all()

    for integration in integrations:
        try:
            client = _build_client(integration)
            health = await client.get_health()
            try:
                integration.health_status = HealthStatus(health.get("status", "unknown"))
            except ValueError:
                integration.health_status = HealthStatus.UNKNOWN
            integration.last_health_check = datetime.now(timezone.utc)
            await client.close()
        except Exception as e:
            integration.health_status = HealthStatus.ERROR
            integration.last_health_check = datetime.now(timezone.utc)
            logger.error("Health check failed for %s: %s", integration.display_name, e)

    await db.flush()
    return len(integrations)
