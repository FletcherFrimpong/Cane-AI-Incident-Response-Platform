"""Factory for creating LLM provider instances based on user configuration."""

import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import UserApiKey, LLMProvider
from app.services.encryption_service import decrypt_value
from app.ai.claude_provider import ClaudeProvider
from app.ai.openai_provider import OpenAIProvider
from app.ai.azure_openai_provider import AzureOpenAIProvider
from app.ai.provider_base import LLMProvider as LLMProviderProtocol
from app.exceptions import NotFoundError, ValidationError

import uuid

logger = logging.getLogger("cane_ai.provider_factory")


def get_system_provider() -> LLMProviderProtocol:
    """Get an LLM provider using system-level config (for automated triage, no user context)."""
    from app.config import get_settings
    settings = get_settings()

    if not settings.auto_triage_api_key:
        raise NotFoundError(
            "No system API key configured. Set CANE_AUTO_TRIAGE_API_KEY environment variable."
        )

    provider_name = settings.auto_triage_provider
    api_key = settings.auto_triage_api_key

    if provider_name == "claude":
        return ClaudeProvider(api_key=api_key)
    elif provider_name == "openai":
        return OpenAIProvider(api_key=api_key)
    elif provider_name == "azure_openai":
        return AzureOpenAIProvider(api_key=api_key, endpoint="")
    else:
        raise ValidationError(f"Unsupported auto-triage provider: {provider_name}")


async def get_provider_for_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    provider_name: str | None = None,
) -> LLMProviderProtocol:
    """Get the LLM provider instance for a user, using their stored API key."""

    if provider_name:
        provider_enum = LLMProvider(provider_name)
        result = await db.execute(
            select(UserApiKey).where(
                UserApiKey.user_id == user_id,
                UserApiKey.provider == provider_enum,
            )
        )
    else:
        # Try default key first
        result = await db.execute(
            select(UserApiKey).where(
                UserApiKey.user_id == user_id,
                UserApiKey.is_default == True,
            )
        )

    api_key_record = result.scalar_one_or_none()

    if not api_key_record:
        # Fallback: get any key
        if not provider_name:
            result = await db.execute(
                select(UserApiKey).where(UserApiKey.user_id == user_id).limit(1)
            )
            api_key_record = result.scalar_one_or_none()

        if not api_key_record:
            raise NotFoundError(
                "No API key configured. Add an LLM API key in Settings → API Keys."
            )

    decrypted_key = decrypt_value(api_key_record.encrypted_key)

    if api_key_record.provider == LLMProvider.CLAUDE:
        return ClaudeProvider(api_key=decrypted_key)
    elif api_key_record.provider == LLMProvider.OPENAI:
        return OpenAIProvider(api_key=decrypted_key)
    elif api_key_record.provider == LLMProvider.AZURE_OPENAI:
        return AzureOpenAIProvider(api_key=decrypted_key, endpoint="")
    else:
        raise ValidationError(f"Unsupported provider: {api_key_record.provider}")
