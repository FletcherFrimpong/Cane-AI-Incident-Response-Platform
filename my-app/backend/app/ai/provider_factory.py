"""Factory for creating LLM provider instances based on user configuration."""

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
