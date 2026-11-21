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


def system_provider_configured() -> bool:
    """True when automated triage has something to call: a real key, or the mock in debug."""
    from app.config import get_settings
    settings = get_settings()
    if settings.auto_triage_provider == "mock":
        return settings.debug
    return bool(settings.auto_triage_api_key)


def get_system_provider() -> LLMProviderProtocol:
    """Get an LLM provider using system-level config (for automated triage, no user context)."""
    from app.config import get_settings
    settings = get_settings()

    provider_name = settings.auto_triage_provider
    if provider_name == "mock":
        # Rule-based stand-in for development and tests. Never available outside debug.
        if not settings.debug:
            raise ValidationError("The mock provider is only available when CANE_DEBUG=true")
        from app.ai.mock_provider import MockProvider
        return MockProvider()

    if not settings.auto_triage_api_key:
        raise NotFoundError(
            "No system API key configured. Set CANE_AUTO_TRIAGE_API_KEY environment variable."
        )

    api_key = settings.auto_triage_api_key

    if provider_name == "claude":
        return ClaudeProvider(api_key=api_key)
    elif provider_name == "openai":
        return OpenAIProvider(api_key=api_key)
    elif provider_name == "azure_openai":
        if not settings.auto_triage_azure_endpoint:
            raise ValidationError(
                "Azure OpenAI needs an endpoint. Set CANE_AUTO_TRIAGE_AZURE_ENDPOINT."
            )
        return AzureOpenAIProvider(api_key=api_key, endpoint=settings.auto_triage_azure_endpoint)
    else:
        raise ValidationError(f"Unsupported auto-triage provider: {provider_name}")


async def get_provider_for_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    provider_name: str | None = None,
) -> LLMProviderProtocol:
    """Get an LLM provider for a user-triggered analysis.

    Order: the user's own key for the named provider (or their default / most recent
    key when none is named), then the system-level key if one is configured."""
    query = select(UserApiKey).where(UserApiKey.user_id == user_id)
    if provider_name:
        try:
            query = query.where(UserApiKey.provider == LLMProvider(provider_name))
        except ValueError:
            raise ValidationError(f"Unsupported provider: {provider_name}")
    # Default key first, then newest. A user may hold several keys per provider.
    query = query.order_by(UserApiKey.is_default.desc(), UserApiKey.created_at.desc()).limit(1)
    api_key_record = (await db.execute(query)).scalars().first()

    if not api_key_record:
        from app.config import get_settings
        settings = get_settings()
        if system_provider_configured() and provider_name in (None, settings.auto_triage_provider):
            return get_system_provider()
        raise NotFoundError(
            "No API key configured. Add an LLM API key in Settings → API Keys."
        )

    decrypted_key = decrypt_value(api_key_record.encrypted_key)

    if api_key_record.provider == LLMProvider.CLAUDE:
        return ClaudeProvider(api_key=decrypted_key)
    elif api_key_record.provider == LLMProvider.OPENAI:
        return OpenAIProvider(api_key=decrypted_key)
    elif api_key_record.provider == LLMProvider.AZURE_OPENAI:
        from app.config import get_settings
        endpoint = get_settings().auto_triage_azure_endpoint
        if not endpoint:
            raise ValidationError("Azure OpenAI needs an endpoint. Set CANE_AUTO_TRIAGE_AZURE_ENDPOINT.")
        return AzureOpenAIProvider(api_key=decrypted_key, endpoint=endpoint)
    else:
        raise ValidationError(f"Unsupported provider: {api_key_record.provider}")
