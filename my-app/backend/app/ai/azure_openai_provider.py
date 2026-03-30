"""Azure OpenAI LLM provider."""

from openai import AsyncAzureOpenAI
from app.ai.provider_base import LLMResponse


class AzureOpenAIProvider:
    provider_name = "azure_openai"

    def __init__(self, api_key: str, endpoint: str, api_version: str = "2024-06-01", deployment: str = "gpt-4o"):
        self.client = AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
        )
        self.default_model = deployment

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = await self.client.chat.completions.create(
            model=model or self.default_model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        choice = response.choices[0]
        usage = response.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model or self.default_model,
            provider="azure_openai",
            prompt_tokens=usage.prompt_tokens if usage else None,
            completion_tokens=usage.completion_tokens if usage else None,
            total_tokens=usage.total_tokens if usage else None,
        )

    async def analyze_with_json(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = await self.client.chat.completions.create(
            model=model or self.default_model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt + "\nRespond with valid JSON only."},
                {"role": "user", "content": user_prompt},
            ],
        )
        choice = response.choices[0]
        usage = response.usage
        return LLMResponse(
            content=choice.message.content or "",
            model=response.model or self.default_model,
            provider="azure_openai",
            prompt_tokens=usage.prompt_tokens if usage else None,
            completion_tokens=usage.completion_tokens if usage else None,
            total_tokens=usage.total_tokens if usage else None,
        )
