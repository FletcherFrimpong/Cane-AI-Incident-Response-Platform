"""OpenAI LLM provider."""

from openai import AsyncOpenAI
from app.ai.provider_base import LLMResponse


class OpenAIProvider:
    provider_name = "openai"

    def __init__(self, api_key: str, base_url: str | None = None):
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = AsyncOpenAI(**kwargs)
        self.default_model = "gpt-4o"

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
            model=response.model,
            provider="openai",
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
            model=response.model,
            provider="openai",
            prompt_tokens=usage.prompt_tokens if usage else None,
            completion_tokens=usage.completion_tokens if usage else None,
            total_tokens=usage.total_tokens if usage else None,
        )
