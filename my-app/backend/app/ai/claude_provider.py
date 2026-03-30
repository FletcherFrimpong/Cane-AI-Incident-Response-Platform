"""Anthropic Claude LLM provider."""

import anthropic
from app.ai.provider_base import LLMProvider, LLMResponse


class ClaudeProvider:
    provider_name = "claude"

    def __init__(self, api_key: str):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.default_model = "claude-sonnet-4-20250514"

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = await self.client.messages.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return LLMResponse(
            content=response.content[0].text,
            model=response.model,
            provider="claude",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
        )

    async def analyze_with_json(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = await self.client.messages.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt + "\n\nYou MUST respond with valid JSON only. No other text.",
            messages=[{"role": "user", "content": user_prompt}],
        )
        return LLMResponse(
            content=response.content[0].text,
            model=response.model,
            provider="claude",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
        )
