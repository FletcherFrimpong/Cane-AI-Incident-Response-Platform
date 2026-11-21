"""Anthropic Claude LLM provider."""

import anthropic

from app.ai.provider_base import LLMRefusalError, LLMResponse

# Opt in to server-side refusal fallback: if a safety classifier declines the request
# (security logs describing malware can trip one), the API re-runs it on a fallback
# model inside the same call instead of returning nothing.
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ClaudeProvider:
    provider_name = "claude"

    def __init__(self, api_key: str):
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.default_model = "claude-opus-5-5"

    async def _create(self, system_prompt: str, user_prompt: str, model: str | None, max_tokens: int) -> LLMResponse:
        # Current Claude models reject sampling parameters (temperature/top_p/top_k)
        # and always think adaptively, so neither is sent. Thinking shares the
        # max_tokens budget with the answer, hence the generous default.
        response = await self.client.messages.create(
            model=model or self.default_model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            extra_headers={"anthropic-beta": _FALLBACK_BETA},
            extra_body={"fallbacks": "default"},
        )
        if response.stop_reason == "refusal":
            raise LLMRefusalError("Claude declined to analyse this content")

        # The reply can start with thinking blocks; the answer is the text block(s).
        text = "".join(block.text for block in response.content if block.type == "text")
        if not text.strip():
            raise ValueError(f"Claude returned no text (stop_reason={response.stop_reason})")
        return LLMResponse(
            content=text,
            model=response.model,
            provider="claude",
            prompt_tokens=response.usage.input_tokens,
            completion_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
        )

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,  # accepted for interface parity; not sent (see _create)
        max_tokens: int = 16000,
    ) -> LLMResponse:
        return await self._create(system_prompt, user_prompt, model, max_tokens)

    async def analyze_with_json(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 16000,
    ) -> LLMResponse:
        return await self._create(
            system_prompt + "\n\nYou MUST respond with valid JSON only. No other text.",
            user_prompt, model, max_tokens,
        )
