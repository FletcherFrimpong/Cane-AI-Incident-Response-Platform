"""Base protocol and types for LLM providers."""

from typing import Protocol, AsyncIterator, runtime_checkable
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


@runtime_checkable
class LLMProvider(Protocol):
    provider_name: str

    async def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    async def analyze_with_json(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...
