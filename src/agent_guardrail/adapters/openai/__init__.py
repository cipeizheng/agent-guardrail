"""Strict OpenAI Chat Completions protocol models and canonical conversion."""

from agent_guardrail.adapters.openai.adapter import OpenAIAdapter, OpenAIAdapterError
from agent_guardrail.adapters.openai.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)

__all__ = [
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "OpenAIAdapter",
    "OpenAIAdapterError",
]
