"""Strict OpenAI Chat/Responses protocol models and canonical conversion."""

from agent_guardrail.adapters.openai.adapter import OpenAIAdapter, OpenAIAdapterError
from agent_guardrail.adapters.openai.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from agent_guardrail.adapters.openai.responses_adapter import (
    OpenAIResponsesAdapter,
    OpenAIResponsesAdapterError,
)
from agent_guardrail.adapters.openai.responses_models import (
    ResponsesRequest,
    ResponsesResponse,
)

__all__ = [
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "OpenAIAdapter",
    "OpenAIAdapterError",
    "OpenAIResponsesAdapter",
    "OpenAIResponsesAdapterError",
    "ResponsesRequest",
    "ResponsesResponse",
]
