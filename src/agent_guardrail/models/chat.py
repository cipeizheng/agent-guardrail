"""Provider-neutral chat models used at an LLM enforcement boundary."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from agent_guardrail.models.core import ToolCall


class ChatModel(BaseModel):
    """Base for closed, provider-neutral chat schemas."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ChatRole(StrEnum):
    """Roles needed by the framework-neutral model/tool loop."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ChatMessage(ChatModel):
    """A normalized message exchanged by an agent and an LLM client."""

    role: ChatRole
    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None

    @model_validator(mode="after")
    def validate_role_fields(self) -> Self:
        if self.role in {ChatRole.SYSTEM, ChatRole.USER}:
            if self.content is None:
                raise ValueError("system and user messages require content")
            if self.tool_calls or self.tool_call_id is not None:
                raise ValueError("system and user messages cannot contain tool fields")
        elif self.role is ChatRole.ASSISTANT:
            if self.content is None and not self.tool_calls:
                raise ValueError("an assistant message requires content or tool calls")
            if self.tool_call_id is not None:
                raise ValueError("assistant messages cannot reference a tool call result")
        elif self.role is ChatRole.TOOL:
            if self.content is None or self.tool_call_id is None:
                raise ValueError("tool messages require content and tool_call_id")
            if self.tool_calls:
                raise ValueError("tool messages cannot create tool calls")
        return self


class ToolDefinition(ChatModel):
    """A provider-neutral function tool declaration and its argument schema."""

    name: str = Field(min_length=1)
    description: str | None = None
    parameters: dict[str, JsonValue] = Field(default_factory=dict)


class ModelRequest(ChatModel):
    """A provider-neutral request used by protocol adapters."""

    model: str | None = None
    messages: tuple[ChatMessage, ...] = Field(min_length=1)
    tools: tuple[ToolDefinition, ...] = ()

    @model_validator(mode="after")
    def validate_tools(self) -> Self:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("model request tool names must be unique")
        return self


class ModelResponse(ChatModel):
    """A normalized assistant response containing text, tool calls, or both."""

    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if self.content is None and not self.tool_calls:
            raise ValueError("a model response requires content or tool calls")
        call_ids = [call.call_id for call in self.tool_calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("model response tool call IDs must be unique")
        return self
