"""Closed schemas for the non-streaming OpenAI Chat Completions subset."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class OpenAIModel(BaseModel):
    """Reject unknown provider fields instead of silently skipping unsafe content."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class FunctionCall(OpenAIModel):
    name: str = Field(min_length=1)
    arguments: str = Field(min_length=1)


class ToolCall(OpenAIModel):
    id: str = Field(min_length=1)
    type: Literal["function"]
    function: FunctionCall


class SystemMessage(OpenAIModel):
    role: Literal["system"]
    content: str
    name: str | None = None


class UserMessage(OpenAIModel):
    role: Literal["user"]
    content: str
    name: str | None = None


class AssistantMessage(OpenAIModel):
    role: Literal["assistant"]
    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    name: str | None = None

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        if self.content is None and not self.tool_calls:
            raise ValueError("assistant messages require content or tool calls")
        call_ids = [call.id for call in self.tool_calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("assistant tool call IDs must be unique")
        return self


class ToolMessage(OpenAIModel):
    role: Literal["tool"]
    content: str
    tool_call_id: str = Field(min_length=1)


ChatMessage = Annotated[
    SystemMessage | UserMessage | AssistantMessage | ToolMessage,
    Field(discriminator="role"),
]


class FunctionDefinition(OpenAIModel):
    name: str = Field(min_length=1)
    description: str | None = None
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    strict: bool | None = None


class FunctionTool(OpenAIModel):
    type: Literal["function"]
    function: FunctionDefinition


class NamedToolChoiceFunction(OpenAIModel):
    name: str = Field(min_length=1)


class NamedToolChoice(OpenAIModel):
    type: Literal["function"]
    function: NamedToolChoiceFunction


class ResponseFormat(OpenAIModel):
    type: Literal["text", "json_object"]


class ChatCompletionRequest(OpenAIModel):
    """Supported request fields; streaming and multiple choices are intentionally excluded."""

    model: str = Field(min_length=1)
    messages: tuple[ChatMessage, ...] = Field(min_length=1)
    tools: tuple[FunctionTool, ...] = ()
    tool_choice: Literal["none", "auto", "required"] | NamedToolChoice | None = None
    parallel_tool_calls: bool | None = None
    response_format: ResponseFormat | None = None
    stream: Literal[False] = False
    n: Literal[1] = 1
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    max_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    stop: str | tuple[str, ...] | None = None
    seed: int | None = None
    user: str | None = None

    @model_validator(mode="after")
    def validate_declared_tools(self) -> Self:
        names = [tool.function.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        if isinstance(self.tool_choice, NamedToolChoice):
            if self.tool_choice.function.name not in set(names):
                raise ValueError("tool_choice must name a declared tool")
        return self


class ResponseAssistantMessage(OpenAIModel):
    role: Literal["assistant"]
    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    refusal: str | None = None

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        if self.content is None and not self.tool_calls and self.refusal is None:
            raise ValueError("assistant response requires content, refusal, or tool calls")
        call_ids = [call.id for call in self.tool_calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("response tool call IDs must be unique")
        return self


class ChatCompletionChoice(OpenAIModel):
    index: Literal[0]
    message: ResponseAssistantMessage
    finish_reason: str | None
    logprobs: dict[str, JsonValue] | None = None


class ChatCompletionResponse(OpenAIModel):
    id: str = Field(min_length=1)
    object: Literal["chat.completion"]
    created: int = Field(ge=0)
    model: str = Field(min_length=1)
    choices: tuple[ChatCompletionChoice, ...] = Field(min_length=1, max_length=1)
    usage: dict[str, JsonValue] | None = None
    service_tier: str | None = None
    system_fingerprint: str | None = None
