"""Closed schemas for the supported OpenAI Chat Completions subset."""

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


class StreamOptions(OpenAIModel):
    include_usage: bool | None = None
    include_obfuscation: bool | None = None


class ChatCompletionRequest(OpenAIModel):
    """Supported request fields; multiple choices remain intentionally excluded."""

    model: str = Field(min_length=1)
    messages: tuple[ChatMessage, ...] = Field(min_length=1)
    tools: tuple[FunctionTool, ...] = ()
    tool_choice: Literal["none", "auto", "required"] | NamedToolChoice | None = None
    parallel_tool_calls: bool | None = None
    response_format: ResponseFormat | None = None
    stream: bool = False
    stream_options: StreamOptions | None = None
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
        if self.stream_options is not None and not self.stream:
            raise ValueError("stream_options requires stream=true")
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
    finish_reason: Literal["stop", "length", "tool_calls", "content_filter"] | None
    logprobs: dict[str, JsonValue] | None = None


class ChatTokenUsage(OpenAIModel):
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ChatCompletionResponse(OpenAIModel):
    id: str = Field(min_length=1)
    object: Literal["chat.completion"]
    created: int = Field(ge=0)
    model: str = Field(min_length=1)
    choices: tuple[ChatCompletionChoice, ...] = Field(min_length=1, max_length=1)
    usage: ChatTokenUsage | None = None
    service_tier: str | None = None
    system_fingerprint: str | None = None


class StreamFunctionDelta(OpenAIModel):
    name: str | None = None
    arguments: str | None = None


class StreamToolCallDelta(OpenAIModel):
    index: int = Field(ge=0)
    id: str | None = None
    type: Literal["function"] | None = None
    function: StreamFunctionDelta | None = None


class StreamChoiceDelta(OpenAIModel):
    role: Literal["assistant"] | None = None
    content: str | None = None
    refusal: str | None = None
    tool_calls: tuple[StreamToolCallDelta, ...] | None = None


class ChatCompletionStreamChoice(OpenAIModel):
    index: Literal[0]
    delta: StreamChoiceDelta
    finish_reason: Literal["stop", "length", "tool_calls", "content_filter"] | None = None
    logprobs: JsonValue | None = None


class ChatCompletionStreamChunk(OpenAIModel):
    id: str = Field(min_length=1)
    object: Literal["chat.completion.chunk"]
    created: int = Field(ge=0)
    model: str = Field(min_length=1)
    choices: tuple[ChatCompletionStreamChoice, ...] = Field(max_length=1)
    usage: ChatTokenUsage | None = None
    moderation: JsonValue | None = None
    service_tier: str | None = None
    system_fingerprint: str | None = None
