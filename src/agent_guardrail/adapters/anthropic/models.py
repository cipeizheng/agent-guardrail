"""Closed schemas for the supported Anthropic Messages API subset."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class AnthropicModel(BaseModel):
    """Reject unknown provider fields instead of silently skipping content."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TextBlock(AnthropicModel):
    type: Literal["text"]
    text: str
    citations: None = None


class DirectCaller(AnthropicModel):
    type: Literal["direct"]


class ToolUseBlock(AnthropicModel):
    type: Literal["tool_use"]
    id: str = Field(min_length=1)
    name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    input: dict[str, JsonValue]
    caller: DirectCaller | None = None
    toolset_name: None = None


class ToolResultBlock(AnthropicModel):
    type: Literal["tool_result"]
    tool_use_id: str = Field(min_length=1)
    content: str | tuple[TextBlock, ...] | None = None
    is_error: bool = False


UserContentBlock = Annotated[TextBlock | ToolResultBlock, Field(discriminator="type")]
AssistantContentBlock = Annotated[TextBlock | ToolUseBlock, Field(discriminator="type")]


class UserMessage(AnthropicModel):
    role: Literal["user"]
    content: str | tuple[UserContentBlock, ...]

    @model_validator(mode="after")
    def validate_tool_result_order(self) -> Self:
        if isinstance(self.content, tuple):
            seen_text = False
            for block in self.content:
                if isinstance(block, TextBlock):
                    seen_text = True
                elif seen_text:
                    raise ValueError("tool_result blocks must precede text blocks")
        return self


class AssistantMessage(AnthropicModel):
    role: Literal["assistant"]
    content: str | tuple[AssistantContentBlock, ...]

    @model_validator(mode="after")
    def validate_tool_use_ids(self) -> Self:
        if isinstance(self.content, tuple):
            ids = [block.id for block in self.content if isinstance(block, ToolUseBlock)]
            if len(ids) != len(set(ids)):
                raise ValueError("assistant tool_use IDs must be unique")
        return self


class SystemMessage(AnthropicModel):
    role: Literal["system"]
    content: str | tuple[TextBlock, ...]


Message = Annotated[
    UserMessage | AssistantMessage | SystemMessage,
    Field(discriminator="role"),
]


class Tool(AnthropicModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    description: str | None = None
    input_schema: dict[str, JsonValue]
    strict: bool | None = None
    type: Literal["custom"] | None = None


class AutoToolChoice(AnthropicModel):
    type: Literal["auto"]
    disable_parallel_tool_use: bool | None = None


class AnyToolChoice(AnthropicModel):
    type: Literal["any"]
    disable_parallel_tool_use: bool | None = None


class NoneToolChoice(AnthropicModel):
    type: Literal["none"]


class NamedToolChoice(AnthropicModel):
    type: Literal["tool"]
    name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    disable_parallel_tool_use: bool | None = None


ToolChoice = Annotated[
    AutoToolChoice | AnyToolChoice | NoneToolChoice | NamedToolChoice,
    Field(discriminator="type"),
]


class Metadata(AnthropicModel):
    user_id: str | None = None


class MessagesRequest(AnthropicModel):
    model: str = Field(min_length=1)
    max_tokens: int = Field(ge=1)
    messages: tuple[Message, ...] = Field(min_length=1)
    system: str | tuple[TextBlock, ...] | None = None
    tools: tuple[Tool, ...] = ()
    tool_choice: ToolChoice | None = None
    stream: bool = False
    temperature: float | None = Field(default=None, ge=0, le=1)
    top_p: float | None = Field(default=None, ge=0, le=1)
    top_k: int | None = Field(default=None, ge=0)
    stop_sequences: tuple[str, ...] = ()
    metadata: Metadata | None = None
    service_tier: Literal["auto", "standard_only"] | None = None

    @model_validator(mode="after")
    def validate_declared_tools(self) -> Self:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        if isinstance(self.tool_choice, NamedToolChoice) and self.tool_choice.name not in names:
            raise ValueError("tool_choice must name a declared tool")
        if self.tool_choice is not None and not self.tools:
            raise ValueError("tool_choice requires declared tools")
        return self


class Usage(AnthropicModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cache_creation_input_tokens: int | None = Field(default=None, ge=0)
    cache_read_input_tokens: int | None = Field(default=None, ge=0)
    inference_geo: str | None = None
    service_tier: Literal["standard", "priority", "batch"] | None = None
    cache_creation: CacheCreation | None = None
    output_tokens_details: OutputTokensDetails | None = None
    server_tool_use: None = None


class CacheCreation(AnthropicModel):
    ephemeral_1h_input_tokens: int = Field(ge=0)
    ephemeral_5m_input_tokens: int = Field(ge=0)


class OutputTokensDetails(AnthropicModel):
    thinking_tokens: int = Field(ge=0)


class MessagesResponse(AnthropicModel):
    id: str = Field(min_length=1)
    type: Literal["message"]
    role: Literal["assistant"]
    content: tuple[AssistantContentBlock, ...] = Field(min_length=1)
    model: str = Field(min_length=1)
    stop_reason: Literal[
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "tool_use",
        "pause_turn",
        "refusal",
        "model_context_window_exceeded",
    ]
    stop_sequence: str | None = None
    usage: Usage
    container: None = None
    stop_details: None = None


class MessageStartBody(AnthropicModel):
    id: str = Field(min_length=1)
    type: Literal["message"]
    role: Literal["assistant"]
    content: tuple[()] = ()
    model: str = Field(min_length=1)
    stop_reason: None
    stop_sequence: None
    usage: Usage
    container: None = None
    stop_details: None = None


class MessageStartEvent(AnthropicModel):
    type: Literal["message_start"]
    message: MessageStartBody


class ContentBlockStartEvent(AnthropicModel):
    type: Literal["content_block_start"]
    index: int = Field(ge=0)
    content_block: AssistantContentBlock


class TextDelta(AnthropicModel):
    type: Literal["text_delta"]
    text: str


class InputJsonDelta(AnthropicModel):
    type: Literal["input_json_delta"]
    partial_json: str


ContentDelta = Annotated[TextDelta | InputJsonDelta, Field(discriminator="type")]


class ContentBlockDeltaEvent(AnthropicModel):
    type: Literal["content_block_delta"]
    index: int = Field(ge=0)
    delta: ContentDelta


class ContentBlockStopEvent(AnthropicModel):
    type: Literal["content_block_stop"]
    index: int = Field(ge=0)


class MessageDeltaBody(AnthropicModel):
    stop_reason: Literal[
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "tool_use",
        "pause_turn",
        "refusal",
        "model_context_window_exceeded",
    ]
    stop_sequence: str | None = None
    container: None = None
    stop_details: None = None


class MessageDeltaUsage(AnthropicModel):
    output_tokens: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    cache_creation_input_tokens: int | None = Field(default=None, ge=0)
    cache_read_input_tokens: int | None = Field(default=None, ge=0)
    output_tokens_details: OutputTokensDetails | None = None
    server_tool_use: None = None


class MessageDeltaEvent(AnthropicModel):
    type: Literal["message_delta"]
    delta: MessageDeltaBody
    usage: MessageDeltaUsage | None = None


class PingEvent(AnthropicModel):
    type: Literal["ping"]


class MessageStopEvent(AnthropicModel):
    type: Literal["message_stop"]
