"""Closed schemas for the supported OpenAI Responses API text/function subset."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class ResponsesModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ResponsesInputTextContent(ResponsesModel):
    """Text content parts emitted by Responses state owners during replay."""

    type: Literal["input_text", "output_text"]
    text: str


class ResponsesInputMessage(ResponsesModel):
    type: Literal["message"] = "message"
    role: Literal["user", "assistant", "system", "developer"]
    content: str | tuple[ResponsesInputTextContent, ...]
    # State owners may replay their stored assistant item with these
    # bookkeeping fields. They are accepted for protocol interoperation but
    # are not used as security identity by the Gateway.
    id: str | None = None
    status: Literal["in_progress", "completed", "incomplete"] | None = None


class ResponsesFunctionCallInput(ResponsesModel):
    type: Literal["function_call"]
    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: str = Field(min_length=1)
    id: str | None = None
    status: Literal["in_progress", "completed", "incomplete"] | None = None


class ResponsesFunctionOutputInput(ResponsesModel):
    type: Literal["function_call_output"]
    call_id: str = Field(min_length=1)
    output: str
    id: str | None = None
    name: str | None = None
    status: Literal["in_progress", "completed", "incomplete"] | None = None


ResponsesInputItem = (
    ResponsesInputMessage | ResponsesFunctionCallInput | ResponsesFunctionOutputInput
)


class ResponsesFunctionTool(ResponsesModel):
    type: Literal["function"]
    name: str = Field(min_length=1)
    description: str | None = None
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    strict: bool | None = None


class ResponsesNamedToolChoice(ResponsesModel):
    type: Literal["function"]
    name: str = Field(min_length=1)


class ResponsesStreamOptions(ResponsesModel):
    include_obfuscation: bool | None = None


class ResponsesRequest(ResponsesModel):
    model: str = Field(min_length=1)
    input: str | tuple[ResponsesInputItem, ...]
    previous_response_id: str | None = Field(default=None, min_length=1)
    instructions: str | None = None
    tools: tuple[ResponsesFunctionTool, ...] = ()
    tool_choice: Literal["none", "auto", "required"] | ResponsesNamedToolChoice | None = None
    parallel_tool_calls: bool | None = None
    max_output_tokens: int | None = Field(default=None, ge=1)
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    store: bool | None = None
    stream: bool = False
    stream_options: ResponsesStreamOptions | None = None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        if isinstance(self.tool_choice, ResponsesNamedToolChoice):
            if self.tool_choice.name not in set(names):
                raise ValueError("tool_choice must name a declared tool")
        if self.stream_options is not None and not self.stream:
            raise ValueError("stream_options requires stream=true")
        return self


class ResponsesOutputText(ResponsesModel):
    type: Literal["output_text"]
    text: str
    annotations: tuple[JsonValue, ...] = ()
    logprobs: tuple[JsonValue, ...] | None = None


class ResponsesRefusal(ResponsesModel):
    type: Literal["refusal"]
    refusal: str


ResponsesOutputContent = Annotated[
    ResponsesOutputText | ResponsesRefusal,
    Field(discriminator="type"),
]


class ResponsesOutputMessage(ResponsesModel):
    type: Literal["message"]
    id: str = Field(min_length=1)
    role: Literal["assistant"]
    status: Literal["in_progress", "completed", "incomplete"]
    content: tuple[ResponsesOutputContent, ...]
    phase: Literal["commentary", "final_answer"] | None = None


class ResponsesFunctionCall(ResponsesModel):
    type: Literal["function_call"]
    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: str
    id: str | None = None
    status: Literal["in_progress", "completed", "incomplete"] | None = None
    caller: JsonValue | None = None
    namespace: str | None = None


ResponsesOutputItem = Annotated[
    ResponsesOutputMessage | ResponsesFunctionCall,
    Field(discriminator="type"),
]


class ResponsesResponse(ResponsesModel):
    id: str = Field(min_length=1)
    object: Literal["response"]
    created_at: float = Field(ge=0)
    model: str = Field(min_length=1)
    output: tuple[ResponsesOutputItem, ...]
    status: (
        Literal[
            "completed",
            "failed",
            "in_progress",
            "cancelled",
            "queued",
            "incomplete",
        ]
        | None
    ) = None
    background: bool | None = None
    completed_at: float | None = None
    context_management: JsonValue | None = None
    conversation: JsonValue | None = None
    error: JsonValue | None = None
    incomplete_details: JsonValue | None = None
    instructions: JsonValue | None = None
    max_output_tokens: int | None = None
    max_tool_calls: int | None = None
    metadata: JsonValue | None = None
    moderation: JsonValue | None = None
    parallel_tool_calls: bool | None = None
    previous_response_id: str | None = None
    prompt: JsonValue | None = None
    prompt_cache_key: str | None = None
    prompt_cache_options: JsonValue | None = None
    prompt_cache_retention: str | None = None
    reasoning: JsonValue | None = None
    safety_identifier: str | None = None
    service_tier: str | None = None
    store: bool | None = None
    temperature: float | None = None
    text: JsonValue | None = None
    tool_choice: JsonValue | None = None
    tools: JsonValue | None = None
    top_logprobs: int | None = None
    top_p: float | None = None
    truncation: str | None = None
    usage: JsonValue | None = None
    user: str | None = None
