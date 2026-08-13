"""Safe conversion between OpenAI payloads and canonical guardrail events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, SchemaError
from pydantic import ValidationError

from agent_guardrail.adapters.openai.models import (
    AssistantMessage,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionStreamChunk,
    FunctionTool,
    SystemMessage,
    ToolMessage,
    UserMessage,
)
from agent_guardrail.adapters.protocols import ProviderAdapterError
from agent_guardrail.adapters.streaming import (
    ProviderStreamUpdate,
    ServerSentEvent,
    StreamRelease,
)
from agent_guardrail.models import (
    ChatMessage,
    ChatRole,
    ModelRequest,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


class OpenAIAdapterError(ProviderAdapterError):
    """A safe protocol error that never includes request or provider content."""


class OpenAIAdapter:
    """Parse a strict Chat Completions subset and validate function calls."""

    upstream_path = "chat/completions"

    def parse_request(self, payload: object) -> ChatCompletionRequest:
        try:
            request = ChatCompletionRequest.model_validate(payload)
        except ValidationError as exc:
            raise OpenAIAdapterError(
                "invalid_request",
                "The Chat Completions request is malformed or unsupported.",
            ) from exc
        self._validate_tool_schemas(request.tools)
        return request

    def parse_response(self, payload: object) -> ChatCompletionResponse:
        try:
            return ChatCompletionResponse.model_validate(payload)
        except ValidationError as exc:
            raise OpenAIAdapterError(
                "invalid_upstream_response",
                "The upstream model returned an unsupported response.",
            ) from exc

    def is_streaming(self, request: ChatCompletionRequest) -> bool:
        return request.stream

    def request_to_canonical(self, request: ChatCompletionRequest) -> ModelRequest:
        return ModelRequest(
            model=request.model,
            messages=tuple(self._message_to_canonical(message) for message in request.messages),
            tools=tuple(
                ToolDefinition(
                    name=tool.function.name,
                    description=tool.function.description,
                    parameters=tool.function.parameters,
                )
                for tool in request.tools
            ),
        )

    def response_to_canonical(
        self,
        response: ChatCompletionResponse,
        *,
        request: ChatCompletionRequest,
    ) -> ModelResponse:
        choice = response.choices[0]
        if choice.logprobs is not None:
            raise OpenAIAdapterError(
                "invalid_upstream_response",
                "The upstream model returned unsupported response metadata.",
            )
        message = choice.message
        schemas = {tool.function.name: tool.function.parameters for tool in request.tools}
        calls = tuple(self._tool_call_to_canonical(call) for call in message.tool_calls)

        self._validate_canonical_calls(calls, schemas=schemas)

        content = message.content if message.content is not None else message.refusal
        return ModelResponse(content=content, tool_calls=calls)

    def request_payload(self, request: ChatCompletionRequest) -> dict[str, Any]:
        """Return a normalized upstream payload with no Gateway-only fields."""

        return request.model_dump(mode="json", exclude_none=True)

    def response_payload(self, response: ChatCompletionResponse) -> dict[str, Any]:
        """Return a normalized OpenAI-compatible response."""

        return response.model_dump(mode="json", exclude_none=True)

    def stream_decoder(
        self,
        request: ChatCompletionRequest,
    ) -> OpenAIChatStreamDecoder:
        if not request.stream:
            raise OpenAIAdapterError(
                "invalid_request",
                "A stream decoder requires stream=true.",
            )
        return OpenAIChatStreamDecoder(adapter=self, request=request)

    def _message_to_canonical(
        self,
        message: SystemMessage | UserMessage | AssistantMessage | ToolMessage,
    ) -> ChatMessage:
        if isinstance(message, SystemMessage):
            return ChatMessage(role=ChatRole.SYSTEM, content=message.content)
        if isinstance(message, UserMessage):
            return ChatMessage(role=ChatRole.USER, content=message.content)
        if isinstance(message, ToolMessage):
            return ChatMessage(
                role=ChatRole.TOOL,
                content=message.content,
                tool_call_id=message.tool_call_id,
            )
        return ChatMessage(
            role=ChatRole.ASSISTANT,
            content=message.content,
            tool_calls=tuple(self._tool_call_to_canonical(call) for call in message.tool_calls),
        )

    def _tool_call_to_canonical(self, call: Any) -> ToolCall:
        try:
            arguments = json.loads(call.function.arguments)
        except (json.JSONDecodeError, TypeError) as exc:
            raise OpenAIAdapterError(
                "invalid_tool_arguments_json",
                "Tool arguments must be a JSON object.",
            ) from exc
        if not isinstance(arguments, dict):
            raise OpenAIAdapterError(
                "invalid_tool_arguments_json",
                "Tool arguments must be a JSON object.",
            )
        return ToolCall(
            call_id=call.id,
            name=call.function.name,
            arguments=arguments,
        )

    def _validate_tool_schemas(self, tools: tuple[FunctionTool, ...]) -> None:
        for tool in tools:
            try:
                Draft202012Validator.check_schema(tool.function.parameters)
            except SchemaError as exc:
                raise OpenAIAdapterError(
                    "invalid_tool_schema",
                    "A declared tool contains an invalid JSON Schema.",
                ) from exc

    @staticmethod
    def _validate_canonical_calls(
        calls: tuple[ToolCall, ...],
        *,
        schemas: dict[str, dict[str, Any]],
    ) -> None:
        for call in calls:
            schema = schemas.get(call.name)
            if schema is None:
                raise OpenAIAdapterError(
                    "undeclared_tool_call",
                    "The upstream model called a tool that was not declared in the request.",
                )
            validator = Draft202012Validator(schema)
            if next(validator.iter_errors(call.arguments), None) is not None:
                raise OpenAIAdapterError(
                    "invalid_tool_arguments",
                    "The upstream model returned arguments that do not match the tool schema.",
                )


@dataclass(slots=True)
class _PartialToolCall:
    call_id: str | None = None
    name: str | None = None
    arguments: str = ""


class OpenAIChatStreamDecoder:
    """Accumulate one-choice Chat Completions SSE into guarded canonical prefixes."""

    def __init__(self, *, adapter: OpenAIAdapter, request: ChatCompletionRequest) -> None:
        self._adapter = adapter
        self._schemas = {tool.function.name: tool.function.parameters for tool in request.tools}
        self._identity: tuple[str, int, str] | None = None
        self._content = ""
        self._refusal = ""
        self._tool_calls: dict[int, _PartialToolCall] = {}
        self._tools_finished = False
        self._terminal = False

    def consume(self, event: ServerSentEvent) -> ProviderStreamUpdate:
        if self._terminal:
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "The upstream model emitted data after the terminal event.",
            )
        if event.event is not None:
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "Chat Completions requires data-only SSE events.",
            )
        if event.data == "[DONE]":
            output = self._canonical_output()
            self._terminal = True
            return ProviderStreamUpdate(
                release=StreamRelease.FINAL,
                output=output,
                event=ServerSentEvent(data="[DONE]"),
            )
        try:
            payload = json.loads(event.data)
            chunk = ChatCompletionStreamChunk.model_validate(payload)
        except (json.JSONDecodeError, ValidationError):
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "The upstream model returned an unsupported stream event.",
            ) from None

        identity = (chunk.id, chunk.created, chunk.model)
        if self._identity is None:
            self._identity = identity
        elif self._identity != identity:
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "The upstream model changed stream identity.",
            )
        safe_event = ServerSentEvent(
            data=json.dumps(
                chunk.model_dump(
                    mode="json",
                    exclude_none=True,
                    exclude={"moderation"},
                ),
                separators=(",", ":"),
            )
        )
        if not chunk.choices:
            return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)

        choice = chunk.choices[0]
        if chunk.moderation is not None or choice.logprobs is not None:
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "The upstream model returned unsupported stream content.",
            )
        delta = choice.delta
        if delta.content is not None and delta.refusal is not None:
            self._raise_mixed_text()
        text_changed = bool(delta.content)
        refusal_changed = bool(delta.refusal)
        if delta.content is not None:
            if self._refusal:
                self._raise_mixed_text()
            self._content += delta.content
        if delta.refusal is not None:
            if self._content:
                self._raise_mixed_text()
            self._refusal += delta.refusal
        for tool_delta in delta.tool_calls or ():
            if self._tools_finished:
                raise OpenAIAdapterError(
                    "invalid_upstream_stream",
                    "The upstream model emitted tool data after completion.",
                )
            partial = self._tool_calls.setdefault(tool_delta.index, _PartialToolCall())
            if tool_delta.id is not None:
                if partial.call_id is not None and partial.call_id != tool_delta.id:
                    self._raise_tool_stream()
                partial.call_id = tool_delta.id
            function = tool_delta.function
            if function is not None:
                if function.name is not None:
                    if partial.name is not None and partial.name != function.name:
                        self._raise_tool_stream()
                    partial.name = function.name
                if function.arguments is not None:
                    partial.arguments += function.arguments

        finish_reason = choice.finish_reason
        if finish_reason == "tool_calls":
            self._tools_finished = True
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=self._canonical_output(),
                event=safe_event,
            )
        if finish_reason is not None:
            if self._tool_calls and not self._tools_finished:
                self._raise_tool_stream()
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=self._canonical_output(),
                event=safe_event,
            )
        if self._tool_calls:
            return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
        if text_changed or refusal_changed:
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=self._canonical_output(),
                event=safe_event,
            )
        return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)

    def finish(self) -> None:
        if not self._terminal:
            raise OpenAIAdapterError(
                "upstream_incomplete_stream",
                "The upstream model stream ended before [DONE].",
            )

    def error_event(self, *, code: str, message: str) -> ServerSentEvent:
        return ServerSentEvent(
            data=json.dumps(
                {"error": {"type": "guardrail_error", "code": code, "message": message}},
                separators=(",", ":"),
            )
        )

    def _canonical_output(self) -> ModelResponse:
        calls: list[ToolCall] = []
        if self._tool_calls:
            indexes = tuple(sorted(self._tool_calls))
            if indexes != tuple(range(len(indexes))):
                self._raise_tool_stream()
            for index in indexes:
                partial = self._tool_calls[index]
                if partial.call_id is None or partial.name is None:
                    self._raise_tool_stream()
                call_id = partial.call_id
                name = partial.name
                if call_id is None or name is None:  # Static narrowing after NoReturn helper.
                    raise AssertionError("unreachable")
                try:
                    arguments = json.loads(partial.arguments)
                except (json.JSONDecodeError, TypeError):
                    raise OpenAIAdapterError(
                        "invalid_tool_arguments_json",
                        "Tool arguments must be a JSON object.",
                    ) from None
                if not isinstance(arguments, dict):
                    raise OpenAIAdapterError(
                        "invalid_tool_arguments_json",
                        "Tool arguments must be a JSON object.",
                    )
                calls.append(
                    ToolCall(
                        call_id=call_id,
                        name=name,
                        arguments=arguments,
                    )
                )
        canonical_calls = tuple(calls)
        self._adapter._validate_canonical_calls(canonical_calls, schemas=self._schemas)
        content = self._content or self._refusal or None
        try:
            return ModelResponse(content=content, tool_calls=canonical_calls)
        except ValidationError:
            raise OpenAIAdapterError(
                "invalid_upstream_stream",
                "The upstream model stream contains no supported output.",
            ) from None

    @staticmethod
    def _raise_mixed_text() -> None:
        raise OpenAIAdapterError(
            "invalid_upstream_stream",
            "The upstream model mixed content and refusal streams.",
        )

    @staticmethod
    def _raise_tool_stream() -> None:
        raise OpenAIAdapterError(
            "invalid_upstream_stream",
            "The upstream model returned an invalid tool-call stream.",
        )
