"""Safe conversion between Anthropic Messages payloads and canonical events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, NoReturn

from jsonschema import Draft202012Validator, SchemaError
from pydantic import ValidationError

from agent_guardrail.adapters.anthropic.models import (
    AssistantMessage,
    ContentBlockDeltaEvent,
    ContentBlockStartEvent,
    ContentBlockStopEvent,
    InputJsonDelta,
    MessageDeltaEvent,
    MessagesRequest,
    MessagesResponse,
    MessageStartEvent,
    MessageStopEvent,
    PingEvent,
    SystemMessage,
    TextBlock,
    TextDelta,
    ToolResultBlock,
    ToolUseBlock,
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


class AnthropicAdapterError(ProviderAdapterError):
    """A safe protocol error that never includes request or provider content."""


class AnthropicAdapter:
    """Parse a strict client-tool Messages API subset."""

    upstream_path = "v1/messages"

    def parse_request(self, payload: object) -> MessagesRequest:
        try:
            request = MessagesRequest.model_validate(payload)
        except ValidationError as exc:
            raise AnthropicAdapterError(
                "invalid_request",
                "The Anthropic Messages request is malformed or unsupported.",
            ) from exc
        self._validate_tool_schemas(request)
        return request

    def parse_response(self, payload: object) -> MessagesResponse:
        try:
            return MessagesResponse.model_validate(payload)
        except ValidationError as exc:
            raise AnthropicAdapterError(
                "invalid_upstream_response",
                "The upstream model returned an unsupported Anthropic response.",
            ) from exc

    def is_streaming(self, request: MessagesRequest) -> bool:
        return request.stream

    def request_to_canonical(self, request: MessagesRequest) -> ModelRequest:
        messages: list[ChatMessage] = []
        if request.system is not None:
            messages.append(
                ChatMessage(
                    role=ChatRole.SYSTEM,
                    content=self._text_content(request.system),
                )
            )
        for message in request.messages:
            messages.extend(self._message_to_canonical(message))
        return ModelRequest(
            model=request.model,
            messages=tuple(messages),
            tools=tuple(
                ToolDefinition(
                    name=tool.name,
                    description=tool.description,
                    parameters=tool.input_schema,
                )
                for tool in request.tools
            ),
        )

    def response_to_canonical(
        self,
        response: MessagesResponse,
        *,
        request: MessagesRequest,
    ) -> ModelResponse:
        calls = tuple(
            ToolCall(call_id=block.id, name=block.name, arguments=block.input)
            for block in response.content
            if isinstance(block, ToolUseBlock)
        )
        text = "".join(
            block.text for block in response.content if isinstance(block, TextBlock)
        )
        saw_text = any(isinstance(block, TextBlock) for block in response.content)
        self._validate_complete_output(
            calls,
            stop_reason=response.stop_reason,
            request=request,
        )
        return ModelResponse(content=text if saw_text else None, tool_calls=calls)

    def request_payload(self, request: MessagesRequest) -> dict[str, Any]:
        return request.model_dump(mode="json", exclude_none=True)

    def response_payload(self, response: MessagesResponse) -> dict[str, Any]:
        return response.model_dump(mode="json", exclude_none=True)

    def stream_decoder(self, request: MessagesRequest) -> AnthropicStreamDecoder:
        if not request.stream:
            raise AnthropicAdapterError(
                "invalid_request",
                "An Anthropic stream decoder requires stream=true.",
            )
        return AnthropicStreamDecoder(adapter=self, request=request)

    def _message_to_canonical(
        self,
        message: UserMessage | AssistantMessage | SystemMessage,
    ) -> list[ChatMessage]:
        if isinstance(message, SystemMessage):
            return [
                ChatMessage(
                    role=ChatRole.SYSTEM,
                    content=self._text_content(message.content),
                )
            ]
        if isinstance(message, AssistantMessage):
            if isinstance(message.content, str):
                return [ChatMessage(role=ChatRole.ASSISTANT, content=message.content)]
            calls = tuple(
                ToolCall(call_id=block.id, name=block.name, arguments=block.input)
                for block in message.content
                if isinstance(block, ToolUseBlock)
            )
            text = "".join(
                block.text for block in message.content if isinstance(block, TextBlock)
            )
            saw_text = any(isinstance(block, TextBlock) for block in message.content)
            return [
                ChatMessage(
                    role=ChatRole.ASSISTANT,
                    content=text if saw_text else None,
                    tool_calls=calls,
                )
            ]
        if isinstance(message.content, str):
            return [ChatMessage(role=ChatRole.USER, content=message.content)]
        canonical: list[ChatMessage] = []
        for block in message.content:
            if isinstance(block, ToolResultBlock):
                canonical.append(
                    ChatMessage(
                        role=ChatRole.TOOL,
                        content=self._tool_result_content(block),
                        tool_call_id=block.tool_use_id,
                    )
                )
        text = "".join(
            block.text for block in message.content if isinstance(block, TextBlock)
        )
        if any(isinstance(block, TextBlock) for block in message.content):
            canonical.append(ChatMessage(role=ChatRole.USER, content=text))
        return canonical

    @staticmethod
    def _text_content(content: str | tuple[TextBlock, ...]) -> str:
        if isinstance(content, str):
            return content
        return "".join(block.text for block in content)

    @staticmethod
    def _tool_result_content(block: ToolResultBlock) -> str:
        if block.content is None:
            return ""
        if isinstance(block.content, str):
            return block.content
        return "".join(item.text for item in block.content)

    @staticmethod
    def _validate_tool_schemas(request: MessagesRequest) -> None:
        for tool in request.tools:
            try:
                Draft202012Validator.check_schema(tool.input_schema)
            except SchemaError as exc:
                raise AnthropicAdapterError(
                    "invalid_tool_schema",
                    "A declared Anthropic tool contains an invalid JSON Schema.",
                ) from exc

    @staticmethod
    def _validate_complete_output(
        calls: tuple[ToolCall, ...],
        *,
        stop_reason: str,
        request: MessagesRequest,
    ) -> None:
        if stop_reason in {"max_tokens", "pause_turn", "model_context_window_exceeded"}:
            raise AnthropicAdapterError(
                "incomplete_upstream_response",
                "The Anthropic response stopped before a complete supported turn.",
            )
        if (stop_reason == "tool_use") != bool(calls):
            raise AnthropicAdapterError(
                "invalid_upstream_response",
                "The Anthropic response has an inconsistent tool_use stop reason.",
            )
        schemas = {tool.name: tool.input_schema for tool in request.tools}
        for call in calls:
            schema = schemas.get(call.name)
            if schema is None:
                raise AnthropicAdapterError(
                    "undeclared_tool_call",
                    "The upstream model called an Anthropic tool that was not declared.",
                )
            if next(Draft202012Validator(schema).iter_errors(call.arguments), None) is not None:
                raise AnthropicAdapterError(
                    "invalid_tool_arguments",
                    "Anthropic tool input does not match the declared schema.",
                )


@dataclass(slots=True)
class _ActiveBlock:
    index: int
    kind: str
    call_id: str | None = None
    name: str | None = None
    partial_json: str = ""


class AnthropicStreamDecoder:
    """Accumulate supported Anthropic SSE into guarded canonical prefixes."""

    def __init__(self, *, adapter: AnthropicAdapter, request: MessagesRequest) -> None:
        self._adapter = adapter
        self._request = request
        self._started = False
        self._identity: tuple[str, str] | None = None
        self._next_index = 0
        self._active: _ActiveBlock | None = None
        self._text = ""
        self._saw_text = False
        self._calls: list[ToolCall] = []
        self._stop_reason: str | None = None
        self._terminal = False

    def consume(self, event: ServerSentEvent) -> ProviderStreamUpdate:
        if self._terminal:
            self._raise_stream()
        if event.event is None:
            self._raise_stream()
        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError:
            self._raise_stream()
        if not isinstance(payload, dict) or payload.get("type") != event.event:
            self._raise_stream()

        if event.event == "message_start":
            parsed = self._parse(MessageStartEvent, payload)
            if self._started:
                self._raise_stream()
            self._started = True
            self._identity = (parsed.message.id, parsed.message.model)
            return self._held(event.event, parsed)
        if not self._started:
            self._raise_stream()
        if event.event == "ping":
            return self._held(event.event, self._parse(PingEvent, payload))
        if event.event == "content_block_start":
            parsed = self._parse(ContentBlockStartEvent, payload)
            if (
                self._active is not None
                or self._stop_reason is not None
                or parsed.index != self._next_index
            ):
                self._raise_stream()
            block = parsed.content_block
            if isinstance(block, TextBlock):
                if block.text:
                    self._raise_stream()
                self._active = _ActiveBlock(index=parsed.index, kind="text")
                self._saw_text = True
            else:
                if block.input:
                    self._raise_stream()
                self._active = _ActiveBlock(
                    index=parsed.index,
                    kind="tool_use",
                    call_id=block.id,
                    name=block.name,
                )
            return self._held(event.event, parsed)
        if event.event == "content_block_delta":
            parsed = self._parse(ContentBlockDeltaEvent, payload)
            active = self._matching_active(parsed.index)
            if isinstance(parsed.delta, TextDelta):
                if active.kind != "text":
                    self._raise_stream()
                self._text += parsed.delta.text
                safe_event = self._safe_event(event.event, parsed)
                if parsed.delta.text:
                    return ProviderStreamUpdate(
                        release=StreamRelease.GUARD,
                        output=self._canonical_output(),
                        event=safe_event,
                    )
                return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
            if active.kind != "tool_use" or not isinstance(parsed.delta, InputJsonDelta):
                self._raise_stream()
            active.partial_json += parsed.delta.partial_json
            return self._held(event.event, parsed)
        if event.event == "content_block_stop":
            parsed = self._parse(ContentBlockStopEvent, payload)
            active = self._matching_active(parsed.index)
            self._active = None
            self._next_index += 1
            safe_event = self._safe_event(event.event, parsed)
            if active.kind == "text":
                return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
            try:
                arguments = json.loads(active.partial_json or "{}")
            except json.JSONDecodeError:
                raise AnthropicAdapterError(
                    "invalid_tool_arguments_json",
                    "Anthropic streamed tool input must be a JSON object.",
                ) from None
            if not isinstance(arguments, dict) or active.call_id is None or active.name is None:
                self._raise_stream()
            self._calls.append(
                ToolCall(call_id=active.call_id, name=active.name, arguments=arguments)
            )
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=self._canonical_output(),
                event=safe_event,
            )
        if event.event == "message_delta":
            parsed = self._parse(MessageDeltaEvent, payload)
            if self._active is not None or self._stop_reason is not None:
                self._raise_stream()
            stop_reason = parsed.delta.stop_reason
            self._stop_reason = stop_reason
            self._adapter._validate_complete_output(
                tuple(self._calls),
                stop_reason=stop_reason,
                request=self._request,
            )
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=self._canonical_output(),
                event=self._safe_event(event.event, parsed),
            )
        if event.event == "message_stop":
            parsed = self._parse(MessageStopEvent, payload)
            if self._active is not None or self._stop_reason is None:
                self._raise_stream()
            self._terminal = True
            return ProviderStreamUpdate(
                release=StreamRelease.FINAL,
                output=self._canonical_output(),
                event=self._safe_event(event.event, parsed),
            )
        self._raise_stream()

    def finish(self) -> None:
        if not self._terminal:
            raise AnthropicAdapterError(
                "upstream_incomplete_stream",
                "The Anthropic stream ended before message_stop.",
            )

    def error_event(self, *, code: str, message: str) -> ServerSentEvent:
        return ServerSentEvent(
            event="error",
            data=json.dumps(
                {
                    "type": "error",
                    "error": {
                        "type": "guardrail_error",
                        "code": code,
                        "message": message,
                    },
                },
                separators=(",", ":"),
            ),
        )

    def _canonical_output(self) -> ModelResponse:
        try:
            output = ModelResponse(
                content=self._text if self._saw_text else None,
                tool_calls=tuple(self._calls),
            )
        except ValidationError:
            raise AnthropicAdapterError(
                "invalid_upstream_stream",
                "The Anthropic stream contains no supported output.",
            ) from None
        if self._calls:
            self._adapter._validate_complete_output(
                tuple(self._calls),
                stop_reason="tool_use",
                request=self._request,
            )
        return output

    def _matching_active(self, index: int) -> _ActiveBlock:
        if self._active is None or self._active.index != index:
            self._raise_stream()
        return self._active

    @staticmethod
    def _parse(model: Any, payload: dict[str, Any]) -> Any:
        try:
            return model.model_validate(payload)
        except ValidationError:
            raise AnthropicAdapterError(
                "invalid_upstream_stream",
                "The upstream model returned an unsupported Anthropic stream event.",
            ) from None

    @classmethod
    def _held(cls, event_name: str, parsed: Any) -> ProviderStreamUpdate:
        return ProviderStreamUpdate(
            release=StreamRelease.HOLD,
            event=cls._safe_event(event_name, parsed),
        )

    @staticmethod
    def _safe_event(event_name: str, parsed: Any) -> ServerSentEvent:
        return ServerSentEvent(
            event=event_name,
            data=json.dumps(
                parsed.model_dump(mode="json", exclude_none=True),
                separators=(",", ":"),
            ),
        )

    @staticmethod
    def _raise_stream() -> NoReturn:
        raise AnthropicAdapterError(
            "invalid_upstream_stream",
            "The upstream model returned an invalid Anthropic stream sequence.",
        )
