"""OpenAI Responses API conversion using the provider-neutral model boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Never, cast

from jsonschema import Draft202012Validator, SchemaError
from pydantic import JsonValue, ValidationError

from agent_guardrail.adapters.openai.responses_models import (
    ResponsesFunctionCall,
    ResponsesFunctionCallInput,
    ResponsesInputMessage,
    ResponsesOutputMessage,
    ResponsesOutputText,
    ResponsesRefusal,
    ResponsesRequest,
    ResponsesResponse,
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


class OpenAIResponsesAdapterError(ProviderAdapterError):
    """A safe Responses protocol error without request or provider content."""


class OpenAIResponsesAdapter:
    """Strict text and custom-function subset of the OpenAI Responses API."""

    upstream_path = "responses"

    def parse_request(self, payload: object) -> ResponsesRequest:
        try:
            request = ResponsesRequest.model_validate(payload)
        except ValidationError as exc:
            raise OpenAIResponsesAdapterError(
                "invalid_request",
                "The Responses request is malformed or unsupported.",
            ) from exc
        self._validate_tool_schemas(request)
        return request

    def request_to_canonical(self, request: ResponsesRequest) -> ModelRequest:
        messages: list[ChatMessage] = []
        if request.instructions is not None:
            messages.append(ChatMessage(role=ChatRole.SYSTEM, content=request.instructions))
        if isinstance(request.input, str):
            messages.append(ChatMessage(role=ChatRole.USER, content=request.input))
        else:
            calls: dict[str, ToolCall] = {}
            unresolved: set[str] = set()
            pending_calls: list[ToolCall] = []
            for item in request.input:
                if isinstance(item, ResponsesInputMessage):
                    if pending_calls or unresolved:
                        self._invalid_request_history()
                    messages.append(
                        ChatMessage(
                            role=self._role(item.role),
                            content=item.content,
                        )
                    )
                elif isinstance(item, ResponsesFunctionCallInput):
                    if unresolved and not pending_calls:
                        self._invalid_request_history()
                    call = self._canonical_call(
                        call_id=item.call_id,
                        name=item.name,
                        arguments=item.arguments,
                    )
                    if call.call_id in calls:
                        self._invalid_request_history()
                    calls[call.call_id] = call
                    unresolved.add(call.call_id)
                    pending_calls.append(call)
                else:
                    if pending_calls:
                        messages.append(
                            ChatMessage(
                                role=ChatRole.ASSISTANT,
                                tool_calls=tuple(pending_calls),
                            )
                        )
                        pending_calls.clear()
                    if item.call_id not in calls or item.call_id not in unresolved:
                        self._invalid_request_history()
                    call = calls[item.call_id]
                    if item.name is not None and item.name != call.name:
                        self._invalid_request_history()
                    messages.append(
                        ChatMessage(
                            role=ChatRole.TOOL,
                            content=item.output,
                            tool_call_id=item.call_id,
                        )
                    )
                    unresolved.remove(item.call_id)
            if pending_calls or unresolved:
                self._invalid_request_history()
        return ModelRequest(
            model=request.model,
            messages=tuple(messages),
            tools=tuple(
                ToolDefinition(
                    name=tool.name,
                    description=tool.description,
                    parameters=tool.parameters,
                )
                for tool in request.tools
            ),
        )

    def request_payload(self, request: ResponsesRequest) -> dict[str, Any]:
        return request.model_dump(mode="json", exclude_none=True)

    def is_streaming(self, request: ResponsesRequest) -> bool:
        return request.stream

    def parse_response(self, payload: object) -> ResponsesResponse:
        try:
            response = ResponsesResponse.model_validate(payload)
        except ValidationError as exc:
            raise OpenAIResponsesAdapterError(
                "invalid_upstream_response",
                "The upstream model returned an unsupported Responses payload.",
            ) from exc
        if response.status != "completed" or response.error is not None:
            raise OpenAIResponsesAdapterError(
                "invalid_upstream_response",
                "The upstream model response did not complete successfully.",
            )
        return response

    def response_to_canonical(
        self,
        response: ResponsesResponse,
        *,
        request: ResponsesRequest,
    ) -> ModelResponse:
        return self._output_to_canonical(response.output, request=request)

    def response_payload(self, response: ResponsesResponse) -> dict[str, Any]:
        return self._response_wire_payload(response)

    def stream_decoder(
        self,
        request: ResponsesRequest,
    ) -> OpenAIResponsesStreamDecoder:
        if not request.stream:
            raise OpenAIResponsesAdapterError(
                "invalid_request",
                "A stream decoder requires stream=true.",
            )
        return OpenAIResponsesStreamDecoder(adapter=self, request=request)

    def _output_to_canonical(
        self,
        output: tuple[object, ...],
        *,
        request: ResponsesRequest,
    ) -> ModelResponse:
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for item in output:
            if isinstance(item, ResponsesOutputMessage):
                for content in item.content:
                    if isinstance(content, ResponsesOutputText):
                        if content.annotations or content.logprobs:
                            raise OpenAIResponsesAdapterError(
                                "invalid_upstream_response",
                                "The upstream model returned unsupported text metadata.",
                            )
                        text_parts.append(content.text)
                    else:
                        text_parts.append(content.refusal)
            elif isinstance(item, ResponsesFunctionCall):
                calls.append(
                    self._canonical_call(
                        call_id=item.call_id,
                        name=item.name,
                        arguments=item.arguments,
                    )
                )
            else:
                raise OpenAIResponsesAdapterError(
                    "invalid_upstream_response",
                    "The upstream model returned an unsupported output item.",
                )
        canonical_calls = tuple(calls)
        self._validate_calls(canonical_calls, request=request)
        try:
            return ModelResponse(
                content="".join(text_parts) or None,
                tool_calls=canonical_calls,
            )
        except ValidationError:
            raise OpenAIResponsesAdapterError(
                "invalid_upstream_response",
                "The upstream model returned no supported output.",
            ) from None

    @staticmethod
    def _response_wire_payload(response: ResponsesResponse) -> dict[str, Any]:
        """Return only fields whose provider content was mapped and checked."""

        output: list[dict[str, Any]] = []
        for item in response.output:
            if isinstance(item, ResponsesOutputMessage):
                output.append(item.model_dump(mode="json", exclude_none=True))
            else:
                output.append(
                    item.model_dump(
                        mode="json",
                        exclude_none=True,
                        exclude={"caller", "namespace"},
                    )
                )
        payload: dict[str, Any] = {
            "id": response.id,
            "object": response.object,
            "created_at": response.created_at,
            "model": response.model,
            "output": output,
        }
        if response.status is not None:
            payload["status"] = response.status
        return payload

    @staticmethod
    def _role(role: str) -> ChatRole:
        if role in {"system", "developer"}:
            return ChatRole.SYSTEM
        return ChatRole(role)

    @staticmethod
    def _canonical_call(*, call_id: str, name: str, arguments: str) -> ToolCall:
        try:
            parsed = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            raise OpenAIResponsesAdapterError(
                "invalid_tool_arguments_json",
                "Tool arguments must be a JSON object.",
            ) from None
        if not isinstance(parsed, dict):
            raise OpenAIResponsesAdapterError(
                "invalid_tool_arguments_json",
                "Tool arguments must be a JSON object.",
            )
        return ToolCall(
            call_id=call_id,
            name=name,
            arguments=cast(dict[str, JsonValue], parsed),
        )

    @staticmethod
    def _validate_tool_schemas(request: ResponsesRequest) -> None:
        for tool in request.tools:
            try:
                Draft202012Validator.check_schema(tool.parameters)
            except SchemaError as exc:
                raise OpenAIResponsesAdapterError(
                    "invalid_tool_schema",
                    "A declared tool contains an invalid JSON Schema.",
                ) from exc

    @staticmethod
    def _validate_calls(
        calls: tuple[ToolCall, ...],
        *,
        request: ResponsesRequest,
    ) -> None:
        schemas = {tool.name: tool.parameters for tool in request.tools}
        for call in calls:
            schema = schemas.get(call.name)
            if schema is None:
                raise OpenAIResponsesAdapterError(
                    "undeclared_tool_call",
                    "The upstream model called an undeclared tool.",
                )
            if next(Draft202012Validator(schema).iter_errors(call.arguments), None):
                raise OpenAIResponsesAdapterError(
                    "invalid_tool_arguments",
                    "The upstream tool arguments do not match their schema.",
                )

    @staticmethod
    def _invalid_request_history() -> None:
        raise OpenAIResponsesAdapterError(
            "invalid_request_history",
            "The Responses function-call history is incomplete or inconsistent.",
        )


@dataclass(slots=True)
class _PartialResponseFunctionCall:
    output_index: int
    item_id: str
    call_id: str
    name: str
    arguments: str = ""
    arguments_done: bool = False
    item_done: bool = False


class OpenAIResponsesStreamDecoder:
    """Validate Responses named SSE and expose cumulative output prefixes."""

    _HELD_EVENT_TYPES = frozenset(
        {
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.done",
            "response.refusal.done",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "response.output_item.done",
            "response.content_part.done",
        }
    )

    def __init__(
        self,
        *,
        adapter: OpenAIResponsesAdapter,
        request: ResponsesRequest,
    ) -> None:
        self._adapter = adapter
        self._request = request
        self._text = ""
        self._refusal = ""
        self._text_item_id: str | None = None
        self._function_calls: dict[int, _PartialResponseFunctionCall] = {}
        self._last_sequence = -1
        self._terminal = False

    def consume(self, event: ServerSentEvent) -> ProviderStreamUpdate:
        if self._terminal:
            self._invalid_stream("The upstream emitted data after stream completion.")
        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError:
            self._invalid_stream("The upstream returned invalid JSON SSE data.")
        if not isinstance(payload, dict) or not isinstance(payload.get("type"), str):
            self._invalid_stream("The upstream returned an unsupported stream event.")
        event_type = payload["type"]
        sequence_number = payload.get("sequence_number")
        if (
            isinstance(sequence_number, bool)
            or not isinstance(sequence_number, int)
            or sequence_number != self._last_sequence + 1
        ):
            self._invalid_stream("The upstream returned an invalid event sequence.")
        self._last_sequence = sequence_number
        if event.event != event_type:
            self._invalid_stream("The upstream SSE event and payload type differ.")

        if event_type == "response.output_text.delta":
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "content_index",
                    "delta",
                    "logprobs",
                },
            )
            delta_value = payload.get("delta")
            if not isinstance(delta_value, str) or self._refusal or payload.get("logprobs") != []:
                self._invalid_stream("The upstream returned an invalid text delta.")
            self._validate_text_location(payload)
            delta = cast(str, delta_value)
            self._text += delta
            safe_event = self._event(event_type, payload)
            if not delta or self._function_calls:
                return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=ModelResponse(content=self._text),
                event=safe_event,
            )
        if event_type == "response.refusal.delta":
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "content_index",
                    "delta",
                },
            )
            delta_value = payload.get("delta")
            if not isinstance(delta_value, str) or self._text:
                self._invalid_stream("The upstream returned an invalid refusal delta.")
            self._validate_text_location(payload)
            delta = cast(str, delta_value)
            self._refusal += delta
            safe_event = self._event(event_type, payload)
            if not delta or self._function_calls:
                return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=ModelResponse(content=self._refusal),
                event=safe_event,
            )
        if event_type == "response.completed":
            self._require_keys(payload, {"type", "sequence_number", "response"})
            response = self._terminal_response(payload)
            output = self._adapter.response_to_canonical(response, request=self._request)
            self._validate_terminal_response(response, output)
            self._terminal = True
            safe_payload = {
                "type": event_type,
                "sequence_number": sequence_number,
                "response": self._adapter._response_wire_payload(response),
            }
            return ProviderStreamUpdate(
                release=StreamRelease.FINAL,
                output=output,
                event=self._event(event_type, safe_payload),
            )
        if event_type in {"error", "response.failed", "response.incomplete"}:
            raise OpenAIResponsesAdapterError(
                "upstream_stream_failed",
                "The upstream model stream failed.",
            )
        if event_type in self._HELD_EVENT_TYPES:
            safe_event = self._validate_held_event(event_type, payload)
            return ProviderStreamUpdate(release=StreamRelease.HOLD, event=safe_event)
        self._invalid_stream("The upstream returned an unsupported stream event.")

    def finish(self) -> None:
        if not self._terminal:
            raise OpenAIResponsesAdapterError(
                "upstream_incomplete_stream",
                "The upstream model stream ended before response.completed.",
            )

    def error_event(self, *, code: str, message: str) -> ServerSentEvent:
        return ServerSentEvent(
            event="error",
            data=json.dumps(
                {
                    "type": "error",
                    "code": code,
                    "message": message,
                    "param": None,
                    "sequence_number": self._last_sequence + 1,
                },
                separators=(",", ":"),
            ),
        )

    def _validate_held_event(
        self,
        event_type: str,
        payload: dict[str, object],
    ) -> ServerSentEvent:
        if event_type in {"response.created", "response.in_progress"}:
            self._require_keys(payload, {"type", "sequence_number", "response"})
            try:
                response = ResponsesResponse.model_validate(payload.get("response"))
            except ValidationError:
                self._invalid_stream("The stream lifecycle event is malformed.")
            if response.output or response.error is not None:
                self._invalid_stream("The stream lifecycle event contained premature output.")
            safe_payload = {
                "type": event_type,
                "sequence_number": payload["sequence_number"],
                "response": self._adapter._response_wire_payload(response),
            }
            return self._event(event_type, safe_payload)

        if event_type in {"response.output_item.added", "response.output_item.done"}:
            self._require_keys(
                payload,
                {"type", "sequence_number", "output_index", "item"},
            )
            item = payload.get("item")
            output_index = self._output_index(payload)
            if not isinstance(item, dict):
                self._invalid_stream("The upstream returned an unsupported output item.")
            if item.get("type") == "message":
                if output_index != 0:
                    self._invalid_stream("Only one streamed text output is supported.")
                message = self._validate_message_item(
                    item,
                    require_empty=event_type == "response.output_item.added",
                )
                self._remember_text_item(message.id)
                safe_item = message.model_dump(mode="json", exclude_none=True)
            elif item.get("type") == "function_call":
                function = self._validate_function_item(
                    item,
                    output_index=output_index,
                    added=event_type == "response.output_item.added",
                )
                safe_item = function.model_dump(
                    mode="json",
                    exclude_none=True,
                    exclude={"caller", "namespace"},
                )
            else:
                self._invalid_stream("The upstream returned an unsupported output item.")
            safe_payload = dict(payload)
            safe_payload["item"] = safe_item
            return self._event(event_type, safe_payload)

        if event_type in {"response.content_part.added", "response.content_part.done"}:
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "content_index",
                    "part",
                },
            )
            self._validate_text_location(payload)
            part = payload.get("part")
            if not isinstance(part, dict):
                self._invalid_stream("The upstream returned unsupported output content.")
            safe_part = self._validate_content_part(
                part,
                require_empty=event_type == "response.content_part.added",
            )
            safe_payload = dict(payload)
            safe_payload["part"] = safe_part
            return self._event(event_type, safe_payload)

        if event_type == "response.function_call_arguments.delta":
            self._require_keys(
                payload,
                {"type", "sequence_number", "item_id", "output_index", "delta"},
            )
            delta = payload.get("delta")
            if not isinstance(delta, str):
                self._invalid_stream("The upstream returned an invalid arguments delta.")
            partial = self._function_for_event(payload)
            if partial.arguments_done or partial.item_done:
                self._invalid_stream("The upstream changed completed function arguments.")
            partial.arguments += delta
            return self._event(event_type, payload)

        if event_type == "response.function_call_arguments.done":
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "arguments",
                    "name",
                },
            )
            partial = self._function_for_event(payload)
            if (
                partial.arguments_done
                or payload.get("arguments") != partial.arguments
                or payload.get("name") != partial.name
            ):
                self._invalid_stream("The upstream changed completed function arguments.")
            partial.arguments_done = True
            return self._event(event_type, payload)

        if event_type == "response.output_text.done":
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "content_index",
                    "text",
                    "logprobs",
                },
            )
            self._validate_text_location(payload)
            if payload.get("text") != self._text or payload.get("logprobs") != []:
                self._invalid_stream("The upstream changed completed output text.")
            return self._event(event_type, payload)

        if event_type == "response.refusal.done":
            self._require_keys(
                payload,
                {
                    "type",
                    "sequence_number",
                    "item_id",
                    "output_index",
                    "content_index",
                    "refusal",
                },
            )
            self._validate_text_location(payload)
            if payload.get("refusal") != self._refusal:
                self._invalid_stream("The upstream changed completed refusal text.")
            return self._event(event_type, payload)

        self._invalid_stream("The upstream returned an unsupported stream event.")

    def _validate_message_item(
        self,
        item: dict[str, object],
        *,
        require_empty: bool,
    ) -> ResponsesOutputMessage:
        try:
            message = ResponsesOutputMessage.model_validate(item)
        except ValidationError:
            self._invalid_stream("The upstream returned an invalid output message.")
        if len(message.content) > 1:
            self._invalid_stream("Only one streamed text output part is supported.")
        pieces: list[str] = []
        for content in message.content:
            if isinstance(content, ResponsesOutputText):
                if self._refusal or content.annotations or content.logprobs:
                    self._invalid_stream("The stream included unsupported text metadata.")
                pieces.append(content.text)
            else:
                if self._text:
                    self._invalid_stream("The stream mixed text and refusal output.")
                pieces.append(content.refusal)
        combined = "".join(pieces)
        expected = self._text or self._refusal
        if (require_empty and combined) or (not require_empty and combined != expected):
            self._invalid_stream("The structural event changed streamed text.")
        return message

    def _validate_content_part(
        self,
        part: dict[str, object],
        *,
        require_empty: bool,
    ) -> dict[str, Any]:
        try:
            if part.get("type") == "output_text":
                content = ResponsesOutputText.model_validate(part)
                if self._refusal or content.annotations or content.logprobs:
                    self._invalid_stream("The stream included unsupported text metadata.")
                value = content.text
                expected = self._text
            elif part.get("type") == "refusal":
                content = ResponsesRefusal.model_validate(part)
                if self._text:
                    self._invalid_stream("The stream mixed text and refusal output.")
                value = content.refusal
                expected = self._refusal
            else:
                self._invalid_stream("The upstream returned unsupported output content.")
        except ValidationError:
            self._invalid_stream("The stream content part is malformed.")
        if (require_empty and value) or (not require_empty and value != expected):
            self._invalid_stream("The structural event changed streamed text.")
        return content.model_dump(mode="json", exclude_none=True)

    def _validate_function_item(
        self,
        item: dict[str, object],
        *,
        output_index: int,
        added: bool,
    ) -> ResponsesFunctionCall:
        try:
            function = ResponsesFunctionCall.model_validate(item)
        except ValidationError:
            self._invalid_stream("The upstream returned an invalid function item.")
        if function.id is None:
            self._invalid_stream("The streamed function item requires an ID.")
        if added:
            if output_index in self._function_calls or function.arguments:
                self._invalid_stream("The upstream returned an invalid function item.")
            self._function_calls[output_index] = _PartialResponseFunctionCall(
                output_index=output_index,
                item_id=function.id,
                call_id=function.call_id,
                name=function.name,
            )
            return function
        partial = self._function_calls.get(output_index)
        if (
            partial is None
            or partial.item_done
            or not partial.arguments_done
            or function.id != partial.item_id
            or function.call_id != partial.call_id
            or function.name != partial.name
            or function.arguments != partial.arguments
        ):
            self._invalid_stream("The completed function item changed its arguments.")
        partial.item_done = True
        return function

    def _validate_terminal_response(
        self,
        response: ResponsesResponse,
        output: ModelResponse,
    ) -> None:
        if self._text and (output.content is None or not output.content.startswith(self._text)):
            self._invalid_stream("The completed response changed released text.")
        if self._refusal and (
            output.content is None or not output.content.startswith(self._refusal)
        ):
            self._invalid_stream("The completed response changed released refusal.")
        messages = [item for item in response.output if isinstance(item, ResponsesOutputMessage)]
        if len(messages) > 1:
            self._invalid_stream("Only one streamed text output is supported.")
        if self._text_item_id is not None and (
            not messages or messages[0].id != self._text_item_id
        ):
            self._invalid_stream("The completed response changed its text item.")
        for partial in self._function_calls.values():
            if not partial.arguments_done or not partial.item_done:
                self._invalid_stream("The function stream ended before its item was complete.")
            if partial.output_index >= len(response.output):
                self._invalid_stream("The completed response omitted a streamed function.")
            item = response.output[partial.output_index]
            if (
                not isinstance(item, ResponsesFunctionCall)
                or item.id != partial.item_id
                or item.call_id != partial.call_id
                or item.name != partial.name
                or item.arguments != partial.arguments
            ):
                self._invalid_stream("The completed response changed a streamed function.")

    def _function_for_event(
        self,
        payload: dict[str, object],
    ) -> _PartialResponseFunctionCall:
        output_index = self._output_index(payload)
        item_id = payload.get("item_id")
        partial = self._function_calls.get(output_index)
        if not isinstance(item_id, str) or not item_id or partial is None:
            self._invalid_stream("The function event has no matching output item.")
        if partial.item_id != item_id:
            self._invalid_stream("The function event changed its output item.")
        return partial

    def _validate_text_location(self, payload: dict[str, object]) -> None:
        output_index = payload.get("output_index")
        content_index = payload.get("content_index")
        item_id = payload.get("item_id")
        if (
            isinstance(output_index, bool)
            or output_index != 0
            or isinstance(content_index, bool)
            or content_index != 0
            or not isinstance(item_id, str)
            or not item_id
        ):
            self._invalid_stream("Only one streamed text output part is supported.")
        self._remember_text_item(item_id)

    def _remember_text_item(self, item_id: str) -> None:
        if self._text_item_id is None:
            self._text_item_id = item_id
        elif self._text_item_id != item_id:
            self._invalid_stream("The stream changed its text output item.")

    @staticmethod
    def _output_index(payload: dict[str, object]) -> int:
        output_index = payload.get("output_index")
        if isinstance(output_index, bool) or not isinstance(output_index, int) or output_index < 0:
            OpenAIResponsesStreamDecoder._invalid_stream(
                "The upstream returned an invalid output index."
            )
        return output_index

    @staticmethod
    def _require_keys(payload: dict[str, object], expected: set[str]) -> None:
        if set(payload) != expected:
            OpenAIResponsesStreamDecoder._invalid_stream(
                "The upstream stream event contains unsupported fields."
            )

    @staticmethod
    def _event(event_type: str, payload: dict[str, object]) -> ServerSentEvent:
        return ServerSentEvent(
            event=event_type,
            data=json.dumps(payload, separators=(",", ":")),
        )

    def _terminal_response(self, payload: dict[str, object]) -> ResponsesResponse:
        try:
            return self._adapter.parse_response(payload.get("response"))
        except OpenAIResponsesAdapterError:
            raise OpenAIResponsesAdapterError(
                "invalid_upstream_stream",
                "The upstream completion event is malformed.",
            ) from None

    @staticmethod
    def _invalid_stream(message: str) -> Never:
        raise OpenAIResponsesAdapterError("invalid_upstream_stream", message)
