"""Safe conversion between OpenAI payloads and canonical guardrail events."""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft202012Validator, SchemaError
from pydantic import ValidationError

from agent_guardrail.adapters.openai.models import (
    AssistantMessage,
    ChatCompletionRequest,
    ChatCompletionResponse,
    FunctionTool,
    SystemMessage,
    ToolMessage,
    UserMessage,
)
from agent_guardrail.models import (
    ChatMessage,
    ChatRole,
    ModelRequest,
    ModelResponse,
    ToolCall,
    ToolDefinition,
)


class OpenAIAdapterError(ValueError):
    """A safe protocol error that never includes request or provider content."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class OpenAIAdapter:
    """Parse a strict Chat Completions subset and validate function calls."""

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
        message = response.choices[0].message
        schemas = {tool.function.name: tool.function.parameters for tool in request.tools}
        calls = tuple(self._tool_call_to_canonical(call) for call in message.tool_calls)

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

        content = message.content if message.content is not None else message.refusal
        return ModelResponse(content=content, tool_calls=calls)

    def request_payload(self, request: ChatCompletionRequest) -> dict[str, Any]:
        """Return a normalized upstream payload with no Gateway-only fields."""

        return request.model_dump(mode="json", exclude_none=True)

    def response_payload(self, response: ChatCompletionResponse) -> dict[str, Any]:
        """Return a normalized OpenAI-compatible response."""

        return response.model_dump(mode="json", exclude_none=True)

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
