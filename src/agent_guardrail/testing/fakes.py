"""Deterministic LLM and tool implementations for security semantics tests."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable
from typing import cast

from pydantic import JsonValue

from agent_guardrail.models import ModelRequest, ModelResponse, ToolCall, ToolResult

ToolHandler = Callable[[dict[str, JsonValue]], JsonValue | Awaitable[JsonValue]]


class ScriptedLLM:
    """Return a fixed response sequence without network access or randomness."""

    def __init__(self, responses: Iterable[ModelResponse]) -> None:
        self._responses = tuple(responses)
        if not self._responses:
            raise ValueError("ScriptedLLM requires at least one response")
        self.call_count = 0
        self.requests: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if self.call_count >= len(self._responses):
            raise RuntimeError("ScriptedLLM response queue is exhausted")
        self.requests.append(request)
        response = self._responses[self.call_count]
        self.call_count += 1
        return response


class FakeToolExecutor:
    """Execute in-memory handlers and expose exact side-effect counts."""

    def __init__(self, handlers: dict[str, ToolHandler]) -> None:
        self._handlers = dict(handlers)
        self.calls: list[ToolCall] = []

    def call_count(self, tool_name: str | None = None) -> int:
        if tool_name is None:
            return len(self.calls)
        return sum(call.name == tool_name for call in self.calls)

    async def execute(self, call: ToolCall) -> ToolResult:
        try:
            handler = self._handlers[call.name]
        except KeyError as exc:
            raise ValueError(f"unknown fake tool: {call.name}") from exc

        self.calls.append(call)
        raw_output = handler(cast(dict[str, JsonValue], call.arguments))
        output = await raw_output if inspect.isawaitable(raw_output) else raw_output
        return ToolResult(call_id=call.call_id, name=call.name, output=output)
