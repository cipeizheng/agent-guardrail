"""Framework-neutral boundaries that can be guarded by inline adapters."""

from __future__ import annotations

from typing import Protocol

from agent_guardrail.models import Decision, ModelRequest, ModelResponse, ToolCall, ToolResult


class LLMClient(Protocol):
    """Async model boundary implemented by fakes and provider adapters."""

    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class ToolExecutor(Protocol):
    """Async tool boundary implemented by local and protocol adapters."""

    async def execute(self, call: ToolCall) -> ToolResult: ...


class AuditSink(Protocol):
    """Receive an already-sanitized decision, never a raw provider object."""

    async def record(self, decision: Decision) -> None: ...
