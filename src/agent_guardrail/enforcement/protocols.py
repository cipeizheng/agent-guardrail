"""Framework-neutral audit boundary."""

from __future__ import annotations

from typing import Protocol

from agent_guardrail.models import Decision


class AuditSink(Protocol):
    """Receive an already-sanitized decision, never a raw provider object."""

    async def record(self, decision: Decision) -> None: ...
