"""Small audit sinks for local execution and deterministic tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from agent_guardrail.models import Decision


class NullAuditSink:
    """Discard sanitized audit decisions."""

    async def record(self, decision: Decision) -> None:
        del decision


class InMemoryAuditSink:
    """Collect decisions without ever receiving event payloads."""

    def __init__(self) -> None:
        self.records: list[Decision] = []

    async def record(self, decision: Decision) -> None:
        self.records.append(decision)


class JsonlAuditSink:
    """Append sanitized decision summaries without receiving raw event payloads."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()

    async def record(self, decision: Decision) -> None:
        record = {
            "timestamp": self.clock().isoformat(),
            "trace_id": decision.trace_id,
            "phase": decision.phase.value,
            "action": decision.action.value,
            "rule_ids": [violation.rule_id for violation in decision.violations],
            "codes": [violation.code for violation in decision.violations],
            "policy_version": decision.policy_version,
            "policy_hash": decision.policy_hash,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as output:
            output.write(line)
