"""Bounded task sessions shared by model and MCP Gateway boundaries."""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_guardrail.enforcement import AuditSink, EnforcementSession, NormalizedBatch
from agent_guardrail.models import (
    CandidateRelation,
    EventKind,
    EventOrigin,
    RelationKind,
    ToolResult,
    Trace,
)
from agent_guardrail.runtime import PolicyAnalyzer

TASK_SESSION_HEADER = "x-agent-guardrail-session"
TOOL_PROPOSAL_HEADER = "x-agent-guardrail-proposal-id"
_TOKEN_PATTERN = re.compile(r"ags_[A-Za-z0-9_-]{32,96}\Z")


class TaskSessionError(RuntimeError):
    """A safe task-session failure that never contains a session token."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TaskSession:
    """One opaque task token and its shared enforcement state."""

    token: str
    enforcement: EnforcementSession
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def trace_id(self) -> str:
        return self.enforcement.trace.id


@dataclass(slots=True)
class _StoredTaskSession:
    task: TaskSession
    expires_at: float


class TaskSessionStore:
    """An in-memory, sliding-TTL store for one process and one application user."""

    def __init__(
        self,
        *,
        analyzer: PolicyAnalyzer,
        audit: AuditSink,
        max_sessions: int,
        ttl_seconds: float,
        max_trace_events: int,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] | None = None,
        trace_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._audit = audit
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds
        self._max_trace_events = max_trace_events
        self._clock = clock
        self._token_factory = token_factory or (
            lambda: f"ags_{secrets.token_urlsafe(32)}"
        )
        self._trace_id_factory = trace_id_factory or (
            lambda: f"trc_{secrets.token_hex(16)}"
        )
        self._entries: dict[str, _StoredTaskSession] = {}
        self._lock = asyncio.Lock()

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    def ephemeral(self, *, max_trace_events: int) -> TaskSession:
        """Create request-scoped state without inserting it into the store."""

        return TaskSession(
            token="",
            enforcement=self._new_enforcement_session(max_events=max_trace_events),
        )

    async def create(self) -> TaskSession:
        """Create a new task or fail without evicting an active task."""

        async with self._lock:
            now = self._clock()
            self._purge_expired(now)
            if len(self._entries) >= self._max_sessions:
                raise TaskSessionError(
                    "task_session_capacity_exceeded",
                    "The Gateway task-session capacity is exhausted.",
                )
            for _ in range(8):
                token = self._token_factory()
                if _TOKEN_PATTERN.fullmatch(token) and token not in self._entries:
                    break
            else:
                raise TaskSessionError(
                    "task_session_creation_failed",
                    "The Gateway could not create a task session.",
                )
            task = TaskSession(
                token=token,
                enforcement=self._new_enforcement_session(
                    max_events=self._max_trace_events,
                ),
            )
            self._entries[token] = _StoredTaskSession(
                task=task,
                expires_at=now + self._ttl_seconds,
            )
            return task

    async def get(self, token: str) -> TaskSession:
        """Resolve and refresh one opaque task token."""

        if not _TOKEN_PATTERN.fullmatch(token):
            raise self._not_found()
        async with self._lock:
            now = self._clock()
            self._purge_expired(now)
            stored = self._entries.get(token)
            if stored is None:
                raise self._not_found()
            stored.expires_at = now + self._ttl_seconds
            return stored.task

    async def delete(self, token: str) -> None:
        """Delete one task without revealing whether a malformed token ever existed."""

        if not _TOKEN_PATTERN.fullmatch(token):
            raise self._not_found()
        async with self._lock:
            self._purge_expired(self._clock())
            if self._entries.pop(token, None) is None:
                raise self._not_found()

    async def clear(self) -> None:
        """Drop all in-memory task state during Gateway shutdown."""

        async with self._lock:
            self._entries.clear()

    def _new_enforcement_session(self, *, max_events: int) -> EnforcementSession:
        return EnforcementSession(
            analyzer=self._analyzer,
            trace=Trace(id=self._trace_id_factory(), max_events=max_events),
            audit=self._audit,
        )

    def _purge_expired(self, now: float) -> None:
        expired = [
            token
            for token, stored in self._entries.items()
            if stored.expires_at <= now
        ]
        for token in expired:
            del self._entries[token]

    @staticmethod
    def _not_found() -> TaskSessionError:
        return TaskSessionError(
            "task_session_invalid",
            "The Gateway task session is invalid or expired.",
        )


def relink_observed_tool_results(
    batch: NormalizedBatch,
    *,
    trace: Trace,
) -> NormalizedBatch:
    """Link explicit model history to MCP results observed in the same task.

    The provider request remains client-asserted. Only the model-call input edge is
    replaced, and only when the protocol call ID and tool name identify exactly one
    earlier MCP result observed by this Gateway.
    """

    observed: dict[tuple[str, str], list[str]] = {}
    for event in trace.events:
        if (
            event.kind is not EventKind.TOOL_RESULT
            or event.origin is not EventOrigin.OBSERVED
            or event.metadata.get("adapter") != "mcp_gateway"
        ):
            continue
        result = ToolResult.model_validate(event.payload)
        observed.setdefault((result.call_id, result.name), []).append(event.id)

    if not observed:
        return batch
    candidates_by_key = {candidate.key: candidate for candidate in batch.candidates}
    primary = candidates_by_key[batch.primary_key]
    if primary.kind is not EventKind.MODEL_CALL:
        return batch

    relations: list[CandidateRelation] = []
    seen: set[tuple[str | None, str | None, RelationKind]] = set()
    for relation in primary.relations:
        replacement = relation
        if relation.source_candidate_key is not None:
            source = candidates_by_key[relation.source_candidate_key]
            if source.kind is EventKind.TOOL_RESULT:
                result = ToolResult.model_validate(source.payload)
                matches = observed.get((result.call_id, result.name), [])
                if len(matches) > 1:
                    raise TaskSessionError(
                        "task_history_conflict",
                        "Task history contains an ambiguous observed tool result.",
                    )
                if matches:
                    replacement = CandidateRelation(
                        source_event_id=matches[0],
                        kind=RelationKind.INFLUENCED_BY,
                    )
        key = (
            replacement.source_event_id,
            replacement.source_candidate_key,
            replacement.kind,
        )
        if key not in seen:
            relations.append(replacement)
            seen.add(key)

    rewritten_primary = primary.model_copy(update={"relations": tuple(relations)})
    return NormalizedBatch(
        candidates=tuple(
            rewritten_primary if candidate.key == batch.primary_key else candidate
            for candidate in batch.candidates
        ),
        primary_key=batch.primary_key,
    )
