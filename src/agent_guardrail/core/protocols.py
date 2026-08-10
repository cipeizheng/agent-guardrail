"""Framework-independent extension protocols for rules and detectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pydantic import JsonValue

from agent_guardrail.models import Detection, DetectionContext


class Detector(Protocol):
    """Find structured facts in text without deciding an enforcement action."""

    name: str
    version: str

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]: ...


@dataclass(frozen=True, slots=True)
class PredicateContext:
    """Minimal, payload-free context exposed to a trusted Predicate."""

    trace_id: str
    rule_id: str
    condition_id: str
    event_ids: tuple[str, ...]


class Predicate(Protocol):
    """Return one boolean fact from bounded JSON arguments without side effects."""

    name: str
    version: str

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool: ...
