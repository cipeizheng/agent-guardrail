"""Framework-independent extension protocols for rules and detectors."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from agent_guardrail.models import Detection, DetectionContext, GuardrailContext, Phase, Violation

if TYPE_CHECKING:
    from agent_guardrail.core.services import RuleServices


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


class Rule(Protocol):
    """Decide whether detector facts violate policy in the current context."""

    id: str
    phases: frozenset[Phase]

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]: ...
