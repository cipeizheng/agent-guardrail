"""Stable decision boundary shared by local and future remote runtimes."""

from __future__ import annotations

from typing import Protocol

from agent_guardrail.models import Decision, GuardrailContext


class DecisionEvaluator(Protocol):
    """Evaluate one canonical context without performing the guarded side effect."""

    async def evaluate(self, context: GuardrailContext) -> Decision: ...
