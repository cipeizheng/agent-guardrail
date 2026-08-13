"""Safe exceptions used to stop a guarded boundary."""

from __future__ import annotations

from agent_guardrail.models import Decision


class GuardrailBlocked(RuntimeError):
    """A policy decision blocked the current boundary."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"guardrail blocked trace {decision.trace_id}")


class GuardrailUnavailable(RuntimeError):
    """Evaluation could not complete safely, so the boundary failed closed."""

    def __init__(self, *, trace_id: str, error_type: str) -> None:
        self.trace_id = trace_id
        self.error_type = error_type
        super().__init__(f"guardrail unavailable for trace {trace_id}: {error_type}")
