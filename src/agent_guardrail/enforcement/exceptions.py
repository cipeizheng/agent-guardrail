"""Safe exceptions used when enforcement cannot complete."""

from __future__ import annotations


class GuardrailUnavailable(RuntimeError):
    """Evaluation could not complete safely, so the boundary failed closed."""

    def __init__(self, *, trace_id: str, error_type: str) -> None:
        self.trace_id = trace_id
        self.error_type = error_type
        super().__init__(f"guardrail unavailable for trace {trace_id}: {error_type}")
