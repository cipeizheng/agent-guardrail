"""Stable pending-analysis boundary shared by local and future runtimes."""

from __future__ import annotations

from typing import Protocol

from agent_guardrail.models import Decision, PendingTrace


class PolicyAnalyzer(Protocol):
    """Analyze one atomic pending batch without performing guarded side effects."""

    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
