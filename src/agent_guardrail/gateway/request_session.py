"""Request-scoped enforcement state for Gateway boundaries."""

from __future__ import annotations

import secrets

from agent_guardrail.enforcement import AuditSink, EnforcementSession
from agent_guardrail.models import Trace
from agent_guardrail.runtime import PolicyAnalyzer


def create_request_session(
    *,
    analyzer: PolicyAnalyzer,
    audit: AuditSink,
    max_trace_events: int,
) -> EnforcementSession:
    """Create isolated enforcement state for one Gateway request."""

    return EnforcementSession(
        analyzer=analyzer,
        trace=Trace(
            id=f"trc_{secrets.token_hex(16)}",
            max_events=max_trace_events,
        ),
        audit=audit,
    )
