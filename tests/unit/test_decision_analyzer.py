from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from agent_guardrail.config import load_policy_yaml
from agent_guardrail.core import (
    DetectorPolicyDescriptor,
    DetectorRegistry,
    MatchPolicyAnalyzer,
    PredicateRegistry,
)
from agent_guardrail.models import (
    Action,
    Detection,
    DetectionContext,
    Event,
    EventKind,
    EventOrigin,
    PendingTrace,
    Phase,
    ToolCall,
    Trace,
)
from tests.support import FAKE_SECRET, empty_analyzer, secret_analyzer

NOW = datetime(2026, 8, 10, tzinfo=UTC)


def call(event_id: str, sequence: int, body: str = "safe") -> Event:
    return Event(
        id=event_id,
        trace_id="trace-1",
        sequence=sequence,
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        timestamp=NOW,
        origin=EventOrigin.OBSERVED,
        payload=ToolCall(
            call_id=f"call-{sequence}",
            name="send_email",
            arguments={"body": body},
        ).model_dump(mode="json"),
    )


def pending(*events: Event) -> PendingTrace:
    return PendingTrace(
        trace=Trace(id="trace-1"),
        events=events,
        primary_event_id=events[-1].id,
    )


@pytest.mark.asyncio
async def test_empty_policy_allows_pending_batch() -> None:
    batch = pending(call("e1", 0))

    decision = await empty_analyzer().analyze_pending(batch)

    assert decision.action is Action.ALLOW
    assert decision.pending_event_ids == ("e1",)
    assert decision.violations == ()


@pytest.mark.asyncio
async def test_finding_maps_detector_evidence_without_raw_secret() -> None:
    decision = await secret_analyzer().analyze_pending(
        pending(call("e1", 0, FAKE_SECRET))
    )

    assert decision.action is Action.BLOCK
    assert decision.violations[0].event_ids == ("e1",)
    assert decision.violations[0].evidence[0].detector == "secrets"
    assert decision.violations[0].evidence[0].detector_version == "1"
    assert FAKE_SECRET not in decision.model_dump_json()


@pytest.mark.asyncio
async def test_max_violations_keeps_higher_action_after_complete_matching() -> None:
    analyzer = _analyzer(
        """\
version: 3
engine: {max_violations: 1}
scopes: [pending]
rules:
  - id: log-first
    action: log
    events:
      call: {kind: tool_call, domain: pending, phases: [pre_tool]}
    where: {present: [call, payload]}
    finding: {code: logged, message: Logged match, subjects: [call]}
  - id: block-second
    action: block
    events:
      call: {kind: tool_call, domain: pending, phases: [pre_tool]}
    where: {present: [call, payload]}
    finding: {code: blocked, message: Blocked match, subjects: [call]}
"""
    )

    decision = await analyzer.analyze_pending(pending(call("e1", 0)))

    assert decision.action is Action.BLOCK
    assert [violation.code for violation in decision.violations] == ["blocked"]


@pytest.mark.asyncio
async def test_analysis_budget_error_uses_configured_failure_action() -> None:
    analyzer = _analyzer(
        """\
version: 3
engine: {on_analysis_error: log}
scopes: [pending]
limits: {candidate_events: 1}
rules:
  - id: bounded
    action: block
    events:
      call: {kind: tool_call, domain: pending, phases: [pre_tool]}
    where: {present: [call, payload]}
    finding: {code: matched, message: Match, subjects: [call]}
"""
    )

    decision = await analyzer.analyze_pending(
        pending(call("e1", 0), call("e2", 1))
    )

    assert decision.action is Action.LOG
    assert decision.violations[0].code == "resource_exhausted"
    assert decision.violations[0].event_ids == ("e1", "e2")
    assert decision.violations[0].metadata == {"system": True}


class SlowDetector:
    name = "slow"
    version = "1"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        del text, context
        await asyncio.sleep(0.02)
        return []


@pytest.mark.asyncio
async def test_detector_timeout_uses_dedicated_failure_action() -> None:
    detectors = DetectorRegistry()
    detectors.register(
        SlowDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="slow",
            allowed_encodings=frozenset({"canonical_json"}),
            detection_types=frozenset(),
            max_input_bytes=1_024,
            timeout_ms=1,
        ),
    )
    policy = load_policy_yaml(
        """\
version: 3
engine: {on_analysis_error: allow, on_detector_timeout: block}
scopes: [pending]
rules:
  - id: timeout
    action: log
    events:
      call: {kind: tool_call, domain: pending, phases: [pre_tool]}
    where:
      detector:
        id: scan
        capability: slow
        inputs:
          - value: {field: [call, payload, arguments]}
            encoding: canonical_json
    finding:
      code: matched
      message: Match
      subjects: [call]
""",
        detectors=detectors,
        predicates=PredicateRegistry(),
    )

    decision = await MatchPolicyAnalyzer(policy).analyze_pending(
        pending(call("e1", 0))
    )

    assert decision.action is Action.BLOCK
    assert decision.violations[0].code == "detector_timeout"
    assert decision.violations[0].metadata["capability"] == "slow"


def _analyzer(source: str) -> MatchPolicyAnalyzer:
    policy = load_policy_yaml(
        source,
        detectors=DetectorRegistry(),
        predicates=PredicateRegistry(),
    )
    return MatchPolicyAnalyzer(policy)
