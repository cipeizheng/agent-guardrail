from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from agent_guardrail.core import (
    DetectorRegistry,
    EngineConfig,
    GuardrailEngine,
    PolicySet,
    RuleBinding,
)
from agent_guardrail.core.services import RuleServices
from agent_guardrail.models import (
    Action,
    Detection,
    DetectionContext,
    GuardrailContext,
    PendingTrace,
    Phase,
    Violation,
)
from tests.support import FAKE_SECRET, tool_context


@dataclass
class StaticRule:
    id: str
    phases: frozenset[Phase]
    code: str
    fail: bool = False
    delay_seconds: float = 0

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.fail:
            raise RuntimeError(FAKE_SECRET)
        return [
            Violation(
                rule_id=self.id,
                code=self.code,
                phase=context.event.phase,
                message="A deterministic test rule matched.",
            )
        ]


def engine_for(
    *bindings: RuleBinding,
    config: EngineConfig | None = None,
    detectors: DetectorRegistry | None = None,
) -> GuardrailEngine:
    return GuardrailEngine(
        policy=PolicySet(
            version=1,
            content_hash="test-policy-hash",
            engine=config or EngineConfig(),
            rules=tuple(bindings),
        ),
        detectors=detectors or DetectorRegistry(),
    )


@pytest.mark.asyncio
async def test_engine_aggregates_all_rule_actions() -> None:
    log_rule = StaticRule("log-rule", frozenset({Phase.PRE_TOOL}), "log_match")
    block_rule = StaticRule("block-rule", frozenset({Phase.PRE_TOOL}), "block_match")
    engine = engine_for(
        RuleBinding(rule=log_rule, action=Action.LOG),
        RuleBinding(rule=block_rule, action=Action.BLOCK),
    )

    decision = await engine.evaluate(tool_context(body="safe"))

    assert decision.action is Action.BLOCK
    assert [violation.action for violation in decision.violations] == [
        Action.LOG,
        Action.BLOCK,
    ]


@pytest.mark.asyncio
async def test_engine_analyzes_every_pending_event_and_binds_findings() -> None:
    rule = StaticRule("batch-rule", frozenset({Phase.PRE_TOOL}), "batch_match")
    engine = engine_for(RuleBinding(rule=rule, action=Action.LOG))
    first_context = tool_context(body="first")
    second = tool_context(body="second").event.model_copy(update={"id": "event-2", "sequence": 1})
    pending = PendingTrace(
        trace=first_context.trace,
        events=(first_context.event, second),
        primary_event_id=second.id,
    )

    decision = await engine.analyze_pending(pending)

    assert decision.pending_event_ids == (first_context.event.id, second.id)
    assert decision.event_id == second.id
    assert [violation.event_ids for violation in decision.violations] == [
        (first_context.event.id,),
        (second.id,),
    ]


@pytest.mark.asyncio
async def test_rule_error_is_explicit_and_does_not_leak_exception_text() -> None:
    rule = StaticRule("broken-rule", frozenset({Phase.PRE_TOOL}), "unused", fail=True)
    engine = engine_for(RuleBinding(rule=rule, action=Action.ALLOW))

    decision = await engine.evaluate(tool_context(body="safe"))

    assert decision.action is Action.BLOCK
    assert decision.violations[0].code == "rule_error"
    assert decision.violations[0].metadata["error_type"] == "RuntimeError"
    assert FAKE_SECRET not in decision.model_dump_json()


@pytest.mark.asyncio
async def test_rule_timeout_uses_configured_failure_action() -> None:
    rule = StaticRule(
        "slow-rule",
        frozenset({Phase.PRE_TOOL}),
        "unused",
        delay_seconds=0.05,
    )
    engine = engine_for(
        RuleBinding(rule=rule, action=Action.ALLOW),
        config=EngineConfig(default_timeout_ms=1, on_rule_error=Action.LOG),
    )

    decision = await engine.evaluate(tool_context(body="safe"))

    assert decision.action is Action.LOG
    assert decision.violations[0].code == "rule_timeout"


class CountingDetector:
    name = "counting"
    version = "1"

    def __init__(self, *, delay_seconds: float = 0) -> None:
        self.call_count = 0
        self.delay_seconds = delay_seconds

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        del text, context
        self.call_count += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        return []


@dataclass
class DetectorRule:
    id: str = "detector-rule"
    phases: frozenset[Phase] = frozenset({Phase.PRE_TOOL})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        await services.detect("counting", "same content", context=context, path="$.one")
        await services.detect("counting", "same content", context=context, path="$.two")
        return []


@dataclass
class PreviousPendingRule:
    id: str = "previous-pending-rule"
    phases: frozenset[Phase] = frozenset({Phase.PRE_TOOL})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        previous = context.trace.previous()
        if previous is None:
            return []
        return [
            Violation(
                rule_id=self.id,
                code="related_pending_events",
                phase=context.event.phase,
                message="Two pending events are related for this test.",
                event_ids=(previous.id,),
            )
        ]


@dataclass
class MutatingRule:
    id: str = "mutating-rule"
    phases: frozenset[Phase] = frozenset({Phase.PRE_TOOL})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        context.event.payload["arguments"] = {"changed": True}
        return []


@pytest.mark.asyncio
async def test_detector_results_are_cached_within_one_evaluation() -> None:
    detector = CountingDetector()
    detectors = DetectorRegistry()
    detectors.register(detector)
    engine = engine_for(
        RuleBinding(rule=DetectorRule(), action=Action.BLOCK),
        detectors=detectors,
    )

    decision = await engine.evaluate(tool_context(body="safe"))

    assert decision.action is Action.ALLOW
    assert detector.call_count == 1


@pytest.mark.asyncio
async def test_rule_can_bind_a_finding_to_multiple_pending_events() -> None:
    engine = engine_for(
        RuleBinding(rule=PreviousPendingRule(), action=Action.LOG),
    )
    first_context = tool_context(body="first")
    second = tool_context(body="second").event.model_copy(update={"id": "event-2", "sequence": 1})
    pending = PendingTrace(
        trace=first_context.trace,
        events=(first_context.event, second),
        primary_event_id=second.id,
    )

    decision = await engine.analyze_pending(pending)

    assert decision.violations[0].event_ids == (first_context.event.id, second.id)


@pytest.mark.asyncio
async def test_engine_rejects_rule_mutation_of_pending_trace() -> None:
    engine = engine_for(RuleBinding(rule=MutatingRule(), action=Action.BLOCK))
    pending = PendingTrace.from_context(tool_context(body="sensitive"))

    with pytest.raises(RuntimeError, match="mutated the pending trace"):
        await engine.analyze_pending(pending)


@pytest.mark.asyncio
async def test_detector_cache_does_not_reuse_event_scoped_evidence_across_batch() -> None:
    detector = CountingDetector()
    detectors = DetectorRegistry()
    detectors.register(detector)
    engine = engine_for(
        RuleBinding(rule=DetectorRule(), action=Action.BLOCK),
        detectors=detectors,
    )
    first_context = tool_context(body="first")
    second = tool_context(body="second").event.model_copy(update={"id": "event-2", "sequence": 1})
    pending = PendingTrace(
        trace=first_context.trace,
        events=(first_context.event, second),
        primary_event_id=second.id,
    )

    await engine.analyze_pending(pending)

    assert detector.call_count == 2


@pytest.mark.asyncio
async def test_detector_timeout_is_not_silently_allowed() -> None:
    detector = CountingDetector(delay_seconds=0.05)
    detectors = DetectorRegistry()
    detectors.register(detector)
    engine = engine_for(
        RuleBinding(rule=DetectorRule(), action=Action.ALLOW),
        config=EngineConfig(
            default_timeout_ms=100,
            detector_timeout_ms=1,
            on_detector_timeout=Action.LOG,
        ),
        detectors=detectors,
    )

    decision = await engine.evaluate(tool_context(body="safe"))

    assert decision.action is Action.LOG
    assert decision.violations[0].code == "detector_timeout"
