"""I12 execution tests for explicitly compiled MatchPlan capabilities."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import JsonValue

from agent_guardrail.config import create_default_predicate_registry
from agent_guardrail.core import (
    CapabilityCompilationError,
    CompiledMatchPlan,
    DetectorPolicyDescriptor,
    DetectorRegistry,
    Predicate,
    PredicateContext,
    PredicatePolicyDescriptor,
    PredicateRegistry,
    SnapshotMatcher,
    compile_match_plan_capabilities,
)
from agent_guardrail.core.match_plan import (
    CollectionBinding,
    DetectorCondition,
    DetectorInput,
    DetectorInputEncoding,
    EventBinding,
    EvidenceProjection,
    EvidenceProjectionSource,
    LiteralListValue,
    LiteralValue,
    MatchCondition,
    MatchLimitOverrides,
    MatchLimits,
    MatchPlan,
    PredicateCondition,
    ValueType,
)
from agent_guardrail.models import (
    AnalysisErrorCode,
    Detection,
    DetectionContext,
    EventKind,
    EvidenceSource,
)
from tests.unit.test_matcher import call, field, message, plan, rule, trace


class _ContainsBlocked:
    name = "contains_blocked"
    version = "1"

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        self.calls += 1
        assert context.condition_id == "blocked_fact"
        return len(arguments) == 1 and "blocked" in str(arguments[0])


class _MarkerDetector:
    name = "prompt_injection"
    version = "1"

    def __init__(self, *, delay: float = 0) -> None:
        self.delay = delay
        self.calls = 0

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        del context
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        marker = "injection-marker"
        start = text.find(marker)
        if start < 0:
            return []
        return [
            Detection(
                type="prompt_injection",
                detector=self.name,
                detector_version=self.version,
                confidence=0.9,
                start=start,
                end=start + len(marker),
                masked_evidence="[MATCH]",
                fingerprint="marker_01",
            )
        ]


def _predicate_registry(
    predicate: _ContainsBlocked,
    *,
    max_input_bytes: int = 64,
    timeout_ms: int = 50,
) -> PredicateRegistry:
    registry = PredicateRegistry()
    registry.register(
        predicate,
        policy_descriptor=PredicatePolicyDescriptor(
            name=predicate.name,
            argument_types=(ValueType.STRING,),
            max_input_bytes=max_input_bytes,
            timeout_ms=timeout_ms,
        ),
    )
    return registry


def _detector_registry(
    detector: _MarkerDetector,
    *,
    max_input_bytes: int = 64,
    timeout_ms: int = 50,
) -> DetectorRegistry:
    registry = DetectorRegistry()
    registry.register(
        detector,
        policy_descriptor=DetectorPolicyDescriptor(
            name=detector.name,
            allowed_encodings=frozenset({"text"}),
            detection_types=frozenset({"prompt_injection"}),
            max_input_bytes=max_input_bytes,
            timeout_ms=timeout_ms,
        ),
    )
    return registry


def _compile(
    match_plan: MatchPlan,
    *,
    predicates: PredicateRegistry | None = None,
    detectors: DetectorRegistry | None = None,
) -> CompiledMatchPlan:
    return compile_match_plan_capabilities(
        match_plan,
        predicates=predicates or PredicateRegistry(),
        detectors=detectors or DetectorRegistry(),
    )


def _matcher(compiled: MatchPlan | CompiledMatchPlan) -> SnapshotMatcher:
    return SnapshotMatcher(
        compiled,
        policy_version=3,
        policy_hash="policy-hash-1234",
    )


@pytest.mark.asyncio
async def test_i12_registered_predicate_executes_and_projects_safe_evidence() -> None:
    predicate = _ContainsBlocked()
    selected = rule(
        where=MatchCondition(
            predicate=PredicateCondition(
                id="blocked_fact",
                capability="contains_blocked",
                arguments=(field("event", "payload", "content", "text"),),
            )
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.PREDICATE,
                id="blocked_fact",
                masked_evidence="[MATCH]",
            ),
        ),
    )
    compiled = _compile(plan(selected), predicates=_predicate_registry(predicate))

    hit = await _matcher(compiled).analyze(trace(message("m1", 0, "blocked answer")))
    miss = await _matcher(compiled).analyze(trace(message("m1", 0, "safe answer")))

    assert len(hit.findings) == 1
    assert hit.errors == ()
    assert hit.findings[0].evidence[0].source is EvidenceSource.PREDICATE
    assert hit.findings[0].evidence[0].capability == "contains_blocked"
    assert hit.findings[0].evidence[0].masked_evidence == "[MATCH]"
    assert miss.findings == ()


@pytest.mark.asyncio
async def test_predicate_cache_is_analysis_local_and_context_sensitive() -> None:
    predicate = _ContainsBlocked()
    selected = rule(
        bindings=(EventBinding(name="event", kind=EventKind.TOOL_CALL),),
        collections=(
            CollectionBinding(
                name="item",
                source=field("event", "payload", "arguments", "items"),
                item_type=ValueType.STRING,
            ),
        ),
        where=MatchCondition(
            predicate=PredicateCondition(
                id="blocked_fact",
                capability="contains_blocked",
                arguments=(field("event", "payload", "name"),),
            )
        ),
        finding_bindings=("event", "item"),
    )
    compiled = _compile(plan(selected), predicates=_predicate_registry(predicate))
    analyzer = _matcher(compiled)
    snapshot = trace(call("c1", 0, "blocked_tool", {"items": ["a", "b"]}))

    first = await analyzer.analyze(snapshot)
    second = await analyzer.analyze(snapshot)

    assert len(first.findings) == 2
    assert len(second.findings) == 2
    assert predicate.calls == 2


@pytest.mark.asyncio
async def test_i12_registered_detector_returns_only_masked_bounded_evidence() -> None:
    detector = _MarkerDetector()
    selected = rule(
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("event", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
                types_any=("prompt_injection",),
            )
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.DETECTOR,
                id="injection_fact",
            ),
        ),
    )
    compiled = _compile(plan(selected), detectors=_detector_registry(detector))
    report = await _matcher(compiled).analyze(
        trace(message("m1", 0, "secret injection-marker tail"))
    )

    assert len(report.findings) == 1
    evidence = report.findings[0].evidence[0]
    assert evidence.source is EvidenceSource.DETECTOR
    assert evidence.type == "prompt_injection"
    assert evidence.capability == "prompt_injection"
    assert evidence.masked_evidence == "[MATCH]"
    assert evidence.location is not None
    assert evidence.location.start == 7
    assert "secret injection-marker" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_i12_detector_timeout_is_stable_and_other_rule_still_runs() -> None:
    detector = _MarkerDetector(delay=0.05)
    capability_rule = rule(
        rule_id="capability",
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("event", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
            )
        ),
    )
    compiled = _compile(
        plan(capability_rule, rule(rule_id="structural")),
        detectors=_detector_registry(detector, timeout_ms=1),
    )
    report = await _matcher(compiled).analyze(
        trace(message("m1", 0, "blocked injection-marker"))
    )

    assert [finding.rule_id for finding in report.findings] == ["structural"]
    assert report.errors[0].code is AnalysisErrorCode.DETECTOR_TIMEOUT
    assert report.errors[0].capability == "prompt_injection"
    assert report.errors[0].retryable is True


@pytest.mark.asyncio
async def test_i12_descriptor_and_plan_input_byte_limits_fail_closed() -> None:
    predicate = _ContainsBlocked()
    selected = rule(
        where=MatchCondition(
            predicate=PredicateCondition(
                id="blocked_fact",
                capability="contains_blocked",
                arguments=(field("event", "payload", "content", "text"),),
            )
        ),
        limits=MatchLimitOverrides(predicate_input_bytes=5),
    )
    compiled = _compile(
        plan(selected),
        predicates=_predicate_registry(predicate, max_input_bytes=64),
    )
    report = await _matcher(compiled).analyze(trace(message("m1", 0, "blocked")))

    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED
    assert "predicate_input_bytes" in report.errors[0].message

    detector = _MarkerDetector()
    detector_rule = rule(
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("event", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
            )
        )
    )
    over = _compile(
        plan(detector_rule),
        detectors=_detector_registry(detector, max_input_bytes=6),
    )
    report = await _matcher(over).analyze(
        trace(message("m1", 0, "marker-x injection-marker"))
    )
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED
    assert report.errors[0].capability == "prompt_injection"
    assert detector.calls == 0


class _SlowPredicate:
    name = "slow_predicate"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del arguments, context
        await asyncio.sleep(0.05)
        return True


class _ExplodingPredicate:
    name = "exploding_predicate"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del arguments, context
        raise RuntimeError("raw-sensitive-exception")


def _single_predicate_registry(
    predicate: Predicate,
    *,
    timeout_ms: int,
) -> PredicateRegistry:
    registry = PredicateRegistry()
    registry.register(
        predicate,
        policy_descriptor=PredicatePolicyDescriptor(
            name=predicate.name,
            argument_types=(),
            timeout_ms=timeout_ms,
        ),
    )
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("predicate", "retryable"),
    ((_SlowPredicate(), True), (_ExplodingPredicate(), False)),
)
async def test_predicate_timeout_and_exception_are_redacted_rule_errors(
    predicate: Predicate,
    retryable: bool,
) -> None:
    selected = rule(
        where=MatchCondition(
            predicate=PredicateCondition(
                id="blocked_fact",
                capability=predicate.name,
            )
        )
    )
    compiled = _compile(
        plan(selected),
        predicates=_single_predicate_registry(predicate, timeout_ms=1),
    )
    report = await _matcher(compiled).analyze(
        trace(message("m1", 0, "raw-sensitive-input"))
    )

    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.CAPABILITY_ERROR
    assert report.errors[0].capability == predicate.name
    assert report.errors[0].retryable is retryable
    assert "raw-sensitive" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_detector_deadline_budget_is_reserved_before_invocation() -> None:
    detector = _MarkerDetector()
    selected = rule(
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("event", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
            )
        ),
    )
    match_plan = plan(
        selected,
        limits=MatchLimits(detector_time_ms=10),
    )
    compiled = _compile(
        match_plan,
        detectors=_detector_registry(detector, timeout_ms=11),
    )
    report = await _matcher(compiled).analyze(
        trace(message("m1", 0, "injection-marker"))
    )

    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED
    assert "detector_time_ms" in report.errors[0].message
    assert detector.calls == 0


def test_i12_compiler_rejects_unregistered_and_incompatible_capabilities() -> None:
    unavailable = rule(
        where=MatchCondition(
            predicate=PredicateCondition(
                id="blocked_fact",
                capability="external_checker",
                arguments=(LiteralValue(value="blocked"),),
            )
        )
    )
    with pytest.raises(CapabilityCompilationError, match="unavailable Predicate"):
        _compile(plan(unavailable))

    predicate = _ContainsBlocked()
    registry = _predicate_registry(predicate)
    bad_arity = unavailable.model_copy(
        update={
            "where": MatchCondition(
                predicate=PredicateCondition(
                    id="blocked_fact",
                    capability="contains_blocked",
                )
            )
        }
    )
    with pytest.raises(CapabilityCompilationError, match="incompatible arity"):
        _compile(plan(bad_arity), predicates=registry)

    bad_type = unavailable.model_copy(
        update={
            "where": MatchCondition(
                predicate=PredicateCondition(
                    id="blocked_fact",
                    capability="contains_blocked",
                    arguments=(LiteralValue(value=7),),
                )
            )
        }
    )
    with pytest.raises(CapabilityCompilationError, match="argument type"):
        _compile(plan(bad_type), predicates=registry)

    invalid_embedding = rule(
        where=MatchCondition(
            predicate=PredicateCondition(
                id="vector_similarity",
                capability="embedding_similarity",
                arguments=(
                    LiteralValue(value="not-a-vector"),
                    LiteralListValue(items=(1.0, 0.0)),
                    LiteralValue(value=0.9),
                ),
            )
        )
    )
    with pytest.raises(CapabilityCompilationError, match="argument type"):
        _compile(
            plan(invalid_embedding),
            predicates=create_default_predicate_registry(),
        )

    detector = _MarkerDetector()
    detector_registry = _detector_registry(detector)
    unpublished_type = rule(
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("event", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
                types_any=("unknown_type",),
            )
        )
    )
    with pytest.raises(CapabilityCompilationError, match="detection type"):
        _compile(plan(unpublished_type), detectors=detector_registry)

    bad_text_input = rule(
        where=MatchCondition(
            detector=DetectorCondition(
                id="injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=LiteralValue(value=7),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
            )
        )
    )
    with pytest.raises(CapabilityCompilationError, match="text input type"):
        _compile(plan(bad_text_input), detectors=detector_registry)
