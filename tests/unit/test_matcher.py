from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_guardrail.core.match_plan import (
    BindingDomain,
    BindingValue,
    CollectionBinding,
    Comparison,
    ComparisonOperator,
    CountBounds,
    DerivedValue,
    DetectorCondition,
    DetectorInput,
    DetectorInputEncoding,
    EventBinding,
    EvidenceProjection,
    EvidenceProjectionSource,
    FieldValue,
    FindingTemplate,
    LiteralListValue,
    LiteralValue,
    MatchCondition,
    MatchLimitOverrides,
    MatchLimits,
    MatchPlan,
    MatchRulePlan,
    NullValue,
    ParameterDeclaration,
    ParameterType,
    ParameterValue,
    PredicateCondition,
    PresenceCondition,
    QuantifierOperator,
    QuantifierPlan,
    RelationCondition,
    RelationOperator,
    SplitLinesDerivation,
    ValueType,
)
from agent_guardrail.core.matcher import SnapshotMatcher
from agent_guardrail.core.monitor import MatchMonitor
from agent_guardrail.models import (
    AnalysisErrorCode,
    AnalysisScope,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    FindingEmission,
    MessageRole,
    PendingTrace,
    Phase,
    Trace,
)


def event(
    event_id: str,
    sequence: int,
    kind: EventKind,
    payload: dict[str, object],
    *,
    phase: Phase | None = None,
    origin: EventOrigin = EventOrigin.CLIENT_ASSERTED,
    relations: tuple[EventRelation, ...] = (),
    metadata: dict[str, object] | None = None,
) -> Event:
    default_phases = {
        EventKind.MESSAGE: Phase.PRE_LLM,
        EventKind.TOOL_CALL: Phase.PRE_TOOL,
        EventKind.TOOL_RESULT: Phase.POST_TOOL,
    }
    return Event.model_validate(
        {
            "id": event_id,
            "trace_id": "trace-1",
            "sequence": sequence,
            "kind": kind,
            "phase": phase or default_phases[kind],
            "timestamp": datetime(2026, 8, 10, tzinfo=UTC),
            "origin": origin,
            "payload": payload,
            "metadata": metadata or {},
            "relations": relations,
        }
    )


def message(
    event_id: str,
    sequence: int,
    text: str,
    *,
    role: MessageRole = MessageRole.USER,
    phase: Phase = Phase.PRE_LLM,
) -> Event:
    return event(
        event_id,
        sequence,
        EventKind.MESSAGE,
        {"role": role.value, "content": {"type": "text", "text": text}},
        phase=phase,
    )


def call(
    event_id: str,
    sequence: int,
    name: str,
    arguments: dict[str, object] | None = None,
    *,
    relations: tuple[EventRelation, ...] = (),
) -> Event:
    return event(
        event_id,
        sequence,
        EventKind.TOOL_CALL,
        {"call_id": f"call-{event_id}", "name": name, "arguments": arguments or {}},
        relations=relations,
    )


def result(
    event_id: str,
    sequence: int,
    name: str,
    output: object,
    *,
    source: str | None = None,
) -> Event:
    relations = (EventRelation(source_event_id=source),) if source is not None else ()
    return event(
        event_id,
        sequence,
        EventKind.TOOL_RESULT,
        {"call_id": f"call-{event_id}", "name": name, "output": output},
        relations=relations,
    )


def trace(*events: Event) -> Trace:
    return Trace(id="trace-1", events=events)


def pending_trace(
    past: tuple[Event, ...],
    pending: tuple[Event, ...],
) -> PendingTrace:
    return PendingTrace(
        trace=trace(*past),
        events=pending,
        primary_event_id=pending[-1].id,
    )


def field(binding: str, *path: str | int) -> FieldValue:
    return FieldValue(binding=binding, path=path)


def compare(
    left: FieldValue | BindingValue | ParameterValue | DerivedValue,
    operator: ComparisonOperator,
    right: LiteralValue | LiteralListValue | NullValue | ParameterValue,
    *,
    capture: str | None = None,
) -> MatchCondition:
    return MatchCondition(
        compare=Comparison(
            id=capture,
            left=left,
            operator=operator,
            right=right,
        )
    )


def relation(source: str, target: str, operator: RelationOperator) -> MatchCondition:
    return MatchCondition(
        relation=RelationCondition(source=source, target=target, operator=operator)
    )


def rule(
    *,
    rule_id: str = "test_rule",
    bindings: tuple[EventBinding, ...] = (
        EventBinding(name="event", kind=EventKind.MESSAGE),
    ),
    where: MatchCondition | None = None,
    collections: tuple[CollectionBinding, ...] = (),
    derive: tuple[SplitLinesDerivation, ...] = (),
    subjects: tuple[str, ...] = ("event",),
    finding_bindings: tuple[str, ...] | None = None,
    evidence: tuple[EvidenceProjection, ...] = (),
    limits: MatchLimitOverrides | None = None,
) -> MatchRulePlan:
    return MatchRulePlan(
        id=rule_id,
        event_bindings=bindings,
        derive=derive,
        collection_bindings=collections,
        where=where
        or compare(
            field(bindings[0].name, "payload", "content", "text"),
            ComparisonOperator.CONTAINS,
            LiteralValue(value="blocked"),
        ),
        finding=FindingTemplate(
            code="matched",
            message="Static safe explanation",
            subjects=subjects,
            bindings=finding_bindings
            or (
                *(binding.name for binding in bindings),
                *(binding.name for binding in collections),
            ),
            evidence=evidence,
        ),
        limits=limits or MatchLimitOverrides(),
    )


def plan(
    *rules: MatchRulePlan,
    limits: MatchLimits | None = None,
    parameters: tuple[ParameterDeclaration, ...] = (),
    scopes: tuple[AnalysisScope, ...] = (AnalysisScope.SNAPSHOT,),
) -> MatchPlan:
    return MatchPlan(
        scopes=scopes,
        rules=rules,
        limits=limits or MatchLimits(),
        parameters=parameters,
    )


def matcher(match_plan: MatchPlan) -> SnapshotMatcher:
    return SnapshotMatcher(
        match_plan,
        policy_version=3,
        policy_hash="policy-hash-1234",
    )


def monitor(
    match_plan: MatchPlan,
    *,
    max_finding_identities: int = 100_000,
) -> MatchMonitor:
    return MatchMonitor(
        match_plan,
        policy_version=3,
        policy_hash="policy-hash-1234",
        max_finding_identities=max_finding_identities,
    )


@pytest.mark.asyncio
async def test_i01_typed_event_selection_is_stateless_and_filters_phase() -> None:
    selected = rule(
        bindings=(
            EventBinding(
                name="event",
                kind=EventKind.MESSAGE,
                phases=(Phase.POST_LLM,),
            ),
        ),
        where=MatchCondition(
            all=(
                compare(
                    field("event", "payload", "role"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="assistant"),
                ),
                compare(
                    field("event", "payload", "content", "text"),
                    ComparisonOperator.CONTAINS,
                    LiteralValue(value="blocked"),
                ),
            )
        ),
    )
    snapshot = trace(
        message("m1", 0, "blocked", role=MessageRole.USER),
        message(
            "m2",
            1,
            "blocked text",
            role=MessageRole.ASSISTANT,
            phase=Phase.POST_LLM,
        ),
        call("c1", 2, "blocked"),
    )
    analyzer = matcher(plan(selected))

    first = await analyzer.analyze(snapshot)
    second = await analyzer.analyze(snapshot)

    assert first == second
    assert [finding.subject_event_ids for finding in first.findings] == [("m2",)]
    assert first.errors == ()
    assert snapshot.events[1].payload["content"]["text"] == "blocked text"  # type: ignore[index]


@pytest.mark.asyncio
async def test_i02_named_bindings_use_directional_cartesian_assignments() -> None:
    multi = rule(
        bindings=(
            EventBinding(name="m1", kind=EventKind.MESSAGE),
            EventBinding(name="m2", kind=EventKind.MESSAGE),
            EventBinding(name="target", kind=EventKind.TOOL_CALL),
        ),
        where=MatchCondition(
            all=(
                relation("m1", "m2", RelationOperator.PRECEDES),
                relation("m2", "target", RelationOperator.PRECEDES),
                compare(
                    field("m1", "payload", "role"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="user"),
                ),
                compare(
                    field("m2", "payload", "role"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="user"),
                ),
                compare(
                    field("target", "payload", "name"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="send_email"),
                ),
            )
        ),
        subjects=("target",),
        finding_bindings=("m1", "m2", "target"),
        limits=MatchLimitOverrides(binding_combinations=4),
    )
    report = await matcher(plan(multi)).analyze(
        trace(message("m1", 0, "first"), message("m2", 1, "second"), call("c1", 2, "send_email"))
    )

    assert len(report.findings) == 1
    assert [binding.event_id for binding in report.findings[0].bindings] == ["m1", "m2", "c1"]


@pytest.mark.asyncio
async def test_i02_binding_combination_budget_fails_atomically() -> None:
    bounded = rule(
        bindings=(
            EventBinding(name="left", kind=EventKind.MESSAGE),
            EventBinding(name="right", kind=EventKind.MESSAGE),
        ),
        where=relation("left", "right", RelationOperator.PRECEDES),
        subjects=("right",),
        finding_bindings=("left", "right"),
        limits=MatchLimitOverrides(binding_combinations=3),
    )
    report = await matcher(plan(bounded)).analyze(
        trace(message("m1", 0, "one"), message("m2", 1, "two"))
    )

    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED
    assert "binding_combinations" in report.errors[0].message


def nested_mail_rule(*, max_items: int = 3) -> MatchRulePlan:
    collection = CollectionBinding(
        name="outgoing_mail",
        source=field("target", "payload", "arguments", "emails"),
        item_type=ValueType.OBJECT,
    )
    return rule(
        bindings=(EventBinding(name="target", kind=EventKind.TOOL_CALL),),
        collections=(collection,),
        where=MatchCondition(
            all=(
                compare(
                    field("target", "payload", "name"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="send_email"),
                ),
                compare(
                    field("outgoing_mail", "to"),
                    ComparisonOperator.NOT_IN,
                    LiteralListValue(items=("alice@example.test",)),
                ),
            )
        ),
        subjects=("target",),
        finding_bindings=("target", "outgoing_mail"),
        limits=MatchLimitOverrides(collection_items=max_items),
    )


@pytest.mark.asyncio
async def test_i03_nested_collection_has_structural_binding_location() -> None:
    report = await matcher(plan(nested_mail_rule())).analyze(
        trace(
            call(
                "c1",
                0,
                "send_email",
                {
                    "emails": [
                        {"to": "alice@example.test"},
                        {"to": "mallory@example.test"},
                    ]
                },
            )
        )
    )

    assert len(report.findings) == 1
    item = report.findings[0].bindings[1]
    assert item.event_id == "c1"
    assert item.location is not None
    assert item.location.path == ("payload", "arguments", "emails", 1)
    assert "mallory@example.test" not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments", [{}, {"emails": "invalid"}])
async def test_i03_missing_or_non_list_collection_is_an_empty_domain(
    arguments: dict[str, object],
) -> None:
    report = await matcher(plan(nested_mail_rule())).analyze(
        trace(call("c1", 0, "send_email", arguments))
    )
    assert report.findings == ()
    assert report.errors == ()


@pytest.mark.asyncio
async def test_i03_collection_budget_counts_visited_items_and_discards_partial_findings() -> None:
    report = await matcher(plan(nested_mail_rule(max_items=2))).analyze(
        trace(call("c1", 0, "send_email", {"emails": [{"to": "a"}, {"to": "b"}, {"to": "c"}]}))
    )
    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED


def derived_rule(*, item_limit: int = 4, byte_limit: int = 128) -> MatchRulePlan:
    derived = SplitLinesDerivation(
        name="lines",
        source=field("event", "payload", "content", "text"),
    )
    collection = CollectionBinding(
        name="line",
        source=DerivedValue(name="lines"),
        item_type=ValueType.STRING,
    )
    return rule(
        derive=(derived,),
        collections=(collection,),
        where=compare(
            BindingValue(name="line"),
            ComparisonOperator.CONTAINS,
            LiteralValue(value="flagged"),
        ),
        finding_bindings=("event", "line"),
        limits=MatchLimitOverrides(
            derived_items=item_limit,
            derived_bytes=byte_limit,
            collection_items=item_limit,
        ),
    )


@pytest.mark.asyncio
async def test_i04_split_lines_produces_stable_per_line_findings() -> None:
    analyzer = matcher(plan(derived_rule()))
    snapshot = trace(message("m1", 0, "safe\nflagged one\nflagged two"))
    report = await analyzer.analyze(snapshot)

    assert len(report.findings) == 2
    assert report == await analyzer.analyze(snapshot)
    assert [finding.bindings[1].location.start for finding in report.findings] == [5, 17]  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "item_limit", "byte_limit", "dimension"),
    [
        ("a\nb\nflagged", 2, 128, "derived_items"),
        ("flagged-xxx", 4, 10, "derived_bytes"),
    ],
)
async def test_i04_derived_budgets_are_failures(
    text: str,
    item_limit: int,
    byte_limit: int,
    dimension: str,
) -> None:
    selected = derived_rule(item_limit=item_limit, byte_limit=byte_limit)
    report = await matcher(plan(selected)).analyze(trace(message("m1", 0, text)))
    assert report.findings == ()
    assert dimension in report.errors[0].message


@pytest.mark.asyncio
async def test_boolean_presence_null_and_incomplete_not_are_deterministic() -> None:
    conditions = MatchCondition(
        all=(
            MatchCondition(
                present=PresenceCondition(
                    field=field("event", "payload", "arguments", "optional")
                )
            ),
            compare(
                field("event", "payload", "arguments", "optional"),
                ComparisonOperator.EQUALS,
                NullValue(),
            ),
            MatchCondition(
                any=(
                    compare(
                        field("event", "payload", "arguments", "value"),
                        ComparisonOperator.EQUALS,
                        LiteralValue(value="yes"),
                    ),
                    compare(
                        field("event", "payload", "arguments", "value"),
                        ComparisonOperator.NOT_EQUALS,
                        LiteralValue(value="no"),
                    ),
                )
            ),
        )
    )
    selected = rule(
        bindings=(EventBinding(name="event", kind=EventKind.TOOL_CALL),),
        where=conditions,
        subjects=("event",),
    )
    hit = await matcher(plan(selected)).analyze(
        trace(call("c1", 0, "tool", {"optional": None, "value": "yes"}))
    )
    missing = await matcher(plan(selected)).analyze(trace(call("c1", 0, "tool")))

    assert len(hit.findings) == 1
    assert missing.findings == ()


def quantified_rule(*, candidate_limit: int = 6) -> MatchRulePlan:
    quantified = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.COUNT,
            binding=EventBinding(name="item", kind=EventKind.TOOL_RESULT),
            where=MatchCondition(
                all=(
                    relation("target", "item", RelationOperator.DERIVED_FROM_DIRECT),
                    compare(
                        field("item", "payload", "output"),
                        ComparisonOperator.CONTAINS,
                        LiteralValue(value="django"),
                    ),
                )
            ),
            count=CountBounds(minimum=2, maximum=3),
        )
    )
    return rule(
        bindings=(EventBinding(name="target", kind=EventKind.TOOL_CALL),),
        where=quantified,
        subjects=("target",),
        finding_bindings=("target",),
        limits=MatchLimitOverrides(candidate_events=candidate_limit, quantifier_iterations=4),
    )


@pytest.mark.asyncio
async def test_i06_count_quantifier_closes_over_outer_binding() -> None:
    snapshot = trace(
        call("c1", 0, "scroll_down"),
        call("c2", 1, "other"),
        result("r1", 2, "scroll_down", "django-1", source="c1"),
        result("r2", 3, "scroll_down", "django-2", source="c1"),
    )
    report = await matcher(plan(quantified_rule())).analyze(snapshot)

    assert [finding.subject_event_ids for finding in report.findings] == [("c1",)]


@pytest.mark.asyncio
async def test_quantifier_exists_forall_and_collection_domains() -> None:
    exists = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.EXISTS,
            binding=CollectionBinding(
                name="item",
                source=field("event", "payload", "arguments", "items"),
                item_type=ValueType.INTEGER,
            ),
            where=compare(
                BindingValue(name="item"),
                ComparisonOperator.EQUALS,
                LiteralValue(value=2),
            ),
        )
    )
    forall = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.FORALL,
            binding=CollectionBinding(
                name="item2",
                source=field("event", "payload", "arguments", "empty"),
                item_type=ValueType.STRING,
            ),
            where=compare(
                BindingValue(name="item2"),
                ComparisonOperator.NOT_EQUALS,
                LiteralValue(value="bad"),
            ),
        )
    )
    selected = rule(
        bindings=(EventBinding(name="event", kind=EventKind.TOOL_CALL),),
        where=MatchCondition(all=(exists, forall)),
        subjects=("event",),
    )
    report = await matcher(plan(selected)).analyze(
        trace(call("c1", 0, "tool", {"items": [1, True, 2], "empty": []}))
    )
    assert len(report.findings) == 1


@pytest.mark.asyncio
async def test_i06_quantifier_budget_is_not_a_no_match() -> None:
    bounded = quantified_rule(candidate_limit=3)
    report = await matcher(plan(bounded)).analyze(
        trace(
            call("c1", 0, "scroll_down"),
            result("r1", 1, "scroll_down", "django", source="c1"),
            result("r2", 2, "scroll_down", "django", source="c1"),
            result("r3", 3, "scroll_down", "django", source="c1"),
        )
    )
    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED


def relation_rule(operator: RelationOperator) -> MatchRulePlan:
    return rule(
        rule_id=f"relation_{operator.value}",
        bindings=(
            EventBinding(name="source", kind=EventKind.TOOL_CALL),
            EventBinding(name="target", kind=EventKind.TOOL_CALL),
        ),
        where=relation("source", "target", operator),
        subjects=("target",),
        finding_bindings=("source", "target"),
    )


@pytest.mark.asyncio
async def test_i07_order_never_becomes_provenance() -> None:
    snapshot = trace(call("c1", 0, "read"), call("c2", 1, "send"))
    before = snapshot.model_dump_json()
    report = await matcher(
        plan(
            relation_rule(RelationOperator.PRECEDES),
            relation_rule(RelationOperator.IMMEDIATELY_PRECEDES),
            relation_rule(RelationOperator.MAY_INFLUENCE),
            relation_rule(RelationOperator.DERIVED_FROM_DIRECT),
        )
    ).analyze(snapshot)

    assert len(report.findings) == 3
    assert all(finding.subject_event_ids == ("c2",) for finding in report.findings)
    assert snapshot.model_dump_json() == before
    assert snapshot.events[1].relations == ()


@pytest.mark.asyncio
async def test_immediate_precedes_requires_consecutive_trusted_sequences() -> None:
    snapshot = trace(call("c1", 0, "read"), call("c2", 2, "send"))
    report = await matcher(
        plan(relation_rule(RelationOperator.IMMEDIATELY_PRECEDES))
    ).analyze(snapshot)
    assert report.findings == ()


@pytest.mark.asyncio
async def test_i08_direct_and_ancestor_relations_are_distinct() -> None:
    snapshot = trace(
        call("c0", 0, "read_private"),
        result("r1", 1, "read_private", "redacted", source="c0"),
        call("c1", 2, "send", relations=(EventRelation(source_event_id="r1"),)),
    )
    direct = rule(
        rule_id="direct",
        bindings=(
            EventBinding(name="source", kind=EventKind.TOOL_RESULT),
            EventBinding(name="target", kind=EventKind.TOOL_CALL),
        ),
        where=relation("source", "target", RelationOperator.DERIVED_FROM_DIRECT),
        subjects=("target",),
        finding_bindings=("source", "target"),
    )
    ancestor = relation_rule(RelationOperator.DERIVED_FROM_ANCESTOR)
    report = await matcher(plan(direct, ancestor)).analyze(snapshot)

    assert [(finding.rule_id, finding.subject_event_ids) for finding in report.findings] == [
        ("direct", ("c1",)),
        ("relation_derived_from_ancestor", ("c1",)),
    ]


@pytest.mark.asyncio
async def test_snapshot_pending_binding_has_an_empty_domain() -> None:
    selected = rule(
        bindings=(
            EventBinding(name="event", kind=EventKind.MESSAGE, domain=BindingDomain.PENDING),
        )
    )
    report = await matcher(plan(selected)).analyze(trace(message("m1", 0, "blocked")))
    assert report.findings == ()
    assert report.errors == ()


@pytest.mark.asyncio
async def test_i10_stateless_pending_analysis_filters_past_only_subjects() -> None:
    selected = rule(
        bindings=(
            EventBinding(
                name="event",
                kind=EventKind.MESSAGE,
                domain=BindingDomain.VISIBLE,
            ),
        ),
        where=compare(
            field("event", "payload", "content", "text"),
            ComparisonOperator.CONTAINS,
            LiteralValue(value="blocked"),
        ),
    )
    batch = pending_trace(
        (message("h1", 0, "blocked historical", phase=Phase.POST_LLM),),
        (
            message("n1", 1, "blocked one", phase=Phase.POST_LLM),
            message("n2", 2, "blocked two", phase=Phase.POST_LLM),
            message("n3", 3, "safe", phase=Phase.POST_LLM),
        ),
    )
    report = await matcher(
        plan(selected, scopes=(AnalysisScope.PENDING,))
    ).analyze_pending(batch)

    assert report.scope is AnalysisScope.PENDING
    assert report.emission is FindingEmission.ALL
    assert report.event_ids == ("h1", "n1", "n2", "n3")
    assert report.pending_event_ids == ("n1", "n2", "n3")
    assert [finding.subject_event_ids for finding in report.findings] == [
        ("n1",),
        ("n2",),
    ]


@pytest.mark.asyncio
async def test_i10_pending_domains_can_join_past_and_the_whole_batch() -> None:
    selected = rule(
        bindings=(
            EventBinding(
                name="history",
                kind=EventKind.MESSAGE,
                domain=BindingDomain.PAST,
            ),
            EventBinding(
                name="pending_message",
                kind=EventKind.MESSAGE,
                domain=BindingDomain.PENDING,
            ),
            EventBinding(
                name="target",
                kind=EventKind.TOOL_CALL,
                domain=BindingDomain.PENDING,
            ),
        ),
        where=MatchCondition(
            all=(
                relation("history", "pending_message", RelationOperator.PRECEDES),
                relation("pending_message", "target", RelationOperator.PRECEDES),
                compare(
                    field("target", "payload", "name"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="send_email"),
                ),
            )
        ),
        subjects=("target",),
        finding_bindings=("history", "pending_message", "target"),
    )
    pending_call = event(
        "n2",
        2,
        EventKind.TOOL_CALL,
        {"call_id": "call-1", "name": "send_email", "arguments": {}},
        phase=Phase.PRE_LLM,
    )
    batch = pending_trace(
        (message("h1", 0, "first", phase=Phase.PRE_LLM),),
        (message("n1", 1, "second", phase=Phase.PRE_LLM), pending_call),
    )
    report = await matcher(
        plan(selected, scopes=(AnalysisScope.PENDING,))
    ).analyze_pending(batch)

    assert len(report.findings) == 1
    assert [binding.event_id for binding in report.findings[0].bindings] == [
        "h1",
        "n1",
        "n2",
    ]


@pytest.mark.asyncio
async def test_past_only_matches_do_not_consume_pending_finding_budget() -> None:
    selected = rule(limits=MatchLimitOverrides(findings=1))
    batch = pending_trace(
        (message("h1", 0, "blocked old"),),
        (message("n1", 1, "blocked new"),),
    )
    report = await matcher(
        plan(selected, scopes=(AnalysisScope.PENDING,))
    ).analyze_pending(batch)
    assert [finding.subject_event_ids for finding in report.findings] == [("n1",)]
    assert report.errors == ()


@pytest.mark.asyncio
async def test_pending_scope_mismatch_is_an_input_error() -> None:
    batch = pending_trace((), (message("n1", 0, "blocked"),))
    report = await matcher(plan(rule())).analyze_pending(batch)
    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.INPUT_ERROR


@pytest.mark.asyncio
async def test_snapshot_scope_mismatch_is_an_input_error() -> None:
    report = await matcher(
        plan(rule(), scopes=(AnalysisScope.PENDING,))
    ).analyze(trace(message("m1", 0, "blocked")))
    assert report.errors[0].code is AnalysisErrorCode.INPUT_ERROR


@pytest.mark.asyncio
async def test_i12_uncompiled_capability_is_an_explicit_rule_error() -> None:
    capability_rule = rule(
        rule_id="capability",
        where=MatchCondition(
            all=(
                compare(
                    field("event", "payload", "content", "text"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="never"),
                ),
                MatchCondition(
                    detector=DetectorCondition(
                        id="fact",
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
        ),
    )
    structural = rule(rule_id="structural")
    report = await matcher(plan(capability_rule, structural)).analyze(
        trace(message("m1", 0, "blocked"))
    )

    assert [finding.rule_id for finding in report.findings] == ["structural"]
    assert report.errors[0].code is AnalysisErrorCode.CAPABILITY_ERROR
    assert report.errors[0].capability == "prompt_injection"


@pytest.mark.asyncio
async def test_predicate_capability_is_also_deferred_before_empty_search() -> None:
    selected = rule(
        where=MatchCondition(
            predicate=PredicateCondition(id="check", capability="trusted_check")
        )
    )
    report = await matcher(plan(selected)).analyze(trace())
    assert report.errors[0].code is AnalysisErrorCode.CAPABILITY_ERROR
    assert report.errors[0].capability == "trusted_check"


@pytest.mark.asyncio
async def test_i13_repeated_ranges_are_masked_and_payload_free() -> None:
    ranged = rule(
        where=compare(
            field("event", "payload", "content", "text"),
            ComparisonOperator.CONTAINS,
            LiteralValue(value="marker"),
            capture="range_match",
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.MATCHER,
                id="range_match",
                masked_evidence="******",
            ),
        ),
    )
    report = await matcher(plan(ranged)).analyze(
        trace(message("m1", 0, "AA marker BB marker"))
    )
    finding = report.findings[0]

    assert [(location.start, location.end) for location in finding.locations] == [(3, 9), (13, 19)]
    assert [item.masked_evidence for item in finding.evidence] == ["******", "******"]
    serialized = report.model_dump_json()
    assert "AA marker BB marker" not in serialized
    assert '"marker"' not in serialized


@pytest.mark.asyncio
async def test_matcher_evidence_can_omit_locations() -> None:
    selected = rule(
        where=compare(
            field("event", "payload", "content", "text"),
            ComparisonOperator.EQUALS,
            LiteralValue(value="safe"),
            capture="equal_match",
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.MATCHER,
                id="equal_match",
                include_locations=False,
            ),
        ),
    )
    finding = (await matcher(plan(selected)).analyze(trace(message("m1", 0, "safe")))).findings[0]
    assert finding.locations == ()
    assert finding.evidence[0].location is None


@pytest.mark.asyncio
async def test_unselected_boolean_branch_does_not_fabricate_evidence() -> None:
    selected = rule(
        where=MatchCondition(
            any=(
                compare(
                    field("event", "payload", "content", "text"),
                    ComparisonOperator.CONTAINS,
                    LiteralValue(value="absent"),
                    capture="unused_match",
                ),
                compare(
                    field("event", "payload", "content", "text"),
                    ComparisonOperator.EQUALS,
                    LiteralValue(value="safe"),
                ),
            )
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.MATCHER,
                id="unused_match",
            ),
        ),
    )
    finding = (
        await matcher(plan(selected)).analyze(trace(message("m1", 0, "safe")))
    ).findings[0]
    assert finding.evidence == ()


def parameter_rule() -> MatchRulePlan:
    return rule(
        bindings=(EventBinding(name="event", kind=EventKind.TOOL_CALL),),
        where=compare(
            ParameterValue(name="principal"),
            ComparisonOperator.NOT_EQUALS,
            LiteralValue(value="admin"),
        ),
        subjects=("event",),
        finding_bindings=("event", "principal"),
    )


@pytest.mark.asyncio
async def test_i14_trusted_parameter_cannot_be_overridden_by_payload() -> None:
    analyzer = matcher(
        plan(
            parameter_rule(),
            parameters=(ParameterDeclaration(name="principal", type=ParameterType.STRING),),
        )
    )
    report = await analyzer.analyze(
        trace(call("c1", 0, "read", {"principal": "admin"})),
        parameters={"principal": "alice"},
    )

    assert len(report.findings) == 1
    principal = report.findings[0].bindings[1]
    assert principal.event_id is None
    assert "alice" not in report.model_dump_json()
    assert "admin" not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "parameters",
    [None, {"principal": 7}, {"principal": "admin", "extra": True}],
)
async def test_i14_parameter_errors_happen_before_rule_search(
    parameters: dict[str, object] | None,
) -> None:
    analyzer = matcher(
        plan(
            parameter_rule(),
            parameters=(ParameterDeclaration(name="principal", type=ParameterType.STRING),),
        )
    )
    report = await analyzer.analyze(trace(call("c1", 0, "read")), parameters=parameters)
    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.PARAMETER_ERROR


@pytest.mark.asyncio
async def test_optional_parameter_default_and_not_contains_are_supported() -> None:
    selected = rule(
        where=compare(
            field("event", "payload", "content", "text"),
            ComparisonOperator.NOT_CONTAINS,
            ParameterValue(name="needle"),
        ),
        finding_bindings=("event", "needle"),
    )
    analyzer = matcher(
        plan(
            selected,
            parameters=(
                ParameterDeclaration(
                    name="needle",
                    type=ParameterType.STRING,
                    required=False,
                    default="forbidden",
                ),
            ),
        )
    )
    report = await analyzer.analyze(trace(message("m1", 0, "safe")))
    assert len(report.findings) == 1


def test_matcher_constructor_and_empty_literal_search_are_strict() -> None:
    match_plan = plan(rule())
    with pytest.raises(TypeError, match="integer"):
        SnapshotMatcher(match_plan, policy_version=True, policy_hash="policy-hash")
    with pytest.raises(ValueError, match="trimmed"):
        SnapshotMatcher(match_plan, policy_version=1, policy_hash=" policy-hash")
    with pytest.raises(ValidationError, match="empty literal"):
        Comparison(
            left=field("event", "payload", "content", "text"),
            operator=ComparisonOperator.CONTAINS,
            right=LiteralValue(value=""),
        )


@pytest.mark.asyncio
async def test_rule_budget_failure_does_not_discard_other_rule_findings() -> None:
    failing = rule(
        rule_id="failing",
        limits=MatchLimitOverrides(findings=1),
    )
    succeeding = rule(rule_id="succeeding")
    report = await matcher(plan(failing, succeeding)).analyze(
        trace(message("m1", 0, "blocked"), message("m2", 1, "blocked"))
    )

    assert [finding.rule_id for finding in report.findings] == ["succeeding", "succeeding"]
    assert report.errors[0].rule_id == "failing"


@pytest.mark.asyncio
async def test_global_budget_exhaustion_stops_later_rules() -> None:
    first = rule(rule_id="first")
    second = rule(rule_id="second")
    global_limits = MatchLimits(findings=1)
    report = await matcher(plan(first, second, limits=global_limits)).analyze(
        trace(message("m1", 0, "blocked"))
    )

    assert [finding.rule_id for finding in report.findings] == ["first"]
    assert report.errors[0].rule_id == "second"


@pytest.mark.asyncio
async def test_i11_monitor_emits_only_new_committed_snapshot_findings() -> None:
    analyzer = monitor(plan(rule()))
    first_snapshot = trace(message("h1", 0, "blocked old"))

    first = await analyzer.analyze(first_snapshot)
    repeated = await analyzer.analyze(first_snapshot.model_copy(deep=True))
    appended = await analyzer.analyze(
        trace(
            message("h1", 0, "blocked old"),
            message("n1", 1, "blocked new"),
        )
    )
    safe_append = await analyzer.analyze(
        trace(
            message("h1", 0, "blocked old"),
            message("n1", 1, "blocked new"),
            message("n2", 2, "safe"),
        )
    )

    assert first.emission is FindingEmission.NEW
    assert [finding.subject_event_ids for finding in first.findings] == [("h1",)]
    assert repeated.findings == ()
    assert [finding.subject_event_ids for finding in appended.findings] == [("n1",)]
    assert safe_append.findings == ()
    assert analyzer.seen_count == 2


@pytest.mark.asyncio
async def test_pending_findings_are_tentative_and_repeat_until_committed() -> None:
    selected_plan = plan(
        rule(),
        scopes=(AnalysisScope.SNAPSHOT, AnalysisScope.PENDING),
    )
    analyzer = monitor(selected_plan)
    batch = pending_trace((), (message("n1", 0, "blocked"),))

    first = await analyzer.analyze_pending(batch)
    retry = await analyzer.analyze_pending(batch.model_copy(deep=True))

    assert first.emission is FindingEmission.NEW
    assert len(first.findings) == 1
    assert retry.findings == first.findings
    assert analyzer.seen_count == 0

    committed = await analyzer.analyze(trace(message("n1", 0, "blocked")))
    repeated = await analyzer.analyze(trace(message("n1", 0, "blocked")))
    assert committed.findings == first.findings
    assert repeated.findings == ()
    assert analyzer.seen_count == 1


@pytest.mark.asyncio
async def test_monitor_pending_analysis_filters_already_committed_findings() -> None:
    selected_plan = plan(
        rule(),
        scopes=(AnalysisScope.SNAPSHOT, AnalysisScope.PENDING),
    )
    analyzer = monitor(selected_plan)
    await analyzer.analyze(trace(message("h1", 0, "blocked old")))
    batch = pending_trace(
        (message("h1", 0, "blocked old"),),
        (message("n1", 1, "blocked new"),),
    )

    report = await analyzer.analyze_pending(batch)

    assert [finding.subject_event_ids for finding in report.findings] == [("n1",)]
    assert analyzer.seen_count == 1


@pytest.mark.asyncio
async def test_monitor_errors_do_not_advance_dedupe_state() -> None:
    capability_rule = rule(
        rule_id="capability",
        where=MatchCondition(
            predicate=PredicateCondition(id="check", capability="trusted_check")
        ),
    )
    selected_plan = plan(capability_rule, rule(rule_id="structural"))
    analyzer = monitor(selected_plan)
    snapshot = trace(message("m1", 0, "blocked"))

    first = await analyzer.analyze(snapshot)
    retry = await analyzer.analyze(snapshot)

    assert [finding.rule_id for finding in first.findings] == ["structural"]
    assert retry.findings == first.findings
    assert first.errors[0].code is AnalysisErrorCode.CAPABILITY_ERROR
    assert analyzer.seen_count == 0


@pytest.mark.asyncio
async def test_monitor_identity_state_budget_is_atomic_and_retryable() -> None:
    analyzer = monitor(plan(rule()), max_finding_identities=1)
    oversized = trace(
        message("m1", 0, "blocked one"),
        message("m2", 1, "blocked two"),
    )

    first = await analyzer.analyze(oversized)
    retry = await analyzer.analyze(oversized)

    assert first.findings == ()
    assert first.errors[0].code is AnalysisErrorCode.RESOURCE_EXHAUSTED
    assert retry == first
    assert analyzer.seen_count == 0

    accepted = await analyzer.analyze(trace(message("m1", 0, "blocked one")))
    assert len(accepted.findings) == 1
    assert analyzer.seen_count == 1


@pytest.mark.asyncio
async def test_monitor_state_is_namespaced_by_trace_and_resettable() -> None:
    analyzer = monitor(plan(rule()))
    first = trace(message("m1", 0, "blocked"))
    second_event = message("m1", 0, "blocked").model_copy(
        update={"trace_id": "trace-2"},
        deep=True,
    )
    second = Trace(id="trace-2", events=(second_event,))

    assert len((await analyzer.analyze(first)).findings) == 1
    assert len((await analyzer.analyze(second)).findings) == 1
    assert analyzer.seen_count == 2

    analyzer.reset("trace-1")
    assert analyzer.seen_count == 1
    assert len((await analyzer.analyze(first)).findings) == 1
    analyzer.reset()
    assert analyzer.seen_count == 0


def test_monitor_configuration_and_reset_are_strict() -> None:
    with pytest.raises(TypeError, match="integer"):
        monitor(plan(rule()), max_finding_identities=True)
    with pytest.raises(ValueError, match="hard bounds"):
        monitor(plan(rule()), max_finding_identities=0)

    analyzer = monitor(plan(rule()))
    with pytest.raises(TypeError, match="string"):
        analyzer.reset(7)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="trimmed"):
        analyzer.reset(" trace-1")
