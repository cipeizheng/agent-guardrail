from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_guardrail.core.match_plan import (
    BindingDomain,
    BindingValue,
    CollectionBinding,
    Comparison,
    ComparisonOperator,
    CostDimension,
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
    MatchBudgetExceeded,
    MatchCondition,
    MatchCostLedger,
    MatchLimitOverrides,
    MatchLimits,
    MatchPlan,
    MatchRulePlan,
    ParameterDeclaration,
    ParameterType,
    ParameterValue,
    PredicateCondition,
    QuantifierOperator,
    QuantifierPlan,
    RelationCondition,
    RelationOperator,
    SplitLinesDerivation,
    ValueType,
)
from agent_guardrail.models import AnalysisScope, EventKind, EventOrigin


def literal(value: str | int | float | bool) -> LiteralValue:
    return LiteralValue(value=value)


def field(binding: str, *path: str | int) -> FieldValue:
    return FieldValue(binding=binding, path=path)


def comparison(
    left: FieldValue | BindingValue | DerivedValue | ParameterValue,
    operator: ComparisonOperator,
    right: LiteralValue | LiteralListValue,
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


def simple_rule(
    *,
    rule_id: str = "typed_message",
    where: MatchCondition | None = None,
    event_bindings: tuple[EventBinding, ...] | None = None,
    derive: tuple[SplitLinesDerivation, ...] = (),
    collection_bindings: tuple[CollectionBinding, ...] = (),
    finding_bindings: tuple[str, ...] | None = None,
    subjects: tuple[str, ...] | None = None,
    evidence: tuple[EvidenceProjection, ...] = (),
    limits: MatchLimitOverrides | None = None,
) -> MatchRulePlan:
    selected_events = event_bindings or (
        EventBinding(name="message", kind=EventKind.MESSAGE),
    )
    return MatchRulePlan(
        id=rule_id,
        event_bindings=selected_events,
        derive=derive,
        collection_bindings=collection_bindings,
        where=where
        or comparison(
            field(selected_events[0].name, "payload", "content", "text"),
            ComparisonOperator.CONTAINS,
            literal("blocked"),
        ),
        finding=FindingTemplate(
            code="matched",
            message="Static policy explanation",
            subjects=subjects or (selected_events[0].name,),
            bindings=finding_bindings
            or (
                *(binding.name for binding in selected_events),
                *(binding.name for binding in collection_bindings),
            ),
            evidence=evidence,
        ),
        limits=limits or MatchLimitOverrides(),
    )


def plan_for(
    *rules: MatchRulePlan,
    scopes: tuple[AnalysisScope, ...] = (AnalysisScope.SNAPSHOT,),
    parameters: tuple[ParameterDeclaration, ...] = (),
    limits: MatchLimits | None = None,
) -> MatchPlan:
    return MatchPlan(
        scopes=scopes,
        parameters=parameters,
        limits=limits or MatchLimits(),
        rules=rules,
    )


def test_match_plan_represents_i01_i05_without_an_anchor() -> None:
    typed = simple_rule(
        where=MatchCondition(
            all=(
                comparison(
                    field("message", "payload", "role"),
                    ComparisonOperator.EQUALS,
                    literal("assistant"),
                ),
                comparison(
                    field("message", "payload", "content", "text"),
                    ComparisonOperator.CONTAINS,
                    literal("blocked"),
                ),
            )
        )
    )
    multi = simple_rule(
        rule_id="multi_event",
        event_bindings=(
            EventBinding(name="m1", kind=EventKind.MESSAGE),
            EventBinding(name="m2", kind=EventKind.MESSAGE),
            EventBinding(name="call", kind=EventKind.TOOL_CALL),
        ),
        where=MatchCondition(
            all=(
                MatchCondition(
                    relation=RelationCondition(
                        source="m1",
                        target="call",
                        operator=RelationOperator.PRECEDES,
                    )
                ),
                MatchCondition(
                    relation=RelationCondition(
                        source="m2",
                        target="call",
                        operator=RelationOperator.PRECEDES,
                    )
                ),
                comparison(
                    field("call", "payload", "name"),
                    ComparisonOperator.EQUALS,
                    literal("send_email"),
                ),
            )
        ),
        subjects=("call",),
        finding_bindings=("m1", "m2", "call"),
    )
    nested = simple_rule(
        rule_id="nested_mail",
        event_bindings=(EventBinding(name="call", kind=EventKind.TOOL_CALL),),
        collection_bindings=(
            CollectionBinding(
                name="outgoing_mail",
                source=field("call", "payload", "arguments", "emails"),
                item_type=ValueType.OBJECT,
            ),
        ),
        where=comparison(
            field("outgoing_mail", "recipient"),
            ComparisonOperator.NOT_IN,
            LiteralListValue(items=("allowed@example.test",)),
        ),
        subjects=("call",),
        finding_bindings=("call", "outgoing_mail"),
    )
    derived = simple_rule(
        rule_id="derived_lines",
        derive=(
            SplitLinesDerivation(
                name="lines",
                source=field("message", "payload", "content", "text"),
            ),
        ),
        collection_bindings=(
            CollectionBinding(
                name="line",
                source=DerivedValue(name="lines"),
                item_type=ValueType.STRING,
            ),
        ),
        where=comparison(
            BindingValue(name="line"),
            ComparisonOperator.CONTAINS,
            literal("token"),
        ),
        finding_bindings=("message", "line"),
    )
    predicates = simple_rule(
        rule_id="predicate_composition",
        where=MatchCondition(
            all=(
                MatchCondition(
                    predicate=PredicateCondition(
                        id="invalid_role",
                        capability="invalid_role",
                        arguments=(BindingValue(name="message"),),
                    )
                ),
                MatchCondition(
                    predicate=PredicateCondition(
                        id="invalid_pattern",
                        capability="invalid_pattern",
                        arguments=(field("message", "payload", "content", "text"),),
                    )
                ),
            )
        ),
    )

    compiled = plan_for(typed, multi, nested, derived, predicates)
    serialized = json.dumps(compiled.model_dump(mode="json"), sort_keys=True)

    assert len(compiled.rules) == 5
    assert "anchor" not in serialized
    assert "module" not in serialized
    assert "callback" not in serialized


def test_match_plan_represents_i06_quantifier_with_outer_binding_closure() -> None:
    count_results = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.COUNT,
            binding=EventBinding(name="result", kind=EventKind.TOOL_RESULT),
            where=MatchCondition(
                all=(
                    MatchCondition(
                        relation=RelationCondition(
                            source="call",
                            target="result",
                            operator=RelationOperator.DERIVED_FROM_DIRECT,
                        )
                    ),
                    comparison(
                        field("result", "payload", "output"),
                        ComparisonOperator.CONTAINS,
                        literal("django"),
                    ),
                )
            ),
            count=CountBounds(minimum=5),
        )
    )
    rule = simple_rule(
        rule_id="quantified_results",
        event_bindings=(EventBinding(name="call", kind=EventKind.TOOL_CALL),),
        where=count_results,
        subjects=("call",),
        finding_bindings=("call",),
    )

    assert plan_for(rule).rules[0].where.quantify is not None


def test_match_plan_keeps_order_and_provenance_operators_distinct() -> None:
    bindings = (
        EventBinding(name="source", kind=EventKind.TOOL_RESULT),
        EventBinding(name="target", kind=EventKind.TOOL_CALL),
    )
    order = simple_rule(
        rule_id="ordered_flow",
        event_bindings=bindings,
        where=MatchCondition(
            relation=RelationCondition(
                source="source",
                target="target",
                operator=RelationOperator.PRECEDES,
            )
        ),
        subjects=("target",),
        finding_bindings=("source", "target"),
    )
    provenance = simple_rule(
        rule_id="exact_flow",
        event_bindings=bindings,
        where=MatchCondition(
            relation=RelationCondition(
                source="source",
                target="target",
                operator=RelationOperator.DERIVED_FROM_ANCESTOR,
            )
        ),
        subjects=("target",),
        finding_bindings=("source", "target"),
    )

    compiled = plan_for(order, provenance)

    assert compiled.rules[0].where.relation is not None
    assert compiled.rules[0].where.relation.operator is RelationOperator.PRECEDES
    assert compiled.rules[1].where.relation is not None
    assert compiled.rules[1].where.relation.operator is RelationOperator.DERIVED_FROM_ANCESTOR


def test_match_plan_represents_pending_scope_capabilities_ranges_and_parameters() -> None:
    pending = simple_rule(
        rule_id="whole_pending",
        event_bindings=(
            EventBinding(name="history", kind=EventKind.MESSAGE, domain=BindingDomain.PAST),
            EventBinding(name="message", kind=EventKind.MESSAGE, domain=BindingDomain.PENDING),
        ),
        where=MatchCondition(
            relation=RelationCondition(
                source="history",
                target="message",
                operator=RelationOperator.PRECEDES,
            )
        ),
        subjects=("message",),
        finding_bindings=("history", "message"),
    )
    detector = simple_rule(
        rule_id="trusted_detector",
        where=MatchCondition(
            detector=DetectorCondition(
                id="prompt_injection_fact",
                capability="prompt_injection",
                inputs=(
                    DetectorInput(
                        value=field("message", "payload", "content", "text"),
                        encoding=DetectorInputEncoding.TEXT,
                    ),
                ),
                types_any=("prompt_injection",),
            )
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.DETECTOR,
                id="prompt_injection_fact",
            ),
        ),
    )
    ranges = simple_rule(
        rule_id="matcher_ranges",
        where=comparison(
            field("message", "payload", "content", "text"),
            ComparisonOperator.CONTAINS,
            literal("marker"),
            capture="marker_ranges",
        ),
        evidence=(
            EvidenceProjection(
                source=EvidenceProjectionSource.MATCHER,
                id="marker_ranges",
                masked_evidence="******",
            ),
        ),
    )
    parameter = simple_rule(
        rule_id="trusted_principal",
        event_bindings=(EventBinding(name="event", kind=EventKind.TOOL_CALL),),
        where=comparison(
            ParameterValue(name="principal"),
            ComparisonOperator.NOT_EQUALS,
            literal("admin"),
        ),
        subjects=("event",),
        finding_bindings=("event", "principal"),
    )

    compiled = plan_for(
        pending,
        detector,
        ranges,
        parameter,
        scopes=(AnalysisScope.SNAPSHOT, AnalysisScope.PENDING),
        parameters=(
            ParameterDeclaration(name="principal", type=ParameterType.STRING),
        ),
    )

    assert compiled.scopes == (AnalysisScope.SNAPSHOT, AnalysisScope.PENDING)
    assert compiled.rules[0].event_bindings[1].domain is BindingDomain.PENDING
    assert compiled.rules[2].finding.evidence[0].masked_evidence == "******"
    assert compiled.parameters[0].required is True


def test_event_binding_rejects_non_semantic_kinds_and_duplicate_filters() -> None:
    with pytest.raises(ValidationError, match="independent Event kind"):
        EventBinding(name="decision", kind=EventKind.GUARDRAIL_DECISION)
    with pytest.raises(ValidationError, match="origins must be unique"):
        EventBinding(
            name="message",
            kind=EventKind.MESSAGE,
            origins=(EventOrigin.OBSERVED, EventOrigin.OBSERVED),
        )


def test_rule_rejects_unknown_forward_or_unsafe_references() -> None:
    with pytest.raises(ValidationError, match="unknown binding"):
        simple_rule(
            where=comparison(
                field("missing", "payload", "content"),
                ComparisonOperator.CONTAINS,
                literal("blocked"),
            )
        )
    with pytest.raises(ValidationError, match="unknown or forward derivation"):
        simple_rule(
            derive=(
                SplitLinesDerivation(
                    name="first",
                    source=DerivedValue(name="later"),
                ),
                SplitLinesDerivation(
                    name="later",
                    source=field("message", "payload", "content", "text"),
                ),
            )
        )
    with pytest.raises(ValidationError, match="canonical safe envelope"):
        simple_rule(
            where=comparison(
                field("message", "metadata", "principal"),
                ComparisonOperator.EQUALS,
                literal("admin"),
            )
        )


def test_rule_rejects_invalid_subject_binding_and_evidence_projection() -> None:
    collection = CollectionBinding(
        name="item",
        source=field("message", "payload", "content", "text"),
        item_type=ValueType.STRING,
    )
    with pytest.raises(ValidationError, match="subjects must reference"):
        simple_rule(
            collection_bindings=(collection,),
            subjects=("item",),
            finding_bindings=("message", "item"),
        )
    with pytest.raises(ValidationError, match="project every"):
        simple_rule(
            collection_bindings=(collection,),
            finding_bindings=("message",),
        )
    with pytest.raises(ValidationError, match="unknown source"):
        simple_rule(
            evidence=(
                EvidenceProjection(
                    source=EvidenceProjectionSource.DETECTOR,
                    id="not_declared",
                ),
            )
        )


def test_rule_rejects_duplicate_condition_ids_and_quantifier_shadowing() -> None:
    duplicate_ids = MatchCondition(
        all=(
            MatchCondition(
                predicate=PredicateCondition(id="same", capability="first")
            ),
            MatchCondition(
                detector=DetectorCondition(
                    id="same",
                    capability="second",
                    inputs=(
                        DetectorInput(
                            value=field("message", "payload", "content", "text"),
                            encoding=DetectorInputEncoding.TEXT,
                        ),
                    ),
                )
            ),
        )
    )
    with pytest.raises(ValidationError, match="result IDs must be unique"):
        simple_rule(where=duplicate_ids)

    shadowing = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.EXISTS,
            binding=EventBinding(name="message", kind=EventKind.MESSAGE),
            where=comparison(
                field("message", "payload", "content", "text"),
                ComparisonOperator.CONTAINS,
                literal("blocked"),
            ),
        )
    )
    with pytest.raises(ValidationError, match="cannot shadow"):
        simple_rule(where=shadowing)


def test_plan_rejects_projecting_a_lexical_quantifier_binding() -> None:
    quantified = MatchCondition(
        quantify=QuantifierPlan(
            operator=QuantifierOperator.EXISTS,
            binding=EventBinding(name="local_message", kind=EventKind.MESSAGE),
            where=comparison(
                field("local_message", "payload", "content", "text"),
                ComparisonOperator.CONTAINS,
                literal("blocked"),
            ),
        )
    )
    invalid = simple_rule(
        where=quantified,
        finding_bindings=("message", "local_message"),
    )

    with pytest.raises(ValidationError, match="lexical binding"):
        plan_for(invalid)


def test_plan_rejects_unknown_parameters_symbol_collisions_and_duplicate_ids() -> None:
    unknown = simple_rule(
        where=comparison(
            ParameterValue(name="principal"),
            ComparisonOperator.NOT_EQUALS,
            literal("admin"),
        )
    )
    with pytest.raises(ValidationError, match="unknown parameter"):
        plan_for(unknown)

    with pytest.raises(ValidationError, match="cannot shadow"):
        plan_for(
            simple_rule(),
            parameters=(
                ParameterDeclaration(name="message", type=ParameterType.STRING),
            ),
        )

    with pytest.raises(ValidationError, match="Rule IDs must be unique"):
        plan_for(simple_rule(), simple_rule())


def test_parameter_defaults_are_typed_and_provider_payload_is_not_a_parameter_source() -> None:
    optional = ParameterDeclaration(
        name="principal",
        type=ParameterType.STRING,
        required=False,
        default="anonymous",
    )

    assert optional.default == "anonymous"
    assert "provider" not in json.dumps(optional.model_dump(mode="json"))
    with pytest.raises(ValidationError, match="required.*default"):
        ParameterDeclaration(
            name="principal",
            type=ParameterType.STRING,
            default="anonymous",
        )
    with pytest.raises(ValidationError, match="declared type"):
        ParameterDeclaration(
            name="principal",
            type=ParameterType.STRING,
            required=False,
            default=7,
        )
    with pytest.raises(ValidationError, match="optional.*default"):
        ParameterDeclaration(
            name="principal",
            type=ParameterType.STRING,
            required=False,
        )


def test_rule_limits_can_only_lower_analysis_limits() -> None:
    global_limits = MatchLimits(binding_combinations=3, detector_calls=2)
    lowered = simple_rule(
        limits=MatchLimitOverrides(binding_combinations=2, detector_calls=1)
    )
    compiled = plan_for(lowered, limits=global_limits)

    assert lowered.effective_limits(global_limits).binding_combinations == 2
    assert lowered.effective_limits(global_limits).condition_steps == global_limits.condition_steps
    assert compiled.rules[0].limits.detector_calls == 1

    with pytest.raises(ValidationError, match="cannot raise"):
        plan_for(
            simple_rule(limits=MatchLimitOverrides(binding_combinations=4)),
            limits=global_limits,
        )
    with pytest.raises(ValueError, match="cannot raise"):
        MatchLimitOverrides(binding_combinations=4).resolve(global_limits)


@pytest.mark.parametrize("dimension", list(CostDimension))
def test_cost_ledger_accounts_every_dimension(dimension: CostDimension) -> None:
    ledger = MatchCostLedger(plan_for(simple_rule()))

    ledger.consume("typed_message", dimension, 1)
    snapshot = ledger.snapshot()

    assert snapshot.total.value_for(dimension) == 1
    assert snapshot.rules[0].cost.value_for(dimension) == 1


def test_cost_ledger_enforces_rule_and_global_limits_atomically() -> None:
    limits = MatchLimits(binding_combinations=3)
    first = simple_rule(
        rule_id="first",
        limits=MatchLimitOverrides(binding_combinations=2),
    )
    second = simple_rule(rule_id="second")
    ledger = MatchCostLedger(plan_for(first, second, limits=limits))

    ledger.consume("first", CostDimension.BINDING_COMBINATIONS, 2)
    with pytest.raises(MatchBudgetExceeded) as rule_error:
        ledger.consume("first", CostDimension.BINDING_COMBINATIONS)

    assert rule_error.value.rule_id == "first"
    assert rule_error.value.dimension is CostDimension.BINDING_COMBINATIONS
    assert rule_error.value.limit == 2
    assert ledger.snapshot().total.binding_combinations == 2
    assert ledger.snapshot().rules[0].cost.binding_combinations == 2

    ledger.consume("second", CostDimension.BINDING_COMBINATIONS)
    with pytest.raises(MatchBudgetExceeded) as global_error:
        ledger.consume("second", CostDimension.BINDING_COMBINATIONS)

    snapshot = ledger.snapshot()
    assert global_error.value.rule_id is None
    assert global_error.value.limit == 3
    assert snapshot.total.binding_combinations == 3
    assert snapshot.rules[1].cost.binding_combinations == 1


def test_cost_ledger_supports_global_work_and_rejects_invalid_consumption() -> None:
    ledger = MatchCostLedger(
        plan_for(simple_rule(), limits=MatchLimits(candidate_events=2))
    )

    ledger.consume_global(CostDimension.CANDIDATE_EVENTS, 2)
    with pytest.raises(MatchBudgetExceeded, match="candidate_events.*analysis"):
        ledger.consume_global(CostDimension.CANDIDATE_EVENTS)
    assert ledger.snapshot().total.candidate_events == 2

    with pytest.raises(ValueError, match="unknown MatchPlan Rule"):
        ledger.consume("missing", CostDimension.CONDITION_STEPS)
    for invalid in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="positive integer"):
            ledger.consume("typed_message", CostDimension.CONDITION_STEPS, invalid)  # type: ignore[arg-type]


def test_match_plan_models_and_cost_snapshots_are_closed_and_frozen() -> None:
    compiled = plan_for(simple_rule())
    snapshot = MatchCostLedger(compiled).snapshot()

    with pytest.raises(ValidationError, match="extra_forbidden"):
        MatchPlan.model_validate({**compiled.model_dump(mode="json"), "action": "block"})
    with pytest.raises(ValidationError, match="frozen"):
        compiled.scopes = (AnalysisScope.PENDING,)
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.total.condition_steps = 1
