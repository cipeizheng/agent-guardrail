"""Immutable MatchPlan IR and bounded cost accounting for snapshot matchers.

This module defines data and validation only. It does not evaluate a MatchPlan,
invoke capabilities, maintain Monitor state, or participate in Enforcement.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from agent_guardrail.models import AnalysisScope, EventKind, EventOrigin, Phase

MATCH_PLAN_VERSION = 1

MAX_MATCH_RULES = 100
MAX_MATCH_PARAMETERS = 64
MAX_EVENT_BINDINGS = 8
MAX_COLLECTION_BINDINGS = 8
MAX_DERIVATIONS = 16
MAX_CONDITION_NODES = 256
MAX_CONDITION_DEPTH = 8
MAX_CONDITION_CHILDREN = 16
MAX_QUANTIFIER_DEPTH = 4
MAX_VALUE_ARGUMENTS = 16
MAX_LITERAL_ITEMS = 128
MAX_FINDING_PROJECTIONS = 64
MAX_PATH_SEGMENTS = 16
MAX_PATH_SEGMENT_LENGTH = 64

_IDENTIFIER_PATTERN = r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$"
_CAPABILITY_PATTERN = r"^[a-z][a-z0-9_]{0,127}$"
_INDEPENDENT_EVENT_KINDS = frozenset(
    {EventKind.MESSAGE, EventKind.TOOL_CALL, EventKind.TOOL_RESULT}
)
_EVENT_ENVELOPE_FIELDS = frozenset({"id", "sequence", "kind", "phase", "origin", "payload"})
_KIND_PHASES: dict[EventKind, frozenset[Phase]] = {
    EventKind.MESSAGE: frozenset({Phase.PRE_LLM, Phase.POST_LLM}),
    EventKind.TOOL_CALL: frozenset({Phase.PRE_LLM, Phase.POST_LLM, Phase.PRE_TOOL}),
    EventKind.TOOL_RESULT: frozenset({Phase.PRE_LLM, Phase.POST_TOOL}),
}

type ScalarLiteral = StrictStr | StrictInt | StrictFloat | StrictBool


class MatchPlanModel(BaseModel):
    """Closed and immutable base for compiled MatchPlan data."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class BindingDomain(StrEnum):
    """The part of an analysis snapshot from which an Event may be selected."""

    VISIBLE = "visible"
    PAST = "past"
    PENDING = "pending"


class ParameterType(StrEnum):
    """The first bounded scalar parameter types exposed by the Policy SDK."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"


class ValueType(StrEnum):
    """A declared collection item type checked by the compiler and matcher."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    JSON = "json"


class ComparisonOperator(StrEnum):
    """Closed comparison operations justified by I01-I06 and I13."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"


class RelationOperator(StrEnum):
    """Order, conservative influence, and exact provenance remain distinct."""

    PRECEDES = "precedes"
    IMMEDIATELY_PRECEDES = "immediately_precedes"
    MAY_INFLUENCE = "may_influence"
    DERIVED_FROM_DIRECT = "derived_from_direct"
    DERIVED_FROM_ANCESTOR = "derived_from_ancestor"


class QuantifierOperator(StrEnum):
    """Bounded quantifiers evaluated over an explicit local binding domain."""

    EXISTS = "exists"
    FORALL = "forall"
    COUNT = "count"


class EvidenceProjectionSource(StrEnum):
    """The type of named condition result projected into safe Finding evidence."""

    MATCHER = "matcher"
    PREDICATE = "predicate"
    DETECTOR = "detector"


class DetectorInputEncoding(StrEnum):
    """Finite encodings a registered Detector descriptor may authorize."""

    TEXT = "text"
    CANONICAL_JSON = "canonical_json"


class ParameterDeclaration(MatchPlanModel):
    """A trusted, typed analysis parameter declared independently of Event payloads."""

    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    type: ParameterType
    required: StrictBool = True
    default: ScalarLiteral | None = None

    @model_validator(mode="after")
    def validate_default(self) -> Self:
        if self.required and self.default is not None:
            raise ValueError("a required MatchPlan parameter cannot declare a default")
        if not self.required and self.default is None:
            raise ValueError("an optional MatchPlan parameter requires a typed default")
        if self.default is not None and not _parameter_value_matches(self.type, self.default):
            raise ValueError("MatchPlan parameter default does not match its declared type")
        return self


class LiteralValue(MatchPlanModel):
    type: Literal["literal"] = "literal"
    value: ScalarLiteral


class LiteralListValue(MatchPlanModel):
    type: Literal["literal_list"] = "literal_list"
    items: tuple[ScalarLiteral, ...] = Field(default=(), max_length=MAX_LITERAL_ITEMS)


class NullValue(MatchPlanModel):
    type: Literal["null"] = "null"


class BindingValue(MatchPlanModel):
    type: Literal["binding"] = "binding"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)


class FieldValue(MatchPlanModel):
    """A static path relative to a declared Event or collection-item binding."""

    type: Literal["field"] = "field"
    binding: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    path: tuple[StrictStr | StrictInt, ...] = Field(
        min_length=1,
        max_length=MAX_PATH_SEGMENTS,
    )

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        for segment in self.path:
            if isinstance(segment, bool):
                raise ValueError("MatchPlan field paths cannot contain boolean indexes")
            if isinstance(segment, int):
                if segment < 0:
                    raise ValueError("MatchPlan field path indexes must be non-negative")
                continue
            if segment != segment.strip() or not segment:
                raise ValueError("MatchPlan field path strings must be non-blank and trimmed")
            if len(segment) > MAX_PATH_SEGMENT_LENGTH:
                raise ValueError("MatchPlan field path segment is too long")
        return self


class DerivedValue(MatchPlanModel):
    type: Literal["derived"] = "derived"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)


class ParameterValue(MatchPlanModel):
    type: Literal["parameter"] = "parameter"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)


type ValueReference = Annotated[
    LiteralValue
    | LiteralListValue
    | NullValue
    | BindingValue
    | FieldValue
    | DerivedValue
    | ParameterValue,
    Field(discriminator="type"),
]


class EventBinding(MatchPlanModel):
    """One typed Event variable selected without a mandatory anchor."""

    type: Literal["event"] = "event"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    kind: EventKind
    domain: BindingDomain = BindingDomain.VISIBLE
    phases: tuple[Phase, ...] = Field(default=(), max_length=4)
    origins: tuple[EventOrigin, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def validate_event_domain(self) -> Self:
        if self.kind not in _INDEPENDENT_EVENT_KINDS:
            raise ValueError("MatchPlan Event bindings require an independent Event kind")
        if len(self.phases) != len(set(self.phases)):
            raise ValueError("MatchPlan Event binding phases must be unique")
        if len(self.origins) != len(set(self.origins)):
            raise ValueError("MatchPlan Event binding origins must be unique")
        if any(phase not in _KIND_PHASES[self.kind] for phase in self.phases):
            raise ValueError("MatchPlan Event binding phase is incompatible with its kind")
        return self


class CollectionBinding(MatchPlanModel):
    """One item variable expanded from a bounded collection-valued reference."""

    type: Literal["collection"] = "collection"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    source: ValueReference
    item_type: ValueType


type LocalBinding = Annotated[EventBinding | CollectionBinding, Field(discriminator="type")]


class SplitLinesDerivation(MatchPlanModel):
    """The first corpus-backed pure derivation; it returns a bounded string collection."""

    op: Literal["split_lines"] = "split_lines"
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    source: ValueReference


class Comparison(MatchPlanModel):
    """A pure comparison whose optional ID can project ranges/evidence."""

    id: StrictStr | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    left: ValueReference
    operator: ComparisonOperator
    right: ValueReference

    @model_validator(mode="after")
    def validate_bounded_string_search(self) -> Self:
        if (
            self.operator in {ComparisonOperator.CONTAINS, ComparisonOperator.NOT_CONTAINS}
            and isinstance(self.right, LiteralValue)
            and self.right.value == ""
        ):
            raise ValueError("MatchPlan string search cannot use an empty literal")
        return self


class PresenceCondition(MatchPlanModel):
    """An explicit field-presence check for deterministic missing-value behavior."""

    field: FieldValue


class RelationCondition(MatchPlanModel):
    """A relation between two Event bindings, never an implicit provenance edge."""

    source: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    target: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    operator: RelationOperator

    @model_validator(mode="after")
    def validate_distinct_bindings(self) -> Self:
        if self.source == self.target:
            raise ValueError("MatchPlan relations require two distinct Event bindings")
        return self


class PredicateCondition(MatchPlanModel):
    """A call to a pure, deployment-registered Predicate descriptor."""

    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    capability: StrictStr = Field(pattern=_CAPABILITY_PATTERN)
    arguments: tuple[ValueReference, ...] = Field(default=(), max_length=MAX_VALUE_ARGUMENTS)


class DetectorInput(MatchPlanModel):
    value: ValueReference
    encoding: DetectorInputEncoding


class DetectorCondition(MatchPlanModel):
    """A call to a deployment-registered Detector with bounded encoded inputs."""

    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    capability: StrictStr = Field(pattern=_CAPABILITY_PATTERN)
    inputs: tuple[DetectorInput, ...] = Field(min_length=1, max_length=MAX_VALUE_ARGUMENTS)
    types_any: tuple[StrictStr, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_types(self) -> Self:
        if len(self.types_any) != len(set(self.types_any)):
            raise ValueError("MatchPlan Detector type filters must be unique")
        if any(not value or value != value.strip() for value in self.types_any):
            raise ValueError("MatchPlan Detector type filters must be non-blank and trimmed")
        return self


class CountBounds(MatchPlanModel):
    minimum: StrictInt | None = Field(default=None, ge=0)
    maximum: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if self.minimum is None and self.maximum is None:
            raise ValueError("MatchPlan count requires a minimum or maximum")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.maximum < self.minimum
        ):
            raise ValueError("MatchPlan count maximum cannot be less than minimum")
        return self


class QuantifierPlan(MatchPlanModel):
    """One lexical local binding with bounded exists/count/forall semantics."""

    operator: QuantifierOperator
    binding: LocalBinding
    where: MatchCondition
    count: CountBounds | None = None

    @model_validator(mode="after")
    def validate_operator_fields(self) -> Self:
        if self.operator is QuantifierOperator.COUNT:
            if self.count is None:
                raise ValueError("MatchPlan count quantifier requires count bounds")
        elif self.count is not None:
            raise ValueError("only a MatchPlan count quantifier may declare count bounds")
        return self


class MatchCondition(MatchPlanModel):
    """One node in a closed, recursively bounded boolean condition tree."""

    all: tuple[MatchCondition, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_CONDITION_CHILDREN,
    )
    any: tuple[MatchCondition, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_CONDITION_CHILDREN,
    )
    not_: MatchCondition | None = Field(default=None, alias="not")
    compare: Comparison | None = None
    present: PresenceCondition | None = None
    relation: RelationCondition | None = None
    predicate: PredicateCondition | None = None
    detector: DetectorCondition | None = None
    quantify: QuantifierPlan | None = None

    @model_validator(mode="after")
    def validate_one_operation(self) -> Self:
        operations = (
            self.all,
            self.any,
            self.not_,
            self.compare,
            self.present,
            self.relation,
            self.predicate,
            self.detector,
            self.quantify,
        )
        if sum(operation is not None for operation in operations) != 1:
            raise ValueError("MatchPlan condition must contain exactly one operation")
        return self


class EvidenceProjection(MatchPlanModel):
    """A safe projection from one named condition result into a Finding."""

    source: EvidenceProjectionSource
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    include_locations: StrictBool = True
    masked_evidence: StrictStr | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_mask(self) -> Self:
        if self.masked_evidence is not None:
            _require_trimmed(self.masked_evidence, "MatchPlan masked evidence")
        return self


class FindingTemplate(MatchPlanModel):
    """Static, payload-free instructions for constructing one Finding per match."""

    code: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    message: StrictStr = Field(min_length=1, max_length=512)
    subjects: tuple[StrictStr, ...] = Field(min_length=1, max_length=64)
    bindings: tuple[StrictStr, ...] = Field(min_length=1, max_length=128)
    evidence: tuple[EvidenceProjection, ...] = Field(
        default=(),
        max_length=MAX_FINDING_PROJECTIONS,
    )

    @model_validator(mode="after")
    def validate_template(self) -> Self:
        _require_trimmed(self.message, "MatchPlan Finding message")
        _require_unique(self.subjects, "MatchPlan Finding subjects")
        _require_unique(self.bindings, "MatchPlan Finding bindings")
        projection_keys = [(item.source, item.id) for item in self.evidence]
        if len(projection_keys) != len(set(projection_keys)):
            raise ValueError("MatchPlan Finding evidence projections must be unique")
        return self


class CostDimension(StrEnum):
    """Independent resource dimensions charged by the matcher."""

    CANDIDATE_EVENTS = "candidate_events"
    BINDING_COMBINATIONS = "binding_combinations"
    COLLECTION_ITEMS = "collection_items"
    DERIVED_ITEMS = "derived_items"
    DERIVED_BYTES = "derived_bytes"
    QUANTIFIER_ITERATIONS = "quantifier_iterations"
    CONDITION_STEPS = "condition_steps"
    RELATION_NODES = "relation_nodes"
    RELATION_HOPS = "relation_hops"
    PREDICATE_CALLS = "predicate_calls"
    PREDICATE_INPUT_BYTES = "predicate_input_bytes"
    PREDICATE_TIME_MS = "predicate_time_ms"
    DETECTOR_CALLS = "detector_calls"
    DETECTOR_INPUT_BYTES = "detector_input_bytes"
    DETECTOR_TIME_MS = "detector_time_ms"
    FINDINGS = "findings"
    EVIDENCE = "evidence"


class MatchLimits(MatchPlanModel):
    """Effective analysis-wide limits bounded by implementation hard caps."""

    candidate_events: StrictInt = Field(default=10_000, ge=1, le=1_000_000)
    binding_combinations: StrictInt = Field(default=8_192, ge=1, le=1_000_000)
    collection_items: StrictInt = Field(default=2_048, ge=1, le=100_000)
    derived_items: StrictInt = Field(default=2_048, ge=1, le=100_000)
    derived_bytes: StrictInt = Field(default=131_072, ge=1, le=4_194_304)
    quantifier_iterations: StrictInt = Field(default=8_192, ge=1, le=1_000_000)
    condition_steps: StrictInt = Field(default=16_384, ge=1, le=2_000_000)
    relation_nodes: StrictInt = Field(default=4_096, ge=1, le=1_000_000)
    relation_hops: StrictInt = Field(default=64, ge=1, le=1_024)
    predicate_calls: StrictInt = Field(default=256, ge=1, le=100_000)
    predicate_input_bytes: StrictInt = Field(default=262_144, ge=1, le=8_388_608)
    predicate_time_ms: StrictInt = Field(default=5_000, ge=1, le=60_000)
    detector_calls: StrictInt = Field(default=32, ge=1, le=1_024)
    detector_input_bytes: StrictInt = Field(default=262_144, ge=1, le=8_388_608)
    detector_time_ms: StrictInt = Field(default=5_000, ge=1, le=60_000)
    findings: StrictInt = Field(default=1_000, ge=1, le=1_000)
    evidence: StrictInt = Field(default=512, ge=1, le=8_192)

    def value_for(self, dimension: CostDimension) -> int:
        return cast(int, getattr(self, dimension.value))


class MatchLimitOverrides(MatchPlanModel):
    """Per-Rule limits that may only lower the analysis-wide ceiling."""

    candidate_events: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    binding_combinations: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    collection_items: StrictInt | None = Field(default=None, ge=1, le=100_000)
    derived_items: StrictInt | None = Field(default=None, ge=1, le=100_000)
    derived_bytes: StrictInt | None = Field(default=None, ge=1, le=4_194_304)
    quantifier_iterations: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    condition_steps: StrictInt | None = Field(default=None, ge=1, le=2_000_000)
    relation_nodes: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    relation_hops: StrictInt | None = Field(default=None, ge=1, le=1_024)
    predicate_calls: StrictInt | None = Field(default=None, ge=1, le=100_000)
    predicate_input_bytes: StrictInt | None = Field(default=None, ge=1, le=8_388_608)
    predicate_time_ms: StrictInt | None = Field(default=None, ge=1, le=60_000)
    detector_calls: StrictInt | None = Field(default=None, ge=1, le=1_024)
    detector_input_bytes: StrictInt | None = Field(default=None, ge=1, le=8_388_608)
    detector_time_ms: StrictInt | None = Field(default=None, ge=1, le=60_000)
    findings: StrictInt | None = Field(default=None, ge=1, le=1_000)
    evidence: StrictInt | None = Field(default=None, ge=1, le=8_192)

    def resolve(self, global_limits: MatchLimits) -> MatchLimits:
        values: dict[str, int] = {}
        for dimension in CostDimension:
            global_value = global_limits.value_for(dimension)
            override = getattr(self, dimension.value)
            if override is not None and override > global_value:
                raise ValueError("MatchPlan Rule limits cannot raise the analysis-wide limit")
            values[dimension.value] = override if override is not None else global_value
        return MatchLimits.model_validate(values)


class MatchRulePlan(MatchPlanModel):
    """One anchor-free match search and static Finding projection."""

    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    event_bindings: tuple[EventBinding, ...] = Field(
        min_length=1,
        max_length=MAX_EVENT_BINDINGS,
    )
    derive: tuple[SplitLinesDerivation, ...] = Field(default=(), max_length=MAX_DERIVATIONS)
    collection_bindings: tuple[CollectionBinding, ...] = Field(
        default=(),
        max_length=MAX_COLLECTION_BINDINGS,
    )
    where: MatchCondition
    finding: FindingTemplate
    limits: MatchLimitOverrides = Field(default_factory=MatchLimitOverrides)

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        event_names = [binding.name for binding in self.event_bindings]
        derive_names = [derive.name for derive in self.derive]
        collection_names = [binding.name for binding in self.collection_bindings]
        all_names = [*event_names, *derive_names, *collection_names]
        if len(all_names) != len(set(all_names)):
            raise ValueError("MatchPlan Rule symbols must be globally unique")

        allowed_bindings = set(event_names)
        allowed_events = set(event_names)
        allowed_derived: set[str] = set()
        for derive in self.derive:
            _validate_value_reference(
                derive.source,
                bindings=allowed_bindings,
                events=allowed_events,
                derived=allowed_derived,
            )
            allowed_derived.add(derive.name)

        for binding in self.collection_bindings:
            _validate_value_reference(
                binding.source,
                bindings=allowed_bindings,
                events=allowed_events,
                derived=allowed_derived,
            )
            allowed_bindings.add(binding.name)

        named_sources: dict[str, EvidenceProjectionSource] = {}
        _validate_condition(
            self.where,
            bindings=allowed_bindings,
            events=allowed_events,
            derived=allowed_derived,
            named_sources=named_sources,
            depth=1,
            quantifier_depth=0,
        )
        if _condition_node_count(self.where) > MAX_CONDITION_NODES:
            raise ValueError("MatchPlan condition tree exceeds its node limit")

        if not set(self.finding.subjects).issubset(allowed_events):
            raise ValueError("MatchPlan Finding subjects must reference top-level Event bindings")
        required_bindings = set(event_names) | set(collection_names)
        if not required_bindings.issubset(self.finding.bindings):
            raise ValueError("MatchPlan Finding must project every top-level match binding")
        for projection in self.finding.evidence:
            if named_sources.get(projection.id) is not projection.source:
                raise ValueError("MatchPlan Finding evidence references an unknown source")
        return self

    def effective_limits(self, global_limits: MatchLimits) -> MatchLimits:
        return self.limits.resolve(global_limits)


class MatchPlan(MatchPlanModel):
    """A provider-neutral, immutable Policy IR consumed by bounded matchers."""

    model_version: Literal[1] = MATCH_PLAN_VERSION
    scopes: tuple[AnalysisScope, ...] = Field(min_length=1, max_length=2)
    limits: MatchLimits = Field(default_factory=MatchLimits)
    parameters: tuple[ParameterDeclaration, ...] = Field(
        default=(),
        max_length=MAX_MATCH_PARAMETERS,
    )
    rules: tuple[MatchRulePlan, ...] = Field(max_length=MAX_MATCH_RULES)

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        _require_unique(self.scopes, "MatchPlan scopes")
        parameter_names = [parameter.name for parameter in self.parameters]
        _require_unique(parameter_names, "MatchPlan parameters")
        rule_ids = [rule.id for rule in self.rules]
        _require_unique(rule_ids, "MatchPlan Rule IDs")
        known_parameters = set(parameter_names)

        for rule in self.rules:
            rule_symbols = _rule_declared_names(rule)
            collisions = known_parameters.intersection(rule_symbols)
            if collisions:
                raise ValueError("MatchPlan parameters cannot shadow Rule symbols")
            unknown_parameters = _rule_parameter_references(rule) - known_parameters
            if unknown_parameters:
                raise ValueError("MatchPlan Rule references an unknown parameter")
            output_symbols = {
                *(binding.name for binding in rule.event_bindings),
                *(binding.name for binding in rule.collection_bindings),
                *(derive.name for derive in rule.derive),
            }
            unknown_outputs = set(rule.finding.bindings) - (
                output_symbols | known_parameters
            )
            if unknown_outputs:
                raise ValueError(
                    "MatchPlan Finding references an unknown or lexical binding"
                )
            for dimension in CostDimension:
                override = getattr(rule.limits, dimension.value)
                if override is not None and override > self.limits.value_for(dimension):
                    raise ValueError("MatchPlan Rule limits cannot raise the analysis-wide limit")
        return self


class MatchCost(MatchPlanModel):
    """An immutable snapshot of consumed matcher resources."""

    candidate_events: StrictInt = Field(default=0, ge=0)
    binding_combinations: StrictInt = Field(default=0, ge=0)
    collection_items: StrictInt = Field(default=0, ge=0)
    derived_items: StrictInt = Field(default=0, ge=0)
    derived_bytes: StrictInt = Field(default=0, ge=0)
    quantifier_iterations: StrictInt = Field(default=0, ge=0)
    condition_steps: StrictInt = Field(default=0, ge=0)
    relation_nodes: StrictInt = Field(default=0, ge=0)
    relation_hops: StrictInt = Field(default=0, ge=0)
    predicate_calls: StrictInt = Field(default=0, ge=0)
    predicate_input_bytes: StrictInt = Field(default=0, ge=0)
    predicate_time_ms: StrictInt = Field(default=0, ge=0)
    detector_calls: StrictInt = Field(default=0, ge=0)
    detector_input_bytes: StrictInt = Field(default=0, ge=0)
    detector_time_ms: StrictInt = Field(default=0, ge=0)
    findings: StrictInt = Field(default=0, ge=0)
    evidence: StrictInt = Field(default=0, ge=0)

    def value_for(self, dimension: CostDimension) -> int:
        return cast(int, getattr(self, dimension.value))


class RuleCostSnapshot(MatchPlanModel):
    rule_id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    cost: MatchCost


class MatchCostSnapshot(MatchPlanModel):
    total: MatchCost
    rules: tuple[RuleCostSnapshot, ...]


class MatchBudgetExceeded(RuntimeError):
    """A safe error raised before a cost consumption would exceed one limit."""

    def __init__(
        self,
        *,
        dimension: CostDimension,
        limit: int,
        current: int,
        requested: int,
        rule_id: str | None,
    ) -> None:
        self.dimension = dimension
        self.limit = limit
        self.current = current
        self.requested = requested
        self.rule_id = rule_id
        scope = f"rule:{rule_id}" if rule_id is not None else "analysis"
        super().__init__(f"MatchPlan budget exceeded for {dimension.value} in {scope}")


class MatchCostLedger:
    """Mutable, analysis-local, atomic accounting against global and per-Rule limits."""

    def __init__(self, plan: MatchPlan) -> None:
        self._global_limits = plan.limits
        self._rule_limits = {
            rule.id: rule.effective_limits(plan.limits) for rule in plan.rules
        }
        self._global_usage = _empty_usage()
        self._rule_usage = {rule.id: _empty_usage() for rule in plan.rules}

    def consume(
        self,
        rule_id: str,
        dimension: CostDimension,
        amount: int = 1,
    ) -> None:
        """Atomically charge one Rule and the enclosing analysis."""

        _validate_cost_amount(amount)
        if rule_id not in self._rule_limits:
            raise ValueError("cost consumption references an unknown MatchPlan Rule")
        rule_usage = self._rule_usage[rule_id]
        rule_limit = self._rule_limits[rule_id].value_for(dimension)
        global_limit = self._global_limits.value_for(dimension)
        _check_cost_limit(
            dimension=dimension,
            current=rule_usage[dimension],
            requested=amount,
            limit=rule_limit,
            rule_id=rule_id,
        )
        _check_cost_limit(
            dimension=dimension,
            current=self._global_usage[dimension],
            requested=amount,
            limit=global_limit,
            rule_id=None,
        )
        rule_usage[dimension] += amount
        self._global_usage[dimension] += amount

    def consume_global(self, dimension: CostDimension, amount: int = 1) -> None:
        """Charge analysis-wide work that is not attributable to one Rule."""

        _validate_cost_amount(amount)
        _check_cost_limit(
            dimension=dimension,
            current=self._global_usage[dimension],
            requested=amount,
            limit=self._global_limits.value_for(dimension),
            rule_id=None,
        )
        self._global_usage[dimension] += amount

    def snapshot(self) -> MatchCostSnapshot:
        """Return a deterministic immutable copy without exposing mutable dictionaries."""

        return MatchCostSnapshot(
            total=_cost_from_usage(self._global_usage),
            rules=tuple(
                RuleCostSnapshot(rule_id=rule_id, cost=_cost_from_usage(usage))
                for rule_id, usage in self._rule_usage.items()
            ),
        )


def _validate_value_reference(
    value: ValueReference,
    *,
    bindings: set[str],
    events: set[str],
    derived: set[str],
) -> None:
    if isinstance(value, BindingValue):
        if value.name not in bindings:
            raise ValueError("MatchPlan value references an unknown binding")
        return
    if isinstance(value, FieldValue):
        if value.binding not in bindings:
            raise ValueError("MatchPlan field references an unknown binding")
        if value.binding in events:
            first = value.path[0]
            if not isinstance(first, str) or first not in _EVENT_ENVELOPE_FIELDS:
                raise ValueError("MatchPlan Event fields must use the canonical safe envelope")
        return
    if isinstance(value, DerivedValue):
        if value.name not in derived:
            raise ValueError("MatchPlan value references an unknown or forward derivation")


def _validate_condition(
    condition: MatchCondition,
    *,
    bindings: set[str],
    events: set[str],
    derived: set[str],
    named_sources: dict[str, EvidenceProjectionSource],
    depth: int,
    quantifier_depth: int,
) -> None:
    if depth > MAX_CONDITION_DEPTH:
        raise ValueError("MatchPlan condition tree exceeds its depth limit")
    if condition.all is not None:
        for item in condition.all:
            _validate_condition(
                item,
                bindings=bindings,
                events=events,
                derived=derived,
                named_sources=named_sources,
                depth=depth + 1,
                quantifier_depth=quantifier_depth,
            )
        return
    if condition.any is not None:
        for item in condition.any:
            _validate_condition(
                item,
                bindings=bindings,
                events=events,
                derived=derived,
                named_sources=named_sources,
                depth=depth + 1,
                quantifier_depth=quantifier_depth,
            )
        return
    if condition.not_ is not None:
        _validate_condition(
            condition.not_,
            bindings=bindings,
            events=events,
            derived=derived,
            named_sources=named_sources,
            depth=depth + 1,
            quantifier_depth=quantifier_depth,
        )
        return
    if condition.compare is not None:
        _validate_value_reference(
            condition.compare.left,
            bindings=bindings,
            events=events,
            derived=derived,
        )
        _validate_value_reference(
            condition.compare.right,
            bindings=bindings,
            events=events,
            derived=derived,
        )
        if condition.compare.id is not None:
            _add_named_source(
                named_sources,
                condition.compare.id,
                EvidenceProjectionSource.MATCHER,
            )
        return
    if condition.present is not None:
        _validate_value_reference(
            condition.present.field,
            bindings=bindings,
            events=events,
            derived=derived,
        )
        return
    if condition.relation is not None:
        if condition.relation.source not in events or condition.relation.target not in events:
            raise ValueError("MatchPlan relations must reference Event bindings")
        return
    if condition.predicate is not None:
        for argument in condition.predicate.arguments:
            _validate_value_reference(
                argument,
                bindings=bindings,
                events=events,
                derived=derived,
            )
        _add_named_source(
            named_sources,
            condition.predicate.id,
            EvidenceProjectionSource.PREDICATE,
        )
        return
    if condition.detector is not None:
        for detector_input in condition.detector.inputs:
            _validate_value_reference(
                detector_input.value,
                bindings=bindings,
                events=events,
                derived=derived,
            )
        _add_named_source(
            named_sources,
            condition.detector.id,
            EvidenceProjectionSource.DETECTOR,
        )
        return
    if condition.quantify is not None:
        if quantifier_depth >= MAX_QUANTIFIER_DEPTH:
            raise ValueError("MatchPlan quantifier nesting exceeds its depth limit")
        local = condition.quantify.binding
        if local.name in bindings or local.name in derived:
            raise ValueError("MatchPlan quantifier bindings cannot shadow outer variables")
        if isinstance(local, CollectionBinding):
            _validate_value_reference(
                local.source,
                bindings=bindings,
                events=events,
                derived=derived,
            )
        local_bindings = {*bindings, local.name}
        local_events = {*events, local.name} if isinstance(local, EventBinding) else set(events)
        _validate_condition(
            condition.quantify.where,
            bindings=local_bindings,
            events=local_events,
            derived=derived,
            named_sources=named_sources,
            depth=depth + 1,
            quantifier_depth=quantifier_depth + 1,
        )
        return
    raise ValueError("validated MatchPlan condition has no operation")


def _condition_node_count(condition: MatchCondition) -> int:
    if condition.all is not None:
        return 1 + sum(_condition_node_count(item) for item in condition.all)
    if condition.any is not None:
        return 1 + sum(_condition_node_count(item) for item in condition.any)
    if condition.not_ is not None:
        return 1 + _condition_node_count(condition.not_)
    if condition.quantify is not None:
        return 1 + _condition_node_count(condition.quantify.where)
    return 1


def _add_named_source(
    named_sources: dict[str, EvidenceProjectionSource],
    name: str,
    source: EvidenceProjectionSource,
) -> None:
    if name in named_sources:
        raise ValueError("MatchPlan condition result IDs must be unique within a Rule")
    named_sources[name] = source


def _rule_declared_names(rule: MatchRulePlan) -> set[str]:
    names = {binding.name for binding in rule.event_bindings}
    names.update(binding.name for binding in rule.collection_bindings)
    names.update(derive.name for derive in rule.derive)
    names.update(_quantifier_binding_names(rule.where))
    return names


def _quantifier_binding_names(condition: MatchCondition) -> set[str]:
    if condition.all is not None:
        return set().union(*(_quantifier_binding_names(item) for item in condition.all))
    if condition.any is not None:
        return set().union(*(_quantifier_binding_names(item) for item in condition.any))
    if condition.not_ is not None:
        return _quantifier_binding_names(condition.not_)
    if condition.quantify is not None:
        return {
            condition.quantify.binding.name,
            *_quantifier_binding_names(condition.quantify.where),
        }
    return set()


def _rule_parameter_references(rule: MatchRulePlan) -> set[str]:
    references: set[str] = set()
    for derive in rule.derive:
        _collect_value_parameters(derive.source, references)
    for binding in rule.collection_bindings:
        _collect_value_parameters(binding.source, references)
    _collect_condition_parameters(rule.where, references)
    references.update(
        name
        for name in rule.finding.bindings
        if name not in _rule_declared_names(rule)
    )
    return references


def _collect_condition_parameters(condition: MatchCondition, references: set[str]) -> None:
    if condition.all is not None:
        for item in condition.all:
            _collect_condition_parameters(item, references)
        return
    if condition.any is not None:
        for item in condition.any:
            _collect_condition_parameters(item, references)
        return
    if condition.not_ is not None:
        _collect_condition_parameters(condition.not_, references)
        return
    if condition.compare is not None:
        _collect_value_parameters(condition.compare.left, references)
        _collect_value_parameters(condition.compare.right, references)
        return
    if condition.present is not None:
        _collect_value_parameters(condition.present.field, references)
        return
    if condition.predicate is not None:
        for argument in condition.predicate.arguments:
            _collect_value_parameters(argument, references)
        return
    if condition.detector is not None:
        for detector_input in condition.detector.inputs:
            _collect_value_parameters(detector_input.value, references)
        return
    if condition.quantify is not None:
        if isinstance(condition.quantify.binding, CollectionBinding):
            _collect_value_parameters(condition.quantify.binding.source, references)
        _collect_condition_parameters(condition.quantify.where, references)


def _collect_value_parameters(value: ValueReference, references: set[str]) -> None:
    if isinstance(value, ParameterValue):
        references.add(value.name)


def _parameter_value_matches(parameter_type: ParameterType, value: ScalarLiteral) -> bool:
    return {
        ParameterType.STRING: type(value) is str,
        ParameterType.INTEGER: type(value) is int,
        ParameterType.FLOAT: type(value) is float,
        ParameterType.BOOLEAN: type(value) is bool,
    }[parameter_type]


def _require_trimmed(value: str, field: str) -> None:
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a non-blank trimmed string")


def _require_unique(values: tuple[object, ...] | list[str], field: str) -> None:
    sequence = tuple(values)
    if len(sequence) != len(set(sequence)):
        raise ValueError(f"{field} must be unique")


def _empty_usage() -> dict[CostDimension, int]:
    return dict.fromkeys(CostDimension, 0)


def _cost_from_usage(usage: dict[CostDimension, int]) -> MatchCost:
    return MatchCost.model_validate(
        {dimension.value: usage[dimension] for dimension in CostDimension}
    )


def _validate_cost_amount(amount: int) -> None:
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("MatchPlan cost consumption must be a positive integer")


def _check_cost_limit(
    *,
    dimension: CostDimension,
    current: int,
    requested: int,
    limit: int,
    rule_id: str | None,
) -> None:
    if current + requested > limit:
        raise MatchBudgetExceeded(
            dimension=dimension,
            limit=limit,
            current=current,
            requested=requested,
            rule_id=rule_id,
        )


QuantifierPlan.model_rebuild()
