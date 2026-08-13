"""Strict, readable author schema compiled into immutable MatchPlan v1."""

from __future__ import annotations

import re
from collections.abc import Mapping
from math import isfinite
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

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
    SimilarityCondition,
    SimilarityThreshold,
    SplitLinesDerivation,
    ValueReference,
    ValueType,
)
from agent_guardrail.models import AnalysisScope, EventKind, EventOrigin

AUTHOR_POLICY_VERSION = 1

MAX_AUTHOR_PREDICATES = 128
MAX_AUTHOR_RULES = 100
MAX_AUTHOR_PARAMETERS = 64
MAX_AUTHOR_ARGUMENTS = 16
MAX_AUTHOR_PATH_SEGMENTS = 17

_IDENTIFIER_PATTERN = r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$"
type ScalarLiteral = StrictStr | StrictInt | StrictFloat | StrictBool
type PathSegment = StrictStr | StrictInt


class AuthorModel(BaseModel):
    """Closed and frozen authoring data; it has no executable behavior."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class AuthorValue(AuthorModel):
    """One readable value reference; field paths include their binding first."""

    field: tuple[PathSegment, ...] | None = Field(
        default=None,
        min_length=2,
        max_length=MAX_AUTHOR_PATH_SEGMENTS,
    )
    binding: StrictStr | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    derived: StrictStr | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    parameter: StrictStr | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    literal: ScalarLiteral | tuple[ScalarLiteral, ...] | None = None

    @model_validator(mode="after")
    def validate_one_source(self) -> Self:
        selected = {
            "field": self.field is not None,
            "binding": self.binding is not None,
            "derived": self.derived is not None,
            "parameter": self.parameter is not None,
            "literal": "literal" in self.model_fields_set,
        }
        if sum(selected.values()) != 1:
            raise ValueError("author value must contain exactly one source")
        if self.field is not None:
            _validate_author_path(self.field)
        return self


class AuthorParameterSpec(AuthorModel):
    type: ParameterType
    required: StrictBool = True
    default: ScalarLiteral | None = None


class AuthorEventSpec(AuthorModel):
    kind: EventKind
    domain: BindingDomain = BindingDomain.VISIBLE
    origins: tuple[EventOrigin, ...] = Field(default=(), max_length=3)


class AuthorCollectionSpec(AuthorModel):
    source: AuthorValue = Field(alias="from")
    item_type: ValueType


class AuthorDerivationSpec(AuthorModel):
    operation: Literal["split_lines"]
    source: AuthorValue


class AuthorComparison(AuthorModel):
    id: StrictStr | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    left: AuthorValue
    operator: ComparisonOperator
    right: AuthorValue


class AuthorRelation(AuthorModel):
    source: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    target: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    operator: RelationOperator


class AuthorToolMatch(AuthorModel):
    binding: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    name: StrictStr = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_name(self) -> Self:
        _require_trimmed(self.name, "tool name")
        return self


class AuthorCapabilityPredicate(AuthorModel):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    capability: StrictStr = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    arguments: tuple[AuthorValue, ...] = Field(default=(), max_length=MAX_AUTHOR_ARGUMENTS)


class AuthorDetectorInput(AuthorModel):
    value: AuthorValue
    encoding: DetectorInputEncoding


class AuthorCapabilityDetector(AuthorModel):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    capability: StrictStr = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    inputs: tuple[AuthorDetectorInput, ...] = Field(
        min_length=1,
        max_length=MAX_AUTHOR_ARGUMENTS,
    )
    types_any: tuple[StrictStr, ...] = Field(default=(), max_length=64)


class AuthorSimilarity(AuthorModel):
    """Invariant-compatible is_similar call without a Policy-selected model."""

    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    capability: StrictStr = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    data: AuthorValue
    target: AuthorValue
    threshold: StrictFloat | SimilarityThreshold = SimilarityThreshold.MIGHT_RESEMBLE

    @model_validator(mode="after")
    def validate_threshold(self) -> Self:
        if isinstance(self.threshold, float) and (
            not isfinite(self.threshold) or not 0.0 <= self.threshold <= 1.0
        ):
            raise ValueError("author similarity threshold must be in [0, 1]")
        return self


class AuthorPredicateUse(AuthorModel):
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    arguments: dict[StrictStr, AuthorValue] = Field(
        default_factory=dict,
        max_length=MAX_AUTHOR_ARGUMENTS,
    )

    @model_validator(mode="after")
    def validate_argument_names(self) -> Self:
        _validate_names(self.arguments, "predicate argument")
        return self


class AuthorLocalEvent(AuthorModel):
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    kind: EventKind
    domain: BindingDomain = BindingDomain.VISIBLE
    origins: tuple[EventOrigin, ...] = Field(default=(), max_length=3)


class AuthorLocalCollection(AuthorModel):
    name: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    source: AuthorValue = Field(alias="from")
    item_type: ValueType


class AuthorQuantifier(AuthorModel):
    operator: QuantifierOperator
    event: AuthorLocalEvent | None = None
    collection: AuthorLocalCollection | None = None
    where: AuthorCondition
    minimum: StrictInt | None = Field(default=None, ge=0)
    maximum: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_quantifier(self) -> Self:
        if (self.event is None) == (self.collection is None):
            raise ValueError("author quantifier requires exactly one local binding")
        if self.operator is QuantifierOperator.COUNT:
            if self.minimum is None and self.maximum is None:
                raise ValueError("author count requires minimum or maximum")
        elif self.minimum is not None or self.maximum is not None:
            raise ValueError("only author count accepts minimum or maximum")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.maximum < self.minimum
        ):
            raise ValueError("author count maximum cannot be below minimum")
        return self


class AuthorCondition(AuthorModel):
    """Closed author condition tree, including compile-time predicate use."""

    all: tuple[AuthorCondition, ...] | None = Field(default=None, min_length=1, max_length=16)
    any: tuple[AuthorCondition, ...] | None = Field(default=None, min_length=1, max_length=16)
    not_: AuthorCondition | None = Field(default=None, alias="not")
    compare: AuthorComparison | None = None
    present: tuple[PathSegment, ...] | None = Field(
        default=None,
        min_length=2,
        max_length=MAX_AUTHOR_PATH_SEGMENTS,
    )
    relation: AuthorRelation | None = None
    tool: AuthorToolMatch | None = None
    predicate: AuthorCapabilityPredicate | None = None
    detector: AuthorCapabilityDetector | None = None
    similarity: AuthorSimilarity | None = None
    use: AuthorPredicateUse | None = None
    quantify: AuthorQuantifier | None = None

    @model_validator(mode="after")
    def validate_one_operation(self) -> Self:
        operations = (
            self.all,
            self.any,
            self.not_,
            self.compare,
            self.present,
            self.relation,
            self.tool,
            self.predicate,
            self.detector,
            self.similarity,
            self.use,
            self.quantify,
        )
        if sum(operation is not None for operation in operations) != 1:
            raise ValueError("author condition must contain exactly one operation")
        if self.present is not None:
            _validate_author_path(self.present)
        return self


class AuthorPredicateDefinition(AuthorModel):
    parameters: tuple[StrictStr, ...] = Field(default=(), max_length=MAX_AUTHOR_ARGUMENTS)
    where: AuthorCondition

    @model_validator(mode="after")
    def validate_parameters(self) -> Self:
        _require_unique_names(self.parameters, "predicate parameters")
        return self


class AuthorEvidence(AuthorModel):
    source: EvidenceProjectionSource
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    include_locations: StrictBool = True
    masked_evidence: StrictStr | None = Field(default=None, min_length=1, max_length=256)


class AuthorFinding(AuthorModel):
    code: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    message: StrictStr = Field(min_length=1, max_length=512)
    subjects: tuple[StrictStr, ...] = Field(min_length=1, max_length=64)
    bindings: tuple[StrictStr, ...] = Field(default=(), max_length=128)
    evidence: tuple[AuthorEvidence, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_finding(self) -> Self:
        _require_trimmed(self.message, "finding message")
        _require_unique_names(self.subjects, "finding subjects")
        _require_unique_names(self.bindings, "finding extra bindings")
        return self


class AuthorRule(AuthorModel):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    events: dict[StrictStr, AuthorEventSpec] = Field(min_length=1, max_length=8)
    derive: dict[StrictStr, AuthorDerivationSpec] = Field(default_factory=dict, max_length=16)
    collections: dict[StrictStr, AuthorCollectionSpec] = Field(
        default_factory=dict,
        max_length=8,
    )
    where: AuthorCondition
    finding: AuthorFinding
    limits: MatchLimitOverrides = Field(default_factory=MatchLimitOverrides)

    @model_validator(mode="after")
    def validate_symbols(self) -> Self:
        for values, label in (
            (self.events, "event"),
            (self.derive, "derivation"),
            (self.collections, "collection"),
        ):
            _validate_names(values, label)
        names = [*self.events, *self.derive, *self.collections]
        if len(names) != len(set(names)):
            raise ValueError("author Rule symbols must be globally unique")
        projected = set(self.events) | set(self.collections)
        overlap = projected.intersection(self.finding.bindings)
        if overlap:
            raise ValueError("author finding bindings list only additional projections")
        return self


class AuthorPolicy(AuthorModel):
    """Readable YAML/Python builder input; compilation is explicit and side-effect free."""

    version: Literal[1]
    scopes: tuple[AnalysisScope, ...] = (AnalysisScope.SNAPSHOT,)
    limits: MatchLimits = Field(default_factory=MatchLimits)
    parameters: dict[StrictStr, AuthorParameterSpec] = Field(
        default_factory=dict,
        max_length=MAX_AUTHOR_PARAMETERS,
    )
    predicates: dict[StrictStr, AuthorPredicateDefinition] = Field(
        default_factory=dict,
        max_length=MAX_AUTHOR_PREDICATES,
    )
    rules: tuple[AuthorRule, ...] = Field(max_length=MAX_AUTHOR_RULES)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        _require_unique_names(self.scopes, "author scopes")
        _validate_names(self.parameters, "parameter")
        _validate_names(self.predicates, "predicate")
        rule_ids = tuple(rule.id for rule in self.rules)
        _require_unique_names(rule_ids, "author Rule IDs")
        return self


class AuthorPolicyCompilationError(ValueError):
    """A safe compile-time rejection without author payload values."""


def compile_author_policy(policy: AuthorPolicy) -> MatchPlan:
    """Compile strict author data to the only executable IR, MatchPlan v1."""

    _validate_predicate_graph(policy.predicates)
    try:
        return MatchPlan(
            scopes=policy.scopes,
            limits=policy.limits,
            parameters=tuple(
                ParameterDeclaration(
                    name=name,
                    type=spec.type,
                    required=spec.required,
                    default=spec.default,
                )
                for name, spec in policy.parameters.items()
            ),
            rules=tuple(_compile_rule(rule, policy.predicates) for rule in policy.rules),
        )
    except AuthorPolicyCompilationError:
        raise
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise AuthorPolicyCompilationError(
            f"author policy cannot compile to MatchPlan: {details}"
        ) from exc


def _compile_rule(
    rule: AuthorRule,
    predicates: dict[StrictStr, AuthorPredicateDefinition],
) -> MatchRulePlan:
    event_bindings = tuple(
        EventBinding(
            name=name,
            kind=spec.kind,
            domain=spec.domain,
            origins=spec.origins,
        )
        for name, spec in rule.events.items()
    )
    derive = tuple(
        SplitLinesDerivation(
            name=name,
            source=_compile_value(spec.source, {}),
        )
        for name, spec in rule.derive.items()
    )
    collections = tuple(
        CollectionBinding(
            name=name,
            source=_compile_value(spec.source, {}),
            item_type=spec.item_type,
        )
        for name, spec in rule.collections.items()
    )
    automatic_bindings = (*rule.events, *rule.collections)
    finding_bindings = (*automatic_bindings, *rule.finding.bindings)
    return MatchRulePlan(
        id=rule.id,
        event_bindings=event_bindings,
        derive=derive,
        collection_bindings=collections,
        where=_compile_condition(
            rule.where,
            predicates=predicates,
            substitutions={},
            stack=(),
        ),
        finding=FindingTemplate(
            code=rule.finding.code,
            message=rule.finding.message,
            subjects=rule.finding.subjects,
            bindings=finding_bindings,
            evidence=tuple(
                EvidenceProjection(
                    source=item.source,
                    id=item.id,
                    include_locations=item.include_locations,
                    masked_evidence=item.masked_evidence,
                )
                for item in rule.finding.evidence
            ),
        ),
        limits=rule.limits,
    )


def _compile_condition(
    condition: AuthorCondition,
    *,
    predicates: dict[StrictStr, AuthorPredicateDefinition],
    substitutions: dict[str, AuthorValue],
    stack: tuple[str, ...],
) -> MatchCondition:
    nested = {
        "predicates": predicates,
        "substitutions": substitutions,
        "stack": stack,
    }
    if condition.all is not None:
        return MatchCondition(
            all=tuple(_compile_condition(child, **nested) for child in condition.all)
        )
    if condition.any is not None:
        return MatchCondition(
            any=tuple(_compile_condition(child, **nested) for child in condition.any)
        )
    if condition.not_ is not None:
        return MatchCondition.model_validate(
            {"not": _compile_condition(condition.not_, **nested)}
        )
    if condition.compare is not None:
        comparison = condition.compare
        return MatchCondition(
            compare=Comparison(
                id=comparison.id,
                left=_compile_value(comparison.left, substitutions),
                operator=comparison.operator,
                right=_compile_value(comparison.right, substitutions),
            )
        )
    if condition.present is not None:
        value = _substitute_field(condition.present, substitutions)
        return MatchCondition(present=PresenceCondition(field=_field_value(value)))
    if condition.relation is not None:
        relation = condition.relation
        return MatchCondition(
            relation=RelationCondition(
                source=_substitute_binding_name(relation.source, substitutions),
                target=_substitute_binding_name(relation.target, substitutions),
                operator=relation.operator,
            )
        )
    if condition.tool is not None:
        binding = _substitute_binding_name(condition.tool.binding, substitutions)
        return MatchCondition(
            compare=Comparison(
                left=FieldValue(binding=binding, path=("payload", "name")),
                operator=ComparisonOperator.EQUALS,
                right=LiteralValue(value=condition.tool.name),
            )
        )
    if condition.predicate is not None:
        predicate = condition.predicate
        return MatchCondition(
            predicate=PredicateCondition(
                id=predicate.id,
                capability=predicate.capability,
                arguments=tuple(
                    _compile_value(argument, substitutions)
                    for argument in predicate.arguments
                ),
            )
        )
    if condition.detector is not None:
        detector = condition.detector
        return MatchCondition(
            detector=DetectorCondition(
                id=detector.id,
                capability=detector.capability,
                inputs=tuple(
                    DetectorInput(
                        value=_compile_value(item.value, substitutions),
                        encoding=item.encoding,
                    )
                    for item in detector.inputs
                ),
                types_any=detector.types_any,
            )
        )
    if condition.similarity is not None:
        similarity = condition.similarity
        return MatchCondition(
            similarity=SimilarityCondition(
                id=similarity.id,
                capability=similarity.capability,
                data=_compile_value(similarity.data, substitutions),
                target=_compile_value(similarity.target, substitutions),
                threshold=similarity.threshold,
            )
        )
    if condition.use is not None:
        return _expand_predicate(
            condition.use,
            predicates=predicates,
            substitutions=substitutions,
            stack=stack,
        )
    if condition.quantify is not None:
        quantifier = condition.quantify
        if quantifier.event is not None:
            local_name = quantifier.event.name
            local_binding: EventBinding | CollectionBinding = EventBinding(
                name=local_name,
                kind=quantifier.event.kind,
                domain=quantifier.event.domain,
                origins=quantifier.event.origins,
            )
        elif quantifier.collection is not None:
            local_name = quantifier.collection.name
            local_binding = CollectionBinding(
                name=local_name,
                source=_compile_value(quantifier.collection.source, substitutions),
                item_type=quantifier.collection.item_type,
            )
        else:  # pragma: no cover - schema guarantees exactly one
            raise AuthorPolicyCompilationError("author quantifier has no binding")
        if local_name in substitutions:
            raise AuthorPolicyCompilationError(
                "declarative predicate parameter cannot be shadowed by a quantifier"
            )
        bounds = (
            CountBounds(minimum=quantifier.minimum, maximum=quantifier.maximum)
            if quantifier.operator is QuantifierOperator.COUNT
            else None
        )
        return MatchCondition(
            quantify=QuantifierPlan(
                operator=quantifier.operator,
                binding=local_binding,
                where=_compile_condition(quantifier.where, **nested),
                count=bounds,
            )
        )
    raise AuthorPolicyCompilationError("author condition has no operation")


def _expand_predicate(
    use: AuthorPredicateUse,
    *,
    predicates: dict[StrictStr, AuthorPredicateDefinition],
    substitutions: dict[str, AuthorValue],
    stack: tuple[str, ...],
) -> MatchCondition:
    definition = predicates.get(use.name)
    if definition is None:
        raise AuthorPolicyCompilationError("author predicate call references an unknown predicate")
    if use.name in stack:
        raise AuthorPolicyCompilationError("author declarative predicates cannot be recursive")
    expected = set(definition.parameters)
    supplied = set(use.arguments)
    if supplied != expected:
        raise AuthorPolicyCompilationError("author predicate arguments do not match its parameters")
    expanded_arguments = {
        name: _substitute_value(value, substitutions)
        for name, value in use.arguments.items()
    }
    return _compile_condition(
        definition.where,
        predicates=predicates,
        substitutions=expanded_arguments,
        stack=(*stack, use.name),
    )


def _compile_value(
    value: AuthorValue,
    substitutions: dict[str, AuthorValue],
) -> ValueReference:
    resolved = _substitute_value(value, substitutions)
    if resolved.field is not None:
        return _field_value(resolved.field)
    if resolved.binding is not None:
        return BindingValue(name=resolved.binding)
    if resolved.derived is not None:
        return DerivedValue(name=resolved.derived)
    if resolved.parameter is not None:
        return ParameterValue(name=resolved.parameter)
    literal = resolved.literal
    if isinstance(literal, tuple):
        return LiteralListValue(items=literal)
    if literal is None:
        return NullValue()
    return LiteralValue(value=literal)


def _substitute_value(
    value: AuthorValue,
    substitutions: dict[str, AuthorValue],
) -> AuthorValue:
    if value.binding is not None and value.binding in substitutions:
        return substitutions[value.binding]
    if value.field is not None and isinstance(value.field[0], str):
        if value.field[0] in substitutions:
            return AuthorValue(
                field=_substitute_field(value.field, substitutions),
            )
    return value


def _substitute_field(
    field: tuple[PathSegment, ...],
    substitutions: dict[str, AuthorValue],
) -> tuple[PathSegment, ...]:
    root = field[0]
    if not isinstance(root, str) or root not in substitutions:
        return field
    argument = substitutions[root]
    suffix = field[1:]
    if argument.binding is not None:
        return (argument.binding, *suffix)
    if argument.field is not None:
        return (*argument.field, *suffix)
    raise AuthorPolicyCompilationError(
        "author predicate field parameter requires a binding or field argument"
    )


def _substitute_binding_name(
    name: str,
    substitutions: dict[str, AuthorValue],
) -> str:
    argument = substitutions.get(name)
    if argument is None:
        return name
    if argument.binding is None:
        raise AuthorPolicyCompilationError(
            "author predicate Event parameter requires a binding argument"
        )
    return argument.binding


def _field_value(path: tuple[PathSegment, ...]) -> FieldValue:
    binding = path[0]
    if not isinstance(binding, str):
        raise AuthorPolicyCompilationError("author field path must start with a binding name")
    return FieldValue(binding=binding, path=path[1:])


def _validate_predicate_graph(
    predicates: dict[StrictStr, AuthorPredicateDefinition],
) -> None:
    calls = {
        name: _condition_predicate_uses(definition.where)
        for name, definition in predicates.items()
    }
    for uses in calls.values():
        for use in uses:
            target = predicates.get(use.name)
            if target is None:
                raise AuthorPolicyCompilationError(
                    "author predicate references an unknown declarative predicate"
                )
            if set(use.arguments) != set(target.parameters):
                raise AuthorPolicyCompilationError(
                    "author predicate arguments do not match its parameters"
                )

    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in active:
            raise AuthorPolicyCompilationError(
                "author declarative predicates cannot be recursive"
            )
        if name in visited:
            return
        active.add(name)
        for use in calls[name]:
            visit(use.name)
        active.remove(name)
        visited.add(name)

    for name in predicates:
        visit(name)


def _condition_predicate_uses(condition: AuthorCondition) -> tuple[AuthorPredicateUse, ...]:
    if condition.use is not None:
        return (condition.use,)
    if condition.all is not None:
        return tuple(
            use
            for item in condition.all
            for use in _condition_predicate_uses(item)
        )
    if condition.any is not None:
        return tuple(
            use
            for item in condition.any
            for use in _condition_predicate_uses(item)
        )
    if condition.not_ is not None:
        return _condition_predicate_uses(condition.not_)
    if condition.quantify is not None:
        return _condition_predicate_uses(condition.quantify.where)
    return ()


def _validate_author_path(path: tuple[PathSegment, ...]) -> None:
    first = path[0]
    if not isinstance(first, str) or not _valid_identifier(first):
        raise ValueError("author field path must start with a binding name")
    for segment in path[1:]:
        if isinstance(segment, bool):
            raise ValueError("author field path cannot contain boolean indexes")
        if isinstance(segment, int):
            if segment < 0:
                raise ValueError("author field path indexes must be non-negative")
            continue
        if not segment or segment != segment.strip() or len(segment) > 64:
            raise ValueError("author field path contains an invalid segment")


def _validate_names(values: Mapping[str, object], label: str) -> None:
    if any(not _valid_identifier(name) for name in values):
        raise ValueError(f"author {label} name is invalid")


def _require_unique_names(values: tuple[object, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"author {label} must be unique")
    if any(isinstance(value, str) and not _valid_identifier(value) for value in values):
        raise ValueError(f"author {label} contains an invalid name")


def _valid_identifier(value: str) -> bool:
    return re.fullmatch(_IDENTIFIER_PATTERN, value) is not None


def _require_trimmed(value: str, label: str) -> None:
    if not value.strip() or value != value.strip():
        raise ValueError(f"author {label} must be a non-blank trimmed string")


AuthorQuantifier.model_rebuild()
