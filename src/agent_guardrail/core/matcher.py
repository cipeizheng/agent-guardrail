"""Deterministic, stateless, and bounded snapshot evaluation for MatchPlan v1."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from itertools import product
from typing import cast

from pydantic import JsonValue

from agent_guardrail.core.capabilities import CompiledMatchPlan
from agent_guardrail.core.match_plan import (
    BindingDomain,
    BindingValue,
    CollectionBinding,
    Comparison,
    ComparisonOperator,
    CostDimension,
    DerivedValue,
    DetectorCondition,
    DetectorInputEncoding,
    EventBinding,
    EvidenceProjectionSource,
    FieldValue,
    LiteralListValue,
    LiteralValue,
    MatchBudgetExceeded,
    MatchCondition,
    MatchCostLedger,
    MatchPlan,
    MatchRulePlan,
    NullValue,
    ParameterType,
    ParameterValue,
    PredicateCondition,
    QuantifierOperator,
    RelationOperator,
    SimilarityCondition,
    SimilarityThreshold,
    SplitLinesDerivation,
    ValueReference,
    ValueType,
)
from agent_guardrail.core.protocols import PredicateContext
from agent_guardrail.core.registry import (
    DetectorPolicyDescriptor,
    SimilarityPolicyDescriptor,
)
from agent_guardrail.models import (
    AnalysisError,
    AnalysisErrorCode,
    AnalysisReport,
    AnalysisScope,
    Detection,
    DetectionContext,
    Event,
    EventKind,
    EvidenceSource,
    Finding,
    FindingBinding,
    FindingEmission,
    FindingEvidence,
    FindingLocation,
    PendingTrace,
    RelationKind,
    Trace,
    compute_binding_key,
)

_BINDING_KEY_NAMESPACE = "match.binding"
_MAX_CAPABILITY_EVIDENCE = 64
_MISSING = object()


@dataclass(frozen=True, slots=True)
class _RuntimeValue:
    value: object
    coordinate: JsonValue
    event_id: str | None = None
    location: FindingLocation | None = None
    items: tuple[_RuntimeValue, ...] | None = None


@dataclass(frozen=True, slots=True)
class _ConditionResult:
    matched: bool
    complete: bool = True
    captures: tuple[_Capture, ...] = ()


@dataclass(frozen=True, slots=True)
class _Capture:
    source: EvidenceProjectionSource
    id: str
    capability: str | None = None
    locations: tuple[FindingLocation, ...] = ()
    facts: tuple[_CapturedEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class _CapturedEvidence:
    type: str
    capability: str
    location: FindingLocation | None = None
    masked_evidence: str | None = None
    fingerprint: str | None = None
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class _EventSnapshot:
    events: tuple[Event, ...]
    past_event_ids: frozenset[str]
    pending_event_ids: frozenset[str]


class _CapabilityFailure(RuntimeError):
    """A safe, already-redacted capability failure at a Rule boundary."""

    def __init__(
        self,
        *,
        code: AnalysisErrorCode,
        message: str,
        capability: str,
        retryable: bool = False,
    ) -> None:
        self.code = code
        self.capability = capability
        self.retryable = retryable
        super().__init__(message)


class _CapabilityRuntime:
    """Analysis-local capability handles and memoized trusted results."""

    def __init__(self, compiled: CompiledMatchPlan) -> None:
        self.predicates = {
            item.descriptor.name: item for item in compiled.predicates
        }
        self.detectors = {
            item.descriptor.name: item for item in compiled.detectors
        }
        self.similarities = {
            item.descriptor.name: item for item in compiled.similarities
        }
        self.predicate_cache: dict[tuple[object, ...], bool] = {}
        self.detector_cache: dict[tuple[object, ...], tuple[Detection, ...]] = {}
        self.similarity_cache: dict[tuple[object, ...], tuple[Detection, ...]] = {}


class SnapshotMatcher:
    """Analyze complete Trace snapshots without retaining cross-call state."""

    __slots__ = ("_compiled", "_plan", "_policy_hash", "_policy_version")

    def __init__(
        self,
        plan: MatchPlan | CompiledMatchPlan,
        *,
        policy_version: int,
        policy_hash: str,
    ) -> None:
        if isinstance(policy_version, bool) or not isinstance(policy_version, int):
            raise TypeError("policy_version must be an integer")
        if policy_version < 1:
            raise ValueError("policy_version must be at least one")
        if not isinstance(policy_hash, str):
            raise TypeError("policy_hash must be a string")
        if not 8 <= len(policy_hash) <= 128 or not policy_hash.strip():
            raise ValueError("policy_hash must be a non-blank bounded string")
        if policy_hash != policy_hash.strip():
            raise ValueError("policy_hash must be trimmed")
        self._compiled = plan if isinstance(plan, CompiledMatchPlan) else None
        self._plan = plan.plan if isinstance(plan, CompiledMatchPlan) else plan
        self._policy_version = policy_version
        self._policy_hash = policy_hash

    async def analyze(
        self,
        trace: Trace,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> AnalysisReport:
        """Return every match in one immutable view of the supplied Trace."""

        events = tuple(event.model_copy(deep=True) for event in trace.events)
        snapshot = _EventSnapshot(
            events=events,
            past_event_ids=frozenset(event.id for event in events),
            pending_event_ids=frozenset(),
        )
        return await self._analyze_snapshot(
            trace_id=trace.id,
            snapshot=snapshot,
            scope=AnalysisScope.SNAPSHOT,
            parameters=parameters,
        )

    async def analyze_pending(
        self,
        pending_trace: PendingTrace,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> AnalysisReport:
        """Return all pending-subject matches over committed and tentative Events."""

        past = tuple(event.model_copy(deep=True) for event in pending_trace.trace.events)
        pending = tuple(event.model_copy(deep=True) for event in pending_trace.events)
        snapshot = _EventSnapshot(
            events=(*past, *pending),
            past_event_ids=frozenset(event.id for event in past),
            pending_event_ids=frozenset(event.id for event in pending),
        )
        return await self._analyze_snapshot(
            trace_id=pending_trace.trace.id,
            snapshot=snapshot,
            scope=AnalysisScope.PENDING,
            parameters=parameters,
        )

    async def _analyze_snapshot(
        self,
        *,
        trace_id: str,
        snapshot: _EventSnapshot,
        scope: AnalysisScope,
        parameters: Mapping[str, object] | None,
    ) -> AnalysisReport:
        event_ids = tuple(event.id for event in snapshot.events)
        pending_event_ids = tuple(
            event.id
            for event in snapshot.events
            if event.id in snapshot.pending_event_ids
        )
        base = {
            "scope": scope,
            "emission": FindingEmission.ALL,
            "policy_version": self._policy_version,
            "policy_hash": self._policy_hash,
            "trace_id": trace_id,
            "event_ids": event_ids,
            "pending_event_ids": pending_event_ids,
        }
        if scope not in self._plan.scopes:
            return AnalysisReport(
                **base,
                findings=(),
                errors=(
                    AnalysisError(
                        code=AnalysisErrorCode.INPUT_ERROR,
                        message=f"MatchPlan does not support {scope.value} analysis",
                    ),
                ),
            )

        resolved_parameters, parameter_error = _resolve_parameters(self._plan, parameters)
        if parameter_error is not None:
            return AnalysisReport(
                **base,
                findings=(),
                errors=(parameter_error,),
            )

        ledger = MatchCostLedger(self._plan)
        capability_runtime = (
            _CapabilityRuntime(self._compiled) if self._compiled is not None else None
        )
        findings: list[Finding] = []
        errors: list[AnalysisError] = []
        events_by_id = {event.id: event for event in snapshot.events}

        for rule in self._plan.rules:
            capability = (
                _first_unavailable_capability(rule.where)
                if capability_runtime is None
                else None
            )
            if capability is not None:
                source, name = capability
                errors.append(
                    AnalysisError(
                        code=AnalysisErrorCode.CAPABILITY_ERROR,
                        message=f"{source.value} capability execution is not available",
                        rule_id=rule.id,
                        capability=name,
                    )
                )
                continue
            try:
                rule_findings = await _evaluate_rule(
                    rule=rule,
                    trace_id=trace_id,
                    snapshot=snapshot,
                    events_by_id=events_by_id,
                    parameters=resolved_parameters,
                    ledger=ledger,
                    capability_runtime=capability_runtime,
                    policy_hash=self._policy_hash,
                    required_subject_event_ids=(
                        snapshot.pending_event_ids
                        if scope is AnalysisScope.PENDING
                        else None
                    ),
                )
            except MatchBudgetExceeded as exc:
                errors.append(
                    AnalysisError(
                        code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
                        message=f"MatchPlan resource budget exhausted: {exc.dimension.value}",
                        rule_id=rule.id,
                    )
                )
                if exc.rule_id is None:
                    break
            except _CapabilityFailure as exc:
                errors.append(
                    AnalysisError(
                        code=exc.code,
                        message=str(exc),
                        rule_id=rule.id,
                        capability=exc.capability,
                        retryable=exc.retryable,
                    )
                )
            except Exception:  # pragma: no cover - defensive public boundary
                errors.append(
                    AnalysisError(
                        code=AnalysisErrorCode.INTERNAL_ERROR,
                        message="MatchPlan rule evaluation failed",
                        rule_id=rule.id,
                    )
                )
            else:
                findings.extend(rule_findings)

        return AnalysisReport(
            **base,
            findings=tuple(_unique_findings(findings)),
            errors=tuple(errors),
        )


def _resolve_parameters(
    plan: MatchPlan,
    supplied: Mapping[str, object] | None,
) -> tuple[dict[str, _RuntimeValue], AnalysisError | None]:
    if supplied is None:
        values: Mapping[str, object] = {}
    elif isinstance(supplied, Mapping):
        values = supplied
    else:
        return {}, _parameter_error("MatchPlan parameters must be a mapping")

    declarations = {parameter.name: parameter for parameter in plan.parameters}
    if any(not isinstance(name, str) for name in values):
        return {}, _parameter_error("MatchPlan parameter names must be strings")
    unknown = set(values) - declarations.keys()
    if unknown:
        return {}, _parameter_error("MatchPlan received an unknown parameter")

    resolved: dict[str, _RuntimeValue] = {}
    for name, declaration in declarations.items():
        if name in values:
            value = values[name]
        elif declaration.required:
            return {}, _parameter_error("MatchPlan is missing a required parameter")
        else:
            value = declaration.default
        if not _parameter_matches(declaration.type, value):
            return {}, _parameter_error("MatchPlan parameter has the wrong type")
        resolved[name] = _RuntimeValue(
            value=value,
            coordinate=cast(JsonValue, {"type": "parameter", "name": name}),
        )
    return resolved, None


def _parameter_matches(parameter_type: ParameterType, value: object) -> bool:
    return {
        ParameterType.STRING: type(value) is str,
        ParameterType.INTEGER: type(value) is int,
        ParameterType.FLOAT: type(value) is float,
        ParameterType.BOOLEAN: type(value) is bool,
    }[parameter_type]


def _parameter_error(message: str) -> AnalysisError:
    return AnalysisError(code=AnalysisErrorCode.PARAMETER_ERROR, message=message)


async def _evaluate_rule(
    *,
    rule: MatchRulePlan,
    trace_id: str,
    snapshot: _EventSnapshot,
    events_by_id: dict[str, Event],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
    capability_runtime: _CapabilityRuntime | None,
    policy_hash: str,
    required_subject_event_ids: frozenset[str] | None,
) -> list[Finding]:
    domains = tuple(
        _event_domain(binding, snapshot, rule.id, ledger)
        for binding in rule.event_bindings
    )
    findings: list[Finding] = []
    for assignment in product(*domains):
        ledger.consume(rule.id, CostDimension.BINDING_COMBINATIONS)
        environment = {
            binding.name: value
            for binding, value in zip(rule.event_bindings, assignment, strict=True)
        }
        derived = _evaluate_derivations(rule, environment, parameters, ledger)
        for expanded in _expand_collections(
            rule,
            environment,
            derived,
            parameters,
            ledger,
        ):
            result = await _evaluate_condition(
                rule.where,
                rule_id=rule.id,
                trace_id=trace_id,
                environment=expanded,
                derived=derived,
                parameters=parameters,
                snapshot=snapshot,
                events_by_id=events_by_id,
                ledger=ledger,
                capability_runtime=capability_runtime,
            )
            if not result.matched:
                continue
            if required_subject_event_ids is not None and not any(
                cast(Event, expanded[name].value).id in required_subject_event_ids
                for name in rule.finding.subjects
            ):
                continue
            ledger.consume(rule.id, CostDimension.FINDINGS)
            findings.append(
                _create_finding(
                    rule=rule,
                    environment=expanded,
                    derived=derived,
                    parameters=parameters,
                    captures=result.captures,
                    ledger=ledger,
                    policy_hash=policy_hash,
                )
            )
    return findings


def _event_domain(
    binding: EventBinding,
    snapshot: _EventSnapshot,
    rule_id: str,
    ledger: MatchCostLedger,
) -> tuple[_RuntimeValue, ...]:
    selected: list[_RuntimeValue] = []
    for event in snapshot.events:
        if (
            binding.domain is BindingDomain.PAST
            and event.id not in snapshot.past_event_ids
        ):
            continue
        if (
            binding.domain is BindingDomain.PENDING
            and event.id not in snapshot.pending_event_ids
        ):
            continue
        if event.kind is not binding.kind:
            continue
        if binding.origins and event.origin not in binding.origins:
            continue
        ledger.consume(rule_id, CostDimension.CANDIDATE_EVENTS)
        selected.append(
            _RuntimeValue(
                value=event,
                coordinate=cast(JsonValue, {"type": "event", "event_id": event.id}),
                event_id=event.id,
            )
        )
    return tuple(selected)


def _evaluate_derivations(
    rule: MatchRulePlan,
    environment: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
) -> dict[str, _RuntimeValue]:
    derived: dict[str, _RuntimeValue] = {}
    for declaration in rule.derive:
        derived[declaration.name] = _split_lines(
            declaration,
            rule_id=rule.id,
            environment=environment,
            derived=derived,
            parameters=parameters,
            ledger=ledger,
        )
    return derived


def _split_lines(
    declaration: SplitLinesDerivation,
    *,
    rule_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
) -> _RuntimeValue:
    source = _resolve_value(declaration.source, environment, derived, parameters)
    coordinate = cast(
        JsonValue,
        {"type": "derived", "name": declaration.name, "source": source.coordinate},
    )
    if type(source.value) is not str:
        return _RuntimeValue(
            value=(),
            coordinate=coordinate,
            event_id=source.event_id,
            location=source.location,
            items=(),
        )

    items: list[_RuntimeValue] = []
    offset = 0
    for index, raw_line in enumerate(source.value.splitlines(keepends=True)):
        line = raw_line.rstrip("\r\n")
        ledger.consume(rule_id, CostDimension.DERIVED_ITEMS)
        encoded_size = len(line.encode("utf-8"))
        if encoded_size:
            ledger.consume(rule_id, CostDimension.DERIVED_BYTES, encoded_size)
        location = _line_location(source.location, offset, len(line))
        items.append(
            _RuntimeValue(
                value=line,
                coordinate=cast(
                    JsonValue,
                    {"type": "derived_item", "derive": declaration.name, "index": index},
                ),
                event_id=source.event_id,
                location=location,
            )
        )
        offset += len(raw_line)
    return _RuntimeValue(
        value=tuple(item.value for item in items),
        coordinate=coordinate,
        event_id=source.event_id,
        location=source.location,
        items=tuple(items),
    )


def _line_location(
    source: FindingLocation | None,
    offset: int,
    length: int,
) -> FindingLocation | None:
    if source is None:
        return None
    base = source.start or 0
    if length == 0:
        return FindingLocation(event_id=source.event_id, path=source.path)
    return FindingLocation(
        event_id=source.event_id,
        path=source.path,
        start=base + offset,
        end=base + offset + length,
    )


def _expand_collections(
    rule: MatchRulePlan,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
) -> tuple[dict[str, _RuntimeValue], ...]:
    branches: list[dict[str, _RuntimeValue]] = [dict(environment)]
    for binding in rule.collection_bindings:
        expanded: list[dict[str, _RuntimeValue]] = []
        for branch in branches:
            source = _resolve_value(binding.source, branch, derived, parameters)
            source_items = source.items
            if source_items is None:
                if not isinstance(source.value, (list, tuple)):
                    continue
                source_items = tuple(
                    _collection_item(source, binding.name, index, value)
                    for index, value in enumerate(source.value)
                )
            for index, item in enumerate(source_items):
                ledger.consume(rule.id, CostDimension.COLLECTION_ITEMS)
                if not _item_matches(binding.item_type, item.value):
                    continue
                bound = item
                if source.items is not None:
                    bound = _RuntimeValue(
                        value=item.value,
                        coordinate=cast(
                            JsonValue,
                            {
                                "type": "collection_item",
                                "binding": binding.name,
                                "source": source.coordinate,
                                "index": index,
                            },
                        ),
                        event_id=item.event_id,
                        location=item.location,
                    )
                next_branch = dict(branch)
                next_branch[binding.name] = bound
                expanded.append(next_branch)
        branches = expanded
        if not branches:
            break
    return tuple(branches)


def _collection_item(
    source: _RuntimeValue,
    binding_name: str,
    index: int,
    value: object,
) -> _RuntimeValue:
    location = None
    if source.location is not None:
        location = FindingLocation(
            event_id=source.location.event_id,
            path=(*source.location.path, index),
        )
    return _RuntimeValue(
        value=value,
        coordinate=cast(
            JsonValue,
            {
                "type": "collection_item",
                "binding": binding_name,
                "source": source.coordinate,
                "index": index,
            },
        ),
        event_id=source.event_id,
        location=location,
    )


def _item_matches(item_type: ValueType, value: object) -> bool:
    if item_type is ValueType.STRING:
        return type(value) is str
    if item_type is ValueType.INTEGER:
        return type(value) is int
    if item_type is ValueType.FLOAT:
        return type(value) is float
    if item_type is ValueType.BOOLEAN:
        return type(value) is bool
    if item_type is ValueType.OBJECT:
        return isinstance(value, Mapping)
    if item_type is ValueType.ARRAY:
        return isinstance(value, (list, tuple))
    return _is_json_value(value)


def _is_json_value(value: object) -> bool:
    if value is None or type(value) in {str, int, float, bool}:
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, Mapping):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


async def _evaluate_condition(
    condition: MatchCondition,
    *,
    rule_id: str,
    trace_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    snapshot: _EventSnapshot,
    events_by_id: dict[str, Event],
    ledger: MatchCostLedger,
    capability_runtime: _CapabilityRuntime | None,
) -> _ConditionResult:
    ledger.consume(rule_id, CostDimension.CONDITION_STEPS)
    nested = {
        "rule_id": rule_id,
        "trace_id": trace_id,
        "environment": environment,
        "derived": derived,
        "parameters": parameters,
        "snapshot": snapshot,
        "events_by_id": events_by_id,
        "ledger": ledger,
        "capability_runtime": capability_runtime,
    }
    if condition.all is not None:
        captures: tuple[_Capture, ...] = ()
        for child in condition.all:
            result = await _evaluate_condition(child, **nested)
            if not result.matched:
                return result
            captures = _merge_captures(captures, result.captures)
        return _ConditionResult(True, captures=captures)
    if condition.any is not None:
        complete = True
        for child in condition.any:
            result = await _evaluate_condition(child, **nested)
            if result.matched:
                return result
            complete = complete and result.complete
        return _ConditionResult(False, complete=complete)
    if condition.not_ is not None:
        result = await _evaluate_condition(condition.not_, **nested)
        if not result.complete:
            return _ConditionResult(False, complete=False)
        return _ConditionResult(not result.matched)
    if condition.compare is not None:
        return _evaluate_comparison(condition.compare, environment, derived, parameters)
    if condition.present is not None:
        value = _resolve_value(condition.present.field, environment, derived, parameters)
        return _ConditionResult(value.value is not _MISSING)
    if condition.relation is not None:
        return _evaluate_relation(
            condition.relation.source,
            condition.relation.target,
            condition.relation.operator,
            rule_id=rule_id,
            environment=environment,
            events_by_id=events_by_id,
            ledger=ledger,
        )
    if condition.predicate is not None:
        if capability_runtime is None:  # pragma: no cover - pre-scanned by caller
            raise RuntimeError("uncompiled Predicate reached evaluation")
        return await _evaluate_predicate(
            condition.predicate,
            rule_id=rule_id,
            trace_id=trace_id,
            environment=environment,
            derived=derived,
            parameters=parameters,
            ledger=ledger,
            runtime=capability_runtime,
        )
    if condition.detector is not None:
        if capability_runtime is None:  # pragma: no cover - pre-scanned by caller
            raise RuntimeError("uncompiled Detector reached evaluation")
        return await _evaluate_detector(
            condition.detector,
            rule_id=rule_id,
            trace_id=trace_id,
            environment=environment,
            derived=derived,
            parameters=parameters,
            ledger=ledger,
            runtime=capability_runtime,
        )
    if condition.similarity is not None:
        if capability_runtime is None:  # pragma: no cover - pre-scanned by caller
            raise RuntimeError("uncompiled Similarity reached evaluation")
        return await _evaluate_similarity(
            condition.similarity,
            rule_id=rule_id,
            trace_id=trace_id,
            environment=environment,
            derived=derived,
            parameters=parameters,
            ledger=ledger,
            runtime=capability_runtime,
        )
    if condition.quantify is not None:
        return await _evaluate_quantifier(condition, **nested)
    raise RuntimeError("validated MatchPlan condition has no operation")


async def _evaluate_predicate(
    condition: PredicateCondition,
    *,
    rule_id: str,
    trace_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
    runtime: _CapabilityRuntime,
) -> _ConditionResult:
    compiled = runtime.predicates[condition.capability]
    descriptor = compiled.descriptor
    resolved = tuple(
        _resolve_value(argument, environment, derived, parameters)
        for argument in condition.arguments
    )
    if any(value.value is _MISSING for value in resolved):
        return _ConditionResult(False, complete=False)
    arguments: list[JsonValue] = []
    for value, expected in zip(resolved, descriptor.argument_types, strict=True):
        converted = _json_capability_value(value.value)
        if converted is _MISSING or not _value_matches_type(
            cast(JsonValue, converted),
            expected,
        ):
            return _ConditionResult(False, complete=False)
        arguments.append(cast(JsonValue, converted))
    encoded = _canonical_json_bytes(arguments, condition.capability)
    _charge_capability_input(
        rule_id=rule_id,
        capability=condition.capability,
        encoded_size=len(encoded),
        descriptor_limit=descriptor.max_input_bytes,
        calls_dimension=CostDimension.PREDICATE_CALLS,
        bytes_dimension=CostDimension.PREDICATE_INPUT_BYTES,
        ledger=ledger,
    )
    event_ids = tuple(event.id for event in _environment_events(environment))
    context = PredicateContext(
        trace_id=trace_id,
        rule_id=rule_id,
        condition_id=condition.id,
        event_ids=event_ids,
    )
    cache_key = (
        condition.capability,
        compiled.implementation.version,
        sha256(encoded).digest(),
        trace_id,
        rule_id,
        condition.id,
        event_ids,
    )
    if cache_key in runtime.predicate_cache:
        matched = runtime.predicate_cache[cache_key]
    else:
        ledger.consume(rule_id, CostDimension.PREDICATE_TIME_MS, descriptor.timeout_ms)
        try:
            async with asyncio.timeout(descriptor.timeout_ms / 1_000):
                result = await compiled.implementation.evaluate(
                    tuple(arguments),
                    context=context,
                )
        except TimeoutError as exc:
            raise _CapabilityFailure(
                code=descriptor.timeout_code,
                message="Predicate capability timed out",
                capability=condition.capability,
                retryable=True,
            ) from exc
        except Exception as exc:
            raise _CapabilityFailure(
                code=descriptor.error_code,
                message="Predicate capability execution failed",
                capability=condition.capability,
            ) from exc
        if type(result) is not bool:
            raise _CapabilityFailure(
                code=descriptor.error_code,
                message="Predicate capability returned an invalid result",
                capability=condition.capability,
            )
        matched = result
        runtime.predicate_cache[cache_key] = matched
    if not matched:
        return _ConditionResult(False)
    locations = tuple(
        _unique_locations(
            [value.location for value in resolved if value.location is not None]
        )
    )
    facts = tuple(
        _CapturedEvidence(
            type=condition.id,
            capability=condition.capability,
            location=location,
        )
        for location in locations
    ) or (
        _CapturedEvidence(
            type=condition.id,
            capability=condition.capability,
        ),
    )
    return _ConditionResult(
        True,
        captures=(
            _Capture(
                source=EvidenceProjectionSource.PREDICATE,
                id=condition.id,
                capability=condition.capability,
                locations=locations,
                facts=facts,
            ),
        ),
    )


async def _evaluate_detector(
    condition: DetectorCondition,
    *,
    rule_id: str,
    trace_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
    runtime: _CapabilityRuntime,
) -> _ConditionResult:
    compiled = runtime.detectors[condition.capability]
    descriptor = compiled.descriptor
    selected_types = set(condition.types_any)
    facts: list[_CapturedEvidence] = []
    complete = True
    fallback_event = next(iter(_environment_events(environment)), None)
    for detector_input in condition.inputs:
        resolved = _resolve_value(
            detector_input.value,
            environment,
            derived,
            parameters,
        )
        encoded_text = _encode_detector_input(
            resolved,
            detector_input.encoding,
            condition.capability,
        )
        if encoded_text is None:
            complete = False
            continue
        encoded = encoded_text.encode("utf-8")
        _charge_capability_input(
            rule_id=rule_id,
            capability=condition.capability,
            encoded_size=len(encoded),
            descriptor_limit=descriptor.max_input_bytes,
            calls_dimension=CostDimension.DETECTOR_CALLS,
            bytes_dimension=CostDimension.DETECTOR_INPUT_BYTES,
            ledger=ledger,
        )
        context_event = (
            cast(Event, environment_event.value)
            if (
                environment_event := _runtime_event_by_id(
                    environment,
                    resolved.event_id,
                )
            )
            is not None
            else fallback_event
        )
        if context_event is None:  # pragma: no cover - top-level Event bindings are required
            complete = False
            continue
        context = DetectionContext(
            trace_id=trace_id,
            event_id=context_event.id,
        )
        cache_key = (
            condition.capability,
            compiled.implementation.version,
            sha256(encoded).digest(),
            context.trace_id,
            context.event_id,
            detector_input.encoding.value,
        )
        if cache_key in runtime.detector_cache:
            detections = runtime.detector_cache[cache_key]
        else:
            detections = await _invoke_detector(
                condition=condition,
                text=encoded_text,
                context=context,
                descriptor=descriptor,
                implementation=compiled.implementation,
                rule_id=rule_id,
                ledger=ledger,
            )
            runtime.detector_cache[cache_key] = detections
        for detection in detections:
            if selected_types and detection.type not in selected_types:
                continue
            if len(facts) >= _MAX_CAPABILITY_EVIDENCE:
                raise _CapabilityFailure(
                    code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
                    message="Detector evidence result limit exceeded",
                    capability=condition.capability,
                )
            facts.append(
                _CapturedEvidence(
                    type=detection.type,
                    capability=condition.capability,
                    location=_detection_location(
                        resolved,
                        detector_input.encoding,
                        detection,
                    ),
                    masked_evidence=detection.masked_evidence,
                    fingerprint=detection.fingerprint,
                    confidence=detection.confidence,
                )
            )
    if not facts:
        return _ConditionResult(False, complete=complete)
    locations = tuple(
        _unique_locations(
            [fact.location for fact in facts if fact.location is not None]
        )
    )
    return _ConditionResult(
        True,
        complete=complete,
        captures=(
            _Capture(
                source=EvidenceProjectionSource.DETECTOR,
                id=condition.id,
                capability=condition.capability,
                locations=locations,
                facts=tuple(_unique_captured_evidence(facts)),
            ),
        ),
    )


async def _invoke_detector(
    *,
    condition: DetectorCondition,
    text: str,
    context: DetectionContext,
    descriptor: DetectorPolicyDescriptor,
    implementation: object,
    rule_id: str,
    ledger: MatchCostLedger,
) -> tuple[Detection, ...]:
    ledger.consume(rule_id, CostDimension.DETECTOR_TIME_MS, descriptor.timeout_ms)
    try:
        async with asyncio.timeout(descriptor.timeout_ms / 1_000):
            raw = await implementation.detect(text, context=context)  # type: ignore[attr-defined]
    except TimeoutError as exc:
        raise _CapabilityFailure(
            code=descriptor.timeout_code,
            message="Detector capability timed out",
            capability=condition.capability,
            retryable=True,
        ) from exc
    except Exception as exc:
        raise _CapabilityFailure(
            code=descriptor.error_code,
            message="Detector capability execution failed",
            capability=condition.capability,
        ) from exc
    if not isinstance(raw, (list, tuple)) or len(raw) > descriptor.max_detections:
        raise _invalid_detector_result(condition.capability, descriptor)
    result: list[Detection] = []
    for detection in raw:
        if not isinstance(detection, Detection):
            raise _invalid_detector_result(condition.capability, descriptor)
        if (
            detection.detector != condition.capability
            or detection.detector_version != implementation.version  # type: ignore[attr-defined]
            or detection.type not in descriptor.detection_types
            or len(detection.masked_evidence) > 256
            or detection.masked_evidence != detection.masked_evidence.strip()
            or len(detection.fingerprint) > 128
            or any(
                character
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for character in detection.fingerprint
            )
            or (
                detection.end is not None
                and detection.end > len(text)
            )
        ):
            raise _invalid_detector_result(condition.capability, descriptor)
        result.append(detection)
    return tuple(result)


async def _evaluate_similarity(
    condition: SimilarityCondition,
    *,
    rule_id: str,
    trace_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    ledger: MatchCostLedger,
    runtime: _CapabilityRuntime,
) -> _ConditionResult:
    compiled = runtime.similarities[condition.capability]
    descriptor = compiled.descriptor
    data_value = _resolve_value(condition.data, environment, derived, parameters)
    target_value = _resolve_value(condition.target, environment, derived, parameters)
    if data_value.value is _MISSING or target_value.value is _MISSING:
        return _ConditionResult(False, complete=False)
    data = _similarity_texts(data_value.value)
    target = _similarity_texts(target_value.value)
    if not data or not target:
        raise _CapabilityFailure(
            code=AnalysisErrorCode.CAPABILITY_ERROR,
            message="Similarity input does not contain text",
            capability=condition.capability,
        )
    if len(data) > descriptor.max_texts or len(target) > descriptor.max_texts:
        raise _CapabilityFailure(
            code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
            message="Similarity text count exceeds its published limit",
            capability=condition.capability,
        )
    threshold = _similarity_threshold(condition.threshold)
    encoded = _canonical_json_bytes((data, target, threshold), condition.capability)
    _charge_capability_input(
        rule_id=rule_id,
        capability=condition.capability,
        encoded_size=len(encoded),
        descriptor_limit=descriptor.max_input_bytes,
        calls_dimension=CostDimension.DETECTOR_CALLS,
        bytes_dimension=CostDimension.DETECTOR_INPUT_BYTES,
        ledger=ledger,
    )
    fallback_event = next(iter(_environment_events(environment)), None)
    context_event = (
        cast(Event, environment_event.value)
        if (
            environment_event := _runtime_event_by_id(environment, data_value.event_id)
        )
        is not None
        else fallback_event
    )
    if context_event is None:  # pragma: no cover - top-level Event bindings are required
        return _ConditionResult(False, complete=False)
    context = DetectionContext(
        trace_id=trace_id,
        event_id=context_event.id,
    )
    cache_key = (
        condition.capability,
        compiled.implementation.version,
        sha256(encoded).digest(),
        context.trace_id,
        context.event_id,
    )
    if cache_key in runtime.similarity_cache:
        detections = runtime.similarity_cache[cache_key]
    else:
        detections = await _invoke_similarity(
            condition=condition,
            data=data,
            target=target,
            threshold=threshold,
            context=context,
            descriptor=descriptor,
            implementation=compiled.implementation,
            rule_id=rule_id,
            ledger=ledger,
        )
        runtime.similarity_cache[cache_key] = detections
    if not detections:
        return _ConditionResult(False)
    facts = tuple(
        _CapturedEvidence(
            type=detection.type,
            capability=condition.capability,
            location=data_value.location,
            masked_evidence=detection.masked_evidence,
            fingerprint=detection.fingerprint,
            confidence=detection.confidence,
        )
        for detection in detections
    )
    locations = (data_value.location,) if data_value.location is not None else ()
    return _ConditionResult(
        True,
        captures=(
            _Capture(
                source=EvidenceProjectionSource.DETECTOR,
                id=condition.id,
                capability=condition.capability,
                locations=locations,
                facts=facts,
            ),
        ),
    )


async def _invoke_similarity(
    *,
    condition: SimilarityCondition,
    data: tuple[str, ...],
    target: tuple[str, ...],
    threshold: float,
    context: DetectionContext,
    descriptor: SimilarityPolicyDescriptor,
    implementation: object,
    rule_id: str,
    ledger: MatchCostLedger,
) -> tuple[Detection, ...]:
    ledger.consume(rule_id, CostDimension.DETECTOR_TIME_MS, descriptor.timeout_ms)
    try:
        async with asyncio.timeout(descriptor.timeout_ms / 1_000):
            raw = await implementation.compare(  # type: ignore[attr-defined]
                data,
                target,
                threshold,
                context=context,
            )
    except TimeoutError as exc:
        raise _CapabilityFailure(
            code=descriptor.timeout_code,
            message="Similarity capability timed out",
            capability=condition.capability,
            retryable=True,
        ) from exc
    except Exception as exc:
        raise _CapabilityFailure(
            code=descriptor.error_code,
            message="Similarity capability execution failed",
            capability=condition.capability,
        ) from exc
    if not isinstance(raw, (list, tuple)) or len(raw) > 1:
        raise _invalid_similarity_result(condition.capability, descriptor)
    result: list[Detection] = []
    for detection in raw:
        if (
            not isinstance(detection, Detection)
            or detection.detector != condition.capability
            or detection.detector_version != implementation.version  # type: ignore[attr-defined]
            or detection.type != descriptor.detection_type
            or detection.start is not None
            or detection.end is not None
            or len(detection.masked_evidence) > 256
            or detection.masked_evidence != detection.masked_evidence.strip()
            or len(detection.fingerprint) > 128
            or any(
                character
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for character in detection.fingerprint
            )
        ):
            raise _invalid_similarity_result(condition.capability, descriptor)
        result.append(detection)
    return tuple(result)


def _similarity_texts(value: object) -> tuple[str, ...]:
    if type(value) is str:
        return (value,)
    if isinstance(value, Event):
        if value.kind is EventKind.MESSAGE:
            return _similarity_texts(value.payload.get("content"))
        if value.kind is EventKind.TOOL_RESULT:
            return _similarity_texts(value.payload.get("output"))
        return ()
    if type(value) is dict:
        if value.get("type") == "text" and type(value.get("text")) is str:
            return (cast(str, value["text"]),)
        for key in ("content", "output"):
            if key in value:
                return _similarity_texts(value[key])
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(text for item in value for text in _similarity_texts(item))
    return ()


def _similarity_threshold(value: int | float | SimilarityThreshold) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return {
        SimilarityThreshold.MIGHT_RESEMBLE: 0.2,
        SimilarityThreshold.SAME_TOPIC: 0.5,
        SimilarityThreshold.VERY_SIMILAR: 0.8,
    }[value]


def _invalid_detector_result(
    capability: str,
    descriptor: DetectorPolicyDescriptor,
) -> _CapabilityFailure:
    return _CapabilityFailure(
        code=descriptor.error_code,
        message="Detector capability returned an invalid result",
        capability=capability,
    )


def _invalid_similarity_result(
    capability: str,
    descriptor: SimilarityPolicyDescriptor,
) -> _CapabilityFailure:
    return _CapabilityFailure(
        code=descriptor.error_code,
        message="Similarity capability returned an invalid result",
        capability=capability,
    )


def _charge_capability_input(
    *,
    rule_id: str,
    capability: str,
    encoded_size: int,
    descriptor_limit: int,
    calls_dimension: CostDimension,
    bytes_dimension: CostDimension,
    ledger: MatchCostLedger,
) -> None:
    if encoded_size > descriptor_limit:
        raise _CapabilityFailure(
            code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
            message="Capability input exceeds its published byte limit",
            capability=capability,
        )
    ledger.consume(rule_id, calls_dimension)
    ledger.consume(rule_id, bytes_dimension, max(1, encoded_size))


def _canonical_json_bytes(value: object, capability: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _CapabilityFailure(
            code=AnalysisErrorCode.CAPABILITY_ERROR,
            message="Capability input cannot be encoded as canonical JSON",
            capability=capability,
        ) from exc


def _encode_detector_input(
    value: _RuntimeValue,
    encoding: DetectorInputEncoding,
    capability: str,
) -> str | None:
    if value.value is _MISSING:
        return None
    if encoding is DetectorInputEncoding.TEXT:
        return value.value if type(value.value) is str else None
    converted = _json_capability_value(value.value)
    if converted is _MISSING:
        return None
    return _canonical_json_bytes(converted, capability).decode("utf-8")


def _json_capability_value(value: object) -> JsonValue | object:
    if isinstance(value, Event):
        value = _event_envelope(value)
    if value is None or type(value) in {str, int, float, bool}:
        return cast(JsonValue, value)
    if isinstance(value, (list, tuple)):
        items = [_json_capability_value(item) for item in value]
        if any(item is _MISSING for item in items):
            return _MISSING
        return cast(JsonValue, items)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            return _MISSING
        converted = {key: _json_capability_value(item) for key, item in value.items()}
        if any(item is _MISSING for item in converted.values()):
            return _MISSING
        return cast(JsonValue, converted)
    return _MISSING


def _value_matches_type(value: JsonValue, expected: ValueType) -> bool:
    if expected is ValueType.JSON:
        return True
    if expected is ValueType.STRING:
        return type(value) is str
    if expected is ValueType.INTEGER:
        return type(value) is int
    if expected is ValueType.FLOAT:
        return type(value) is float
    if expected is ValueType.BOOLEAN:
        return type(value) is bool
    if expected is ValueType.OBJECT:
        return isinstance(value, dict)
    return isinstance(value, list)


def _environment_events(environment: dict[str, _RuntimeValue]) -> tuple[Event, ...]:
    events = {
        value.value.id: value.value
        for value in environment.values()
        if isinstance(value.value, Event)
    }
    return tuple(sorted(events.values(), key=lambda event: (event.sequence, event.id)))


def _runtime_event_by_id(
    environment: dict[str, _RuntimeValue],
    event_id: str | None,
) -> _RuntimeValue | None:
    if event_id is None:
        return None
    return next(
        (
            value
            for value in environment.values()
            if isinstance(value.value, Event) and value.value.id == event_id
        ),
        None,
    )


def _detection_location(
    source: _RuntimeValue,
    encoding: DetectorInputEncoding,
    detection: Detection,
) -> FindingLocation | None:
    if source.location is None:
        return None
    if (
        encoding is DetectorInputEncoding.TEXT
        and detection.start is not None
        and detection.end is not None
    ):
        base = source.location.start or 0
        return FindingLocation(
            event_id=source.location.event_id,
            path=source.location.path,
            start=base + detection.start,
            end=base + detection.end,
        )
    return source.location


def _evaluate_comparison(
    comparison: Comparison,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
) -> _ConditionResult:
    left = _resolve_value(comparison.left, environment, derived, parameters)
    right = _resolve_value(comparison.right, environment, derived, parameters)
    if left.value is _MISSING or right.value is _MISSING:
        return _ConditionResult(False, complete=False)
    matched, supported = _compare(left.value, comparison.operator, right.value)
    if not supported:
        return _ConditionResult(False, complete=False)
    if not matched or comparison.id is None:
        return _ConditionResult(matched)
    locations = _comparison_locations(left, comparison.operator, right.value)
    return _ConditionResult(
        True,
        captures=(
            _Capture(
                source=EvidenceProjectionSource.MATCHER,
                id=comparison.id,
                locations=locations,
            ),
        ),
    )


def _compare(left: object, operator: ComparisonOperator, right: object) -> tuple[bool, bool]:
    if operator is ComparisonOperator.EQUALS:
        return _strict_equal(left, right), True
    if operator is ComparisonOperator.NOT_EQUALS:
        return not _strict_equal(left, right), True
    if operator in {ComparisonOperator.IN, ComparisonOperator.NOT_IN}:
        contained, supported = _contains(right, left)
        return ((not contained) if operator is ComparisonOperator.NOT_IN else contained), supported
    contained, supported = _contains(left, right)
    return (
        (not contained) if operator is ComparisonOperator.NOT_CONTAINS else contained,
        supported,
    )


def _strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    return bool(left == right)


def _contains(container: object, item: object) -> tuple[bool, bool]:
    if type(container) is str and type(item) is str:
        return item in container, True
    if isinstance(container, (list, tuple)):
        return any(_strict_equal(candidate, item) for candidate in container), True
    return False, False


def _comparison_locations(
    left: _RuntimeValue,
    operator: ComparisonOperator,
    right: object,
) -> tuple[FindingLocation, ...]:
    if left.location is None:
        return ()
    if (
        operator is ComparisonOperator.CONTAINS
        and type(left.value) is str
        and type(right) is str
        and right
    ):
        locations: list[FindingLocation] = []
        start = 0
        base = left.location.start or 0
        while (index := left.value.find(right, start)) >= 0:
            locations.append(
                FindingLocation(
                    event_id=left.location.event_id,
                    path=left.location.path,
                    start=base + index,
                    end=base + index + len(right),
                )
            )
            start = index + len(right)
        return tuple(locations)
    return (left.location,)


def _evaluate_relation(
    source_name: str,
    target_name: str,
    operator: RelationOperator,
    *,
    rule_id: str,
    environment: dict[str, _RuntimeValue],
    events_by_id: dict[str, Event],
    ledger: MatchCostLedger,
) -> _ConditionResult:
    source = environment.get(source_name)
    target = environment.get(target_name)
    if (
        source is None
        or target is None
        or not isinstance(source.value, Event)
        or not isinstance(target.value, Event)
    ):
        return _ConditionResult(False, complete=False)
    source_event = source.value
    target_event = target.value
    if operator in {
        RelationOperator.PRECEDES,
        RelationOperator.IMMEDIATELY_PRECEDES,
    }:
        ledger.consume(rule_id, CostDimension.RELATION_NODES)
        if operator is RelationOperator.IMMEDIATELY_PRECEDES:
            return _ConditionResult(source_event.sequence + 1 == target_event.sequence)
        return _ConditionResult(source_event.sequence < target_event.sequence)
    if operator is RelationOperator.MAY_INFLUENCE:
        return _ConditionResult(
            _has_relation_path(
                source_event,
                target_event,
                allowed_kinds=frozenset(
                    {RelationKind.DERIVED_FROM, RelationKind.MAY_INFLUENCE}
                ),
                rule_id=rule_id,
                events_by_id=events_by_id,
                ledger=ledger,
            )
        )
    if operator is RelationOperator.DERIVED_FROM_DIRECT:
        relations = target_event.relations
        ledger.consume(rule_id, CostDimension.RELATION_NODES, max(1, len(relations)))
        return _ConditionResult(
            any(
                relation.source_event_id == source_event.id
                and relation.kind is RelationKind.DERIVED_FROM
                for relation in relations
            )
        )
    return _ConditionResult(
        _has_relation_path(
            source_event,
            target_event,
            allowed_kinds=frozenset({RelationKind.DERIVED_FROM}),
            rule_id=rule_id,
            events_by_id=events_by_id,
            ledger=ledger,
        )
    )


def _has_relation_path(
    source: Event,
    target: Event,
    *,
    allowed_kinds: frozenset[RelationKind],
    rule_id: str,
    events_by_id: dict[str, Event],
    ledger: MatchCostLedger,
) -> bool:
    pending = [
        relation.source_event_id
        for relation in reversed(target.relations)
        if relation.kind in allowed_kinds
    ]
    visited: set[str] = set()
    ledger.consume(rule_id, CostDimension.RELATION_NODES)
    while pending:
        event_id = pending.pop()
        ledger.consume(rule_id, CostDimension.RELATION_HOPS)
        if event_id == source.id:
            return True
        if event_id in visited:
            continue
        visited.add(event_id)
        ledger.consume(rule_id, CostDimension.RELATION_NODES)
        event = events_by_id[event_id]
        pending.extend(
            relation.source_event_id
            for relation in reversed(event.relations)
            if relation.kind in allowed_kinds
        )
    return False


async def _evaluate_quantifier(
    condition: MatchCondition,
    *,
    rule_id: str,
    trace_id: str,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    snapshot: _EventSnapshot,
    events_by_id: dict[str, Event],
    ledger: MatchCostLedger,
    capability_runtime: _CapabilityRuntime | None,
) -> _ConditionResult:
    quantifier = condition.quantify
    if quantifier is None:  # pragma: no cover - guarded by caller
        raise RuntimeError("missing quantifier")
    if isinstance(quantifier.binding, EventBinding):
        domain = _event_domain(quantifier.binding, snapshot, rule_id, ledger)
    else:
        domain = _local_collection_domain(
            quantifier.binding,
            environment,
            derived,
            parameters,
            rule_id,
            ledger,
        )

    matches = 0
    captures: tuple[_Capture, ...] = ()
    complete = True
    for value in domain:
        ledger.consume(rule_id, CostDimension.QUANTIFIER_ITERATIONS)
        nested_environment = dict(environment)
        nested_environment[quantifier.binding.name] = value
        result = await _evaluate_condition(
            quantifier.where,
            rule_id=rule_id,
            trace_id=trace_id,
            environment=nested_environment,
            derived=derived,
            parameters=parameters,
            snapshot=snapshot,
            events_by_id=events_by_id,
            ledger=ledger,
            capability_runtime=capability_runtime,
        )
        complete = complete and result.complete
        if result.matched:
            matches += 1
            captures = _merge_captures(captures, result.captures)
            if quantifier.operator is QuantifierOperator.EXISTS:
                return _ConditionResult(True, captures=result.captures)
        elif quantifier.operator is QuantifierOperator.FORALL and result.complete:
            return _ConditionResult(False)

    if quantifier.operator is QuantifierOperator.EXISTS:
        return _ConditionResult(False, complete=complete)
    if quantifier.operator is QuantifierOperator.FORALL:
        return _ConditionResult(complete, complete=complete, captures=captures)
    if not complete:
        return _ConditionResult(False, complete=False)
    bounds = quantifier.count
    if bounds is None:  # pragma: no cover - guaranteed by MatchPlan validation
        raise RuntimeError("count quantifier is missing bounds")
    matched = (bounds.minimum is None or matches >= bounds.minimum) and (
        bounds.maximum is None or matches <= bounds.maximum
    )
    return _ConditionResult(matched, captures=captures if matched else ())


def _local_collection_domain(
    binding: CollectionBinding,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    rule_id: str,
    ledger: MatchCostLedger,
) -> tuple[_RuntimeValue, ...]:
    source = _resolve_value(binding.source, environment, derived, parameters)
    if source.items is not None:
        candidates = source.items
    elif isinstance(source.value, (list, tuple)):
        candidates = tuple(
            _collection_item(source, binding.name, index, value)
            for index, value in enumerate(source.value)
        )
    else:
        return ()
    result: list[_RuntimeValue] = []
    for item in candidates:
        ledger.consume(rule_id, CostDimension.COLLECTION_ITEMS)
        if _item_matches(binding.item_type, item.value):
            result.append(item)
    return tuple(result)


def _resolve_value(
    reference: ValueReference,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
) -> _RuntimeValue:
    if isinstance(reference, LiteralValue):
        return _RuntimeValue(reference.value, cast(JsonValue, {"type": "literal"}))
    if isinstance(reference, LiteralListValue):
        return _RuntimeValue(reference.items, cast(JsonValue, {"type": "literal_list"}))
    if isinstance(reference, NullValue):
        return _RuntimeValue(None, cast(JsonValue, {"type": "null"}))
    if isinstance(reference, BindingValue):
        return environment[reference.name]
    if isinstance(reference, DerivedValue):
        return derived[reference.name]
    if isinstance(reference, ParameterValue):
        return parameters[reference.name]
    if isinstance(reference, FieldValue):
        return _resolve_field(reference, environment)
    raise RuntimeError("unsupported MatchPlan value reference")


def _resolve_field(
    reference: FieldValue,
    environment: dict[str, _RuntimeValue],
) -> _RuntimeValue:
    root = environment[reference.binding]
    value: object = root.value
    for segment in reference.path:
        if isinstance(value, Event) and isinstance(segment, str):
            value = _event_envelope(value).get(segment, _MISSING)
        elif isinstance(segment, str) and isinstance(value, Mapping):
            value = value.get(segment, _MISSING)
        elif isinstance(segment, int) and isinstance(value, (list, tuple)):
            value = value[segment] if segment < len(value) else _MISSING
        else:
            value = _MISSING
        if value is _MISSING:
            break
    location = None
    if root.event_id is not None:
        prefix = root.location.path if root.location is not None else ()
        location = FindingLocation(
            event_id=root.event_id,
            path=(*prefix, *reference.path),
        )
    return _RuntimeValue(
        value=value,
        coordinate=cast(
            JsonValue,
            {
                "type": "field",
                "binding": reference.binding,
                "parent": root.coordinate,
                "path": list(reference.path),
            },
        ),
        event_id=root.event_id,
        location=location,
    )


def _event_envelope(event: Event) -> dict[str, object]:
    return {
        "id": event.id,
        "sequence": event.sequence,
        "kind": event.kind.value,
        "origin": event.origin.value,
        "payload": event.payload,
    }


def _create_finding(
    *,
    rule: MatchRulePlan,
    environment: dict[str, _RuntimeValue],
    derived: dict[str, _RuntimeValue],
    parameters: dict[str, _RuntimeValue],
    captures: tuple[_Capture, ...],
    ledger: MatchCostLedger,
    policy_hash: str,
) -> Finding:
    values = {**parameters, **derived, **environment}
    bindings = tuple(
        _finding_binding(name, values[name]) for name in rule.finding.bindings
    )
    subjects = tuple(
        cast(Event, environment[name].value).id for name in rule.finding.subjects
    )
    referenced_event_ids = set(subjects)
    referenced_event_ids.update(
        binding.event_id for binding in bindings if binding.event_id is not None
    )
    capture_map = {(capture.source, capture.id): capture for capture in captures}
    evidence: list[FindingEvidence] = []
    locations: list[FindingLocation] = []
    for projection in rule.finding.evidence:
        capture = capture_map.get((projection.source, projection.id))
        if capture is None:
            continue
        projected_locations = tuple(
            location
            for location in capture.locations
            if location.event_id in referenced_event_ids
        )
        if capture.source is EvidenceProjectionSource.MATCHER and (
            projection.include_locations and projected_locations
        ):
            for location in projected_locations:
                ledger.consume(rule.id, CostDimension.EVIDENCE)
                locations.append(location)
                evidence.append(
                    FindingEvidence(
                        source=EvidenceSource.MATCHER,
                        type=projection.id,
                        location=location,
                        masked_evidence=projection.masked_evidence,
                    )
                )
        elif capture.source is EvidenceProjectionSource.MATCHER:
            ledger.consume(rule.id, CostDimension.EVIDENCE)
            evidence.append(
                FindingEvidence(
                    source=EvidenceSource.MATCHER,
                    type=projection.id,
                    masked_evidence=projection.masked_evidence,
                )
            )
        else:
            for fact in capture.facts:
                location = (
                    fact.location
                    if projection.include_locations
                    and fact.location is not None
                    and fact.location.event_id in referenced_event_ids
                    else None
                )
                ledger.consume(rule.id, CostDimension.EVIDENCE)
                if location is not None:
                    locations.append(location)
                evidence.append(
                    FindingEvidence(
                        source=EvidenceSource(capture.source.value),
                        type=fact.type,
                        capability=fact.capability,
                        location=location,
                        masked_evidence=(
                            projection.masked_evidence
                            if projection.masked_evidence is not None
                            else fact.masked_evidence
                        ),
                        fingerprint=fact.fingerprint,
                        confidence=fact.confidence,
                    )
                )
    return Finding.create(
        policy_hash=policy_hash,
        rule_id=rule.id,
        code=rule.finding.code,
        message=rule.finding.message,
        subject_event_ids=subjects,
        bindings=bindings,
        locations=tuple(_unique_locations(locations)),
        evidence=tuple(evidence),
    )


def _finding_binding(name: str, value: _RuntimeValue) -> FindingBinding:
    return FindingBinding(
        name=name,
        key=compute_binding_key(
            namespace=_BINDING_KEY_NAMESPACE,
            coordinate=value.coordinate,
        ),
        event_id=value.event_id,
        location=value.location,
    )


def _merge_captures(
    left: tuple[_Capture, ...],
    right: tuple[_Capture, ...],
) -> tuple[_Capture, ...]:
    merged = list(left)
    indexes = {(capture.source, capture.id): index for index, capture in enumerate(merged)}
    for capture in right:
        key = (capture.source, capture.id)
        if key not in indexes:
            indexes[key] = len(merged)
            merged.append(capture)
            continue
        index = indexes[key]
        existing = merged[index]
        merged[index] = _Capture(
            source=existing.source,
            id=existing.id,
            capability=existing.capability,
            locations=tuple(
                _unique_locations([*existing.locations, *capture.locations])
            ),
            facts=tuple(
                _unique_captured_evidence([*existing.facts, *capture.facts])
            ),
        )
    return tuple(merged)


def _unique_locations(locations: list[FindingLocation]) -> list[FindingLocation]:
    result: list[FindingLocation] = []
    seen: set[tuple[object, ...]] = set()
    for location in locations:
        key = (location.event_id, *location.path, location.start, location.end)
        if key not in seen:
            seen.add(key)
            result.append(location)
    return result


def _unique_captured_evidence(
    facts: list[_CapturedEvidence],
) -> list[_CapturedEvidence]:
    result: list[_CapturedEvidence] = []
    seen: set[tuple[object, ...]] = set()
    for fact in facts:
        location = fact.location
        key = (
            fact.type,
            fact.capability,
            location.event_id if location is not None else None,
            location.path if location is not None else None,
            location.start if location is not None else None,
            location.end if location is not None else None,
            fact.masked_evidence,
            fact.fingerprint,
            fact.confidence,
        )
        if key not in seen:
            seen.add(key)
            result.append(fact)
    return result


def _unique_findings(findings: list[Finding]) -> list[Finding]:
    result: list[Finding] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.id not in seen:
            seen.add(finding.id)
            result.append(finding)
    return result


def _first_unavailable_capability(
    condition: MatchCondition,
) -> tuple[EvidenceProjectionSource, str] | None:
    if condition.predicate is not None:
        return EvidenceProjectionSource.PREDICATE, condition.predicate.capability
    if condition.detector is not None:
        return EvidenceProjectionSource.DETECTOR, condition.detector.capability
    if condition.similarity is not None:
        return EvidenceProjectionSource.DETECTOR, condition.similarity.capability
    if condition.all is not None:
        children = condition.all
    elif condition.any is not None:
        children = condition.any
    elif condition.not_ is not None:
        children = (condition.not_,)
    elif condition.quantify is not None:
        children = (condition.quantify.where,)
    else:
        children = ()
    for child in children:
        capability = _first_unavailable_capability(child)
        if capability is not None:
            return capability
    return None
