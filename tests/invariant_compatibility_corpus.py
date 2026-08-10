"""Strict, provider-neutral fixtures for the future Invariant-aligned matcher.

This module is test-only. Its trusted oracles make the compatibility contract
executable without pretending that MatchPlan, Finding, Policy, or Monitor are
already production features.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from typing import Annotated, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator
from yaml.constructor import ConstructorError
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agent_guardrail.models import (
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    Message,
    MessageRole,
    PendingTrace,
    Phase,
    RelationKind,
    ToolCall,
    ToolResult,
    Trace,
)

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "invariant_compatibility"
FIXTURE_TIME = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


class CompatibilityFixtureLoadError(ValueError):
    """A safe fixture-loading failure."""


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _StrictSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class FixtureModel(BaseModel):
    """Closed and immutable base for compatibility fixtures and oracle output."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class CurrentSupport(StrEnum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class AnalysisMode(StrEnum):
    SNAPSHOT = "snapshot"
    PENDING = "pending"
    INCREMENTAL = "incremental"
    COMPILE = "compile"


class OracleError(StrEnum):
    COMPILE_ERROR = "compile_error"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    DETECTOR_TIMEOUT = "detector_timeout"
    PARAMETER_ERROR = "parameter_error"
    INPUT_ERROR = "input_error"


class RelationOperator(StrEnum):
    PRECEDES = "precedes"
    IMMEDIATELY_PRECEDES = "immediately_precedes"
    DERIVED_FROM_DIRECT = "derived_from_direct"
    DERIVED_FROM_ANCESTOR = "derived_from_ancestor"


class CapabilityKind(StrEnum):
    PREDICATE = "predicate"
    DETECTOR = "detector"


class CapabilityBehavior(StrEnum):
    MATCH = "match"
    TIMEOUT = "timeout"


class RelationFixture(FixtureModel):
    source_event_id: str = Field(min_length=1)
    kind: RelationKind = RelationKind.DERIVED_FROM


class EventFixture(FixtureModel):
    id: str = Field(min_length=1)
    kind: EventKind
    phase: Phase
    origin: EventOrigin = EventOrigin.CLIENT_ASSERTED
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    relations: tuple[RelationFixture, ...] = ()


class TypedMessageOracle(FixtureModel):
    type: Literal["typed_message"] = "typed_message"
    role: MessageRole
    contains: str = Field(min_length=1)


class MultiEventOracle(FixtureModel):
    type: Literal["multi_event"] = "multi_event"
    tool_name: str = Field(min_length=1)
    combination_limit: int = Field(ge=1)


class NestedMailOracle(FixtureModel):
    type: Literal["nested_mail"] = "nested_mail"
    tool_name: str = Field(min_length=1)
    recipient_field: str = Field(min_length=1)
    allowlist: tuple[str, ...] = ()
    max_items: int = Field(ge=1)


class DerivedLinesOracle(FixtureModel):
    type: Literal["derived_lines"] = "derived_lines"
    contains: str = Field(min_length=1)
    max_items: int = Field(ge=1)
    max_bytes: int = Field(ge=1)


class PredicateOracle(FixtureModel):
    type: Literal["predicate"] = "predicate"
    role: MessageRole
    contains: str = Field(min_length=1)
    recursive: bool = False


class QuantifiedResultsOracle(FixtureModel):
    type: Literal["quantified_results"] = "quantified_results"
    tool_name: str = Field(min_length=1)
    contains: str = Field(min_length=1)
    minimum: int = Field(ge=0)
    max_candidates: int = Field(ge=1)


class RelationQueryOracle(FixtureModel):
    type: Literal["relation_query"] = "relation_query"
    operator: RelationOperator
    source_kind: EventKind
    target_kind: EventKind
    source_tool: str | None = None
    target_tool: str | None = None
    max_pairs: int = Field(default=128, ge=1)


class CapabilityOracle(FixtureModel):
    type: Literal["capability"] = "capability"
    capability: str = Field(min_length=1)
    capability_kind: CapabilityKind
    registered: bool
    behavior: CapabilityBehavior = CapabilityBehavior.MATCH
    contains: str = Field(min_length=1)
    max_input_bytes: int = Field(ge=1)
    requested_import: str | None = None


class RangeOracle(FixtureModel):
    type: Literal["ranges"] = "ranges"
    contains: str = Field(min_length=1)
    masked_evidence: str = Field(min_length=1)


class ParameterOracle(FixtureModel):
    type: Literal["parameter"] = "parameter"
    name: str = Field(min_length=1)
    authorized_values: tuple[str, ...]


OracleFixture = Annotated[
    TypedMessageOracle
    | MultiEventOracle
    | NestedMailOracle
    | DerivedLinesOracle
    | PredicateOracle
    | QuantifiedResultsOracle
    | RelationQueryOracle
    | CapabilityOracle
    | RangeOracle
    | ParameterOracle,
    Field(discriminator="type"),
]


class MatchExpectation(FixtureModel):
    subjects: tuple[str, ...] = Field(min_length=1)
    bindings: dict[str, str] = Field(default_factory=dict)
    ranges: tuple[str, ...] = ()
    evidence_types: tuple[str, ...] = ()
    masked_evidence: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_match(self) -> MatchExpectation:
        if len(self.subjects) != len(set(self.subjects)):
            raise ValueError("match subjects must be unique")
        return self


class RunExpectation(FixtureModel):
    matches: tuple[MatchExpectation, ...] = ()
    error: OracleError | None = None
    same_identities_as: int | None = Field(default=None, ge=0)
    relations_unchanged: bool = False
    forbidden_strings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_outcome(self) -> RunExpectation:
        if self.error is not None and self.matches:
            raise ValueError("an error expectation cannot also contain matches")
        if self.error is not None and self.same_identities_as is not None:
            raise ValueError("an error expectation cannot compare identities")
        return self


class CorpusRun(FixtureModel):
    id: str = Field(min_length=1)
    snapshot: tuple[EventFixture, ...] = ()
    past: tuple[EventFixture, ...] = ()
    pending: tuple[EventFixture, ...] = ()
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    expected: RunExpectation


class CorpusCase(FixtureModel):
    id: str = Field(min_length=1)
    mode: AnalysisMode
    oracle: OracleFixture
    runs: tuple[CorpusRun, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_runs(self) -> CorpusCase:
        run_ids = [run.id for run in self.runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("run IDs must be unique within a corpus case")
        for index, run in enumerate(self.runs):
            if run.expected.same_identities_as is not None:
                if run.expected.same_identities_as >= index:
                    raise ValueError("identity comparison must reference an earlier run")
            if self.mode in {AnalysisMode.SNAPSHOT, AnalysisMode.INCREMENTAL}:
                if not run.snapshot or run.past or run.pending:
                    raise ValueError("snapshot/incremental runs require only snapshot events")
            elif self.mode is AnalysisMode.PENDING:
                if run.snapshot or not run.pending:
                    raise ValueError("pending runs require pending events and no snapshot")
            elif self.mode is AnalysisMode.COMPILE:
                if run.snapshot or run.past or run.pending:
                    raise ValueError("compile runs cannot contain events")
        return self


class CorpusFixture(FixtureModel):
    id: str = Field(pattern=r"^i(?:0[1-9]|1[0-4])-[a-z0-9-]+$")
    capability: str = Field(min_length=1)
    current_support: CurrentSupport
    invariant_reference: tuple[str, ...] = Field(min_length=1)
    cases: tuple[CorpusCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_case_ids(self) -> CorpusFixture:
        case_ids = [case.id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case IDs must be unique within a corpus fixture")
        return self


class OracleRunResult(FixtureModel):
    matches: tuple[MatchExpectation, ...] = ()
    identities: tuple[str, ...] = ()
    error: OracleError | None = None
    relations_unchanged: bool = True


@dataclass(frozen=True, slots=True)
class _PreparedRun:
    events: tuple[Event, ...]
    pending_ids: frozenset[str]
    parameters: dict[str, JsonValue]


class _OracleFailure(Exception):
    def __init__(self, error: OracleError):
        self.error = error
        super().__init__(error.value)


def _reject_yaml_indirection(source: str) -> None:
    for token in yaml.scan(source):
        if isinstance(token, (AliasToken, AnchorToken, TagToken)):
            raise CompatibilityFixtureLoadError(
                "compatibility fixture cannot use aliases, anchors, or explicit tags"
            )


def load_compatibility_fixture(path: Path) -> CorpusFixture:
    """Load one compatibility fixture through strict YAML and Pydantic."""

    source = path.read_text(encoding="utf-8")
    _reject_yaml_indirection(source)
    document = yaml.load(source, Loader=_StrictSafeLoader)
    return CorpusFixture.model_validate(document)


def load_all_compatibility_fixtures() -> tuple[CorpusFixture, ...]:
    """Load I01-I14 in filename order and verify filename identity."""

    fixtures: list[CorpusFixture] = []
    for path in sorted(FIXTURE_DIRECTORY.glob("i*.yaml")):
        fixture = load_compatibility_fixture(path)
        if fixture.id != path.stem:
            raise ValueError(f"fixture ID must match filename: {path.name}")
        fixtures.append(fixture)
    if not fixtures:
        raise ValueError("Invariant compatibility corpus has no fixtures")
    return tuple(fixtures)


def execute_case(case: CorpusCase) -> tuple[OracleRunResult, ...]:
    """Execute one fixture case against deterministic test-only oracles."""

    results: list[OracleRunResult] = []
    seen_identities: set[str] = set()
    for run in case.runs:
        try:
            prepared = _prepare_run(case, run)
            relations_before = _relation_signature(prepared.events)
            matches = _evaluate_oracle(case.oracle, prepared.events, prepared.parameters)
            if case.mode is AnalysisMode.PENDING:
                matches = tuple(
                    match
                    for match in matches
                    if prepared.pending_ids.intersection(match.subjects)
                )
            identities = tuple(_stable_identity(case.id, match) for match in matches)
            if case.mode is AnalysisMode.INCREMENTAL:
                new_pairs = tuple(
                    (match, identity)
                    for match, identity in zip(matches, identities, strict=True)
                    if identity not in seen_identities
                )
                seen_identities.update(identities)
                matches = tuple(match for match, _ in new_pairs)
                identities = tuple(identity for _, identity in new_pairs)
            results.append(
                OracleRunResult(
                    matches=matches,
                    identities=identities,
                    relations_unchanged=(
                        relations_before == _relation_signature(prepared.events)
                    ),
                )
            )
        except _OracleFailure as exc:
            results.append(OracleRunResult(error=exc.error))
        except (TypeError, ValueError):
            results.append(OracleRunResult(error=OracleError.INPUT_ERROR))
    return tuple(results)


def _prepare_run(case: CorpusCase, run: CorpusRun) -> _PreparedRun:
    trace_id = f"invariant-compatibility-{case.id}"
    if case.mode is AnalysisMode.COMPILE:
        return _PreparedRun(events=(), pending_ids=frozenset(), parameters=dict(run.parameters))
    if run.snapshot:
        events = tuple(
            _event_from_fixture(event, trace_id=trace_id, sequence=index)
            for index, event in enumerate(run.snapshot)
        )
        Trace(id=trace_id, events=events)
        return _PreparedRun(
            events=events,
            pending_ids=frozenset(),
            parameters=dict(run.parameters),
        )

    past = tuple(
        _event_from_fixture(event, trace_id=trace_id, sequence=index)
        for index, event in enumerate(run.past)
    )
    trace = Trace(id=trace_id, events=past)
    pending = tuple(
        _event_from_fixture(
            event,
            trace_id=trace_id,
            sequence=trace.next_sequence + offset,
        )
        for offset, event in enumerate(run.pending)
    )
    pending_trace = PendingTrace(
        trace=trace,
        events=pending,
        primary_event_id=pending[-1].id,
        attributes=dict(run.parameters),
    )
    return _PreparedRun(
        events=(*pending_trace.trace.events, *pending_trace.events),
        pending_ids=frozenset(pending_trace.event_ids),
        parameters=dict(run.parameters),
    )


def _event_from_fixture(event: EventFixture, *, trace_id: str, sequence: int) -> Event:
    return Event(
        id=event.id,
        trace_id=trace_id,
        sequence=sequence,
        kind=event.kind,
        phase=event.phase,
        timestamp=FIXTURE_TIME,
        origin=event.origin,
        payload=dict(event.payload),
        metadata=dict(event.metadata),
        relations=tuple(
            EventRelation(source_event_id=relation.source_event_id, kind=relation.kind)
            for relation in event.relations
        ),
    )


def _evaluate_oracle(
    oracle: OracleFixture,
    events: tuple[Event, ...],
    parameters: dict[str, JsonValue],
) -> tuple[MatchExpectation, ...]:
    if isinstance(oracle, TypedMessageOracle):
        return _typed_message_matches(oracle, events)
    if isinstance(oracle, MultiEventOracle):
        return _multi_event_matches(oracle, events)
    if isinstance(oracle, NestedMailOracle):
        return _nested_mail_matches(oracle, events)
    if isinstance(oracle, DerivedLinesOracle):
        return _derived_line_matches(oracle, events)
    if isinstance(oracle, PredicateOracle):
        return _predicate_matches(oracle, events)
    if isinstance(oracle, QuantifiedResultsOracle):
        return _quantified_result_matches(oracle, events)
    if isinstance(oracle, RelationQueryOracle):
        return _relation_matches(oracle, events)
    if isinstance(oracle, CapabilityOracle):
        return _capability_matches(oracle, events)
    if isinstance(oracle, RangeOracle):
        return _range_matches(oracle, events)
    if isinstance(oracle, ParameterOracle):
        return _parameter_matches(oracle, events, parameters)
    raise AssertionError("unreachable compatibility oracle")


def _typed_message_matches(
    oracle: TypedMessageOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    matches: list[MatchExpectation] = []
    for event in events:
        if event.kind is not EventKind.MESSAGE:
            continue
        message = Message.model_validate(event.payload)
        if message.role is oracle.role and oracle.contains in message.content.text:
            matches.append(
                MatchExpectation(subjects=(event.id,), bindings={"message": event.id})
            )
    return tuple(matches)


def _multi_event_matches(
    oracle: MultiEventOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    users = [
        event
        for event in events
        if event.kind is EventKind.MESSAGE
        and Message.model_validate(event.payload).role is MessageRole.USER
    ]
    calls = [
        event
        for event in events
        if event.kind is EventKind.TOOL_CALL
        and ToolCall.model_validate(event.payload).name == oracle.tool_name
    ]
    matches: list[MatchExpectation] = []
    explored = 0
    for first, second in combinations(users, 2):
        for call in calls:
            explored += 1
            if explored > oracle.combination_limit:
                raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
            if first.sequence < second.sequence < call.sequence:
                matches.append(
                    MatchExpectation(
                        subjects=(call.id,),
                        bindings={"m1": first.id, "m2": second.id, "call": call.id},
                    )
                )
    return tuple(matches)


def _nested_mail_matches(
    oracle: NestedMailOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    matches: list[MatchExpectation] = []
    for event in events:
        if event.kind is not EventKind.TOOL_CALL:
            continue
        call = ToolCall.model_validate(event.payload)
        if call.name != oracle.tool_name:
            continue
        emails = call.arguments.get("emails")
        if not isinstance(emails, list):
            continue
        if len(emails) > oracle.max_items:
            raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
        for index, mail in enumerate(emails):
            if not isinstance(mail, dict):
                continue
            recipient = mail.get(oracle.recipient_field)
            if isinstance(recipient, str) and recipient not in oracle.allowlist:
                matches.append(
                    MatchExpectation(
                        subjects=(event.id,),
                        bindings={
                            "call": event.id,
                            "outgoing_mail": (
                                f"{event.id}#payload.arguments.emails[{index}]"
                            ),
                        },
                    )
                )
    return tuple(matches)


def _derived_line_matches(
    oracle: DerivedLinesOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    matches: list[MatchExpectation] = []
    for event in events:
        if event.kind is not EventKind.MESSAGE:
            continue
        text = Message.model_validate(event.payload).content.text
        if len(text.encode("utf-8")) > oracle.max_bytes:
            raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
        lines = text.splitlines()
        if len(lines) > oracle.max_items:
            raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
        for index, line in enumerate(lines):
            if oracle.contains in line:
                matches.append(
                    MatchExpectation(
                        subjects=(event.id,),
                        bindings={
                            "message": event.id,
                            "line": f"{event.id}#payload.content.text:line[{index}]",
                        },
                    )
                )
    return tuple(matches)


def _predicate_matches(
    oracle: PredicateOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    if oracle.recursive:
        raise _OracleFailure(OracleError.COMPILE_ERROR)
    return _typed_message_matches(
        TypedMessageOracle(role=oracle.role, contains=oracle.contains),
        events,
    )


def _quantified_result_matches(
    oracle: QuantifiedResultsOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    calls = [
        event
        for event in events
        if event.kind is EventKind.TOOL_CALL
        and ToolCall.model_validate(event.payload).name == oracle.tool_name
    ]
    results = [event for event in events if event.kind is EventKind.TOOL_RESULT]
    if len(results) > oracle.max_candidates:
        raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
    matches: list[MatchExpectation] = []
    for call in calls:
        count = 0
        for result in results:
            if call.id not in result.source_event_ids:
                continue
            output = ToolResult.model_validate(result.payload).output
            output_text = output if isinstance(output, str) else json.dumps(output, sort_keys=True)
            if oracle.contains in output_text:
                count += 1
        if count >= oracle.minimum:
            matches.append(
                MatchExpectation(subjects=(call.id,), bindings={"call": call.id})
            )
    return tuple(matches)


def _relation_matches(
    oracle: RelationQueryOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    sources = [
        event
        for event in events
        if event.kind is oracle.source_kind and _tool_matches(event, oracle.source_tool)
    ]
    targets = [
        event
        for event in events
        if event.kind is oracle.target_kind and _tool_matches(event, oracle.target_tool)
    ]
    explored = 0
    matches: list[MatchExpectation] = []
    for source in sources:
        for target in targets:
            if source.id == target.id:
                continue
            explored += 1
            if explored > oracle.max_pairs:
                raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
            if _relation_holds(oracle.operator, source, target, events):
                matches.append(
                    MatchExpectation(
                        subjects=(target.id,),
                        bindings={"source": source.id, "target": target.id},
                    )
                )
    return tuple(matches)


def _tool_matches(event: Event, expected: str | None) -> bool:
    if expected is None:
        return True
    if event.kind is EventKind.TOOL_CALL:
        return ToolCall.model_validate(event.payload).name == expected
    if event.kind is EventKind.TOOL_RESULT:
        return ToolResult.model_validate(event.payload).name == expected
    return False


def _relation_holds(
    operator: RelationOperator,
    source: Event,
    target: Event,
    events: tuple[Event, ...],
) -> bool:
    if operator is RelationOperator.PRECEDES:
        return source.sequence < target.sequence
    if operator is RelationOperator.IMMEDIATELY_PRECEDES:
        return target.sequence == source.sequence + 1
    if operator is RelationOperator.DERIVED_FROM_DIRECT:
        return source.id in target.source_event_ids
    if operator is RelationOperator.DERIVED_FROM_ANCESTOR:
        return source.id in _ancestor_ids(target, events)
    raise AssertionError("unreachable relation operator")


def _ancestor_ids(target: Event, events: tuple[Event, ...]) -> frozenset[str]:
    by_id = {event.id: event for event in events}
    pending = list(target.source_event_ids)
    ancestors: set[str] = set()
    while pending:
        event_id = pending.pop()
        if event_id in ancestors:
            continue
        ancestor = by_id.get(event_id)
        if ancestor is None:
            continue
        ancestors.add(event_id)
        pending.extend(ancestor.source_event_ids)
    return frozenset(ancestors)


def _capability_matches(
    oracle: CapabilityOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    if oracle.requested_import is not None or not oracle.registered:
        raise _OracleFailure(OracleError.COMPILE_ERROR)
    texts = [
        (event, Message.model_validate(event.payload).content.text)
        for event in events
        if event.kind is EventKind.MESSAGE
    ]
    if sum(len(text.encode("utf-8")) for _, text in texts) > oracle.max_input_bytes:
        raise _OracleFailure(OracleError.RESOURCE_EXHAUSTED)
    if oracle.behavior is CapabilityBehavior.TIMEOUT:
        raise _OracleFailure(OracleError.DETECTOR_TIMEOUT)
    matches: list[MatchExpectation] = []
    for event, text in texts:
        if oracle.contains not in text:
            continue
        evidence_types = (
            (oracle.capability,)
            if oracle.capability_kind is CapabilityKind.DETECTOR
            else ()
        )
        masked_evidence = ("[MATCH]",) if evidence_types else ()
        matches.append(
            MatchExpectation(
                subjects=(event.id,),
                bindings={"event": event.id},
                evidence_types=evidence_types,
                masked_evidence=masked_evidence,
            )
        )
    return tuple(matches)


def _range_matches(
    oracle: RangeOracle,
    events: tuple[Event, ...],
) -> tuple[MatchExpectation, ...]:
    matches: list[MatchExpectation] = []
    for event in events:
        fields = _text_fields(event)
        ranges: list[str] = []
        for path, text in fields:
            start = 0
            while (index := text.find(oracle.contains, start)) >= 0:
                ranges.append(f"{event.id}.{path}:{index}-{index + len(oracle.contains)}")
                start = index + len(oracle.contains)
        if ranges:
            matches.append(
                MatchExpectation(
                    subjects=(event.id,),
                    bindings={"event": event.id},
                    ranges=tuple(ranges),
                    evidence_types=tuple("range_match" for _ in ranges),
                    masked_evidence=tuple(oracle.masked_evidence for _ in ranges),
                )
            )
    return tuple(matches)


def _text_fields(event: Event) -> tuple[tuple[str, str], ...]:
    if event.kind is EventKind.MESSAGE:
        text = Message.model_validate(event.payload).content.text
        return (("payload.content.text", text),)
    if event.kind is EventKind.TOOL_CALL:
        call = ToolCall.model_validate(event.payload)
        fields: list[tuple[str, str]] = []
        _collect_text_fields(call.arguments, "payload.arguments", fields)
        return tuple(fields)
    return ()


def _collect_text_fields(
    value: object,
    path: str,
    fields: list[tuple[str, str]],
) -> None:
    if isinstance(value, str):
        fields.append((path, value))
    elif isinstance(value, dict):
        for key in sorted(value):
            _collect_text_fields(value[key], f"{path}.{key}", fields)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_text_fields(item, f"{path}[{index}]", fields)


def _parameter_matches(
    oracle: ParameterOracle,
    events: tuple[Event, ...],
    parameters: dict[str, JsonValue],
) -> tuple[MatchExpectation, ...]:
    value = parameters.get(oracle.name)
    if not isinstance(value, str):
        raise _OracleFailure(OracleError.PARAMETER_ERROR)
    if value in oracle.authorized_values:
        return ()
    return tuple(
        MatchExpectation(
            subjects=(event.id,),
            bindings={"event": event.id, "principal": f"$parameters.{oracle.name}"},
        )
        for event in events
        if event.kind is EventKind.TOOL_CALL
    )


def _stable_identity(case_id: str, match: MatchExpectation) -> str:
    canonical = json.dumps(
        {
            "case_id": case_id,
            "subjects": match.subjects,
            "bindings": sorted(match.bindings.items()),
            "ranges": match.ranges,
            "evidence_types": match.evidence_types,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _relation_signature(
    events: tuple[Event, ...],
) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    return tuple(
        (
            event.id,
            tuple(
                (relation.source_event_id, cast(str, relation.kind.value))
                for relation in event.relations
            ),
        )
        for event in events
    )
