from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_guardrail.config import (
    PolicyLoadError,
    load_match_plan_file,
    load_match_plan_yaml,
)
from agent_guardrail.core.authoring import (
    AuthorComparison,
    AuthorCondition,
    AuthorEventSpec,
    AuthorFinding,
    AuthorPolicy,
    AuthorRule,
    AuthorValue,
    compile_author_policy,
)
from agent_guardrail.core.match_plan import (
    BindingDomain,
    ComparisonOperator,
    DetectorCondition,
    EventBinding,
    FieldValue,
    ParameterValue,
    PredicateCondition,
    QuantifierOperator,
    RelationOperator,
)
from agent_guardrail.core.matcher import SnapshotMatcher
from agent_guardrail.models import (
    AnalysisErrorCode,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    MessageRole,
    PendingTrace,
    Phase,
    Trace,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "match_policy"


def event(
    event_id: str,
    sequence: int,
    kind: EventKind,
    payload: dict[str, object],
    *,
    phase: Phase,
    origin: EventOrigin = EventOrigin.CLIENT_ASSERTED,
    relations: tuple[EventRelation, ...] = (),
) -> Event:
    return Event.model_validate(
        {
            "id": event_id,
            "trace_id": "trace-1",
            "sequence": sequence,
            "kind": kind,
            "phase": phase,
            "timestamp": datetime(2026, 8, 10, tzinfo=UTC),
            "origin": origin,
            "payload": payload,
            "relations": relations,
        }
    )


def message(event_id: str, sequence: int, text: str, *, role: MessageRole) -> Event:
    return event(
        event_id,
        sequence,
        EventKind.MESSAGE,
        {"role": role.value, "content": {"type": "text", "text": text}},
        phase=Phase.POST_LLM if role is MessageRole.ASSISTANT else Phase.PRE_LLM,
    )


def call(
    event_id: str,
    sequence: int,
    name: str,
    *,
    relations: tuple[EventRelation, ...] = (),
) -> Event:
    return event(
        event_id,
        sequence,
        EventKind.TOOL_CALL,
        {"call_id": f"call-{event_id}", "name": name, "arguments": {}},
        phase=Phase.PRE_TOOL,
        relations=relations,
    )


@pytest.mark.asyncio
async def test_readable_yaml_compiles_predicates_and_runs_snapshot_matcher() -> None:
    plan = load_match_plan_file(FIXTURES / "assistant-blocked.yaml")

    serialized = plan.model_dump_json(by_alias=True)
    assert "blocked_assistant" not in serialized
    assert '"use"' not in serialized
    assert "text_match" in serialized

    matcher = SnapshotMatcher(plan, policy_version=1, policy_hash="author-policy")
    report = await matcher.analyze(
        Trace(
            id="trace-1",
            events=(
                message("m1", 0, "blocked request", role=MessageRole.USER),
                message("m2", 1, "blocked answer", role=MessageRole.ASSISTANT),
                message("m3", 2, "safe answer", role=MessageRole.ASSISTANT),
            ),
        )
    )

    assert report.errors == ()
    assert tuple(finding.subject_event_ids for finding in report.findings) == (("m2",),)
    assert report.findings[0].evidence[0].masked_evidence == "******"


def test_typed_python_author_objects_compile_to_same_plan_as_yaml() -> None:
    python_policy = AuthorPolicy(
        version=1,
        rules=(
            AuthorRule(
                id="assistant_blocked",
                events={
                    "message": AuthorEventSpec(
                        kind=EventKind.MESSAGE,
                        phases=(Phase.POST_LLM,),
                    )
                },
                where=AuthorCondition(
                    compare=AuthorComparison(
                        left=AuthorValue(
                            field=("message", "payload", "content", "text")
                        ),
                        operator=ComparisonOperator.CONTAINS,
                        right=AuthorValue(literal="blocked"),
                    )
                ),
                finding=AuthorFinding(
                    code="blocked_content",
                    message="Assistant emitted blocked content",
                    subjects=("message",),
                ),
            ),
        ),
    )
    yaml_policy = load_match_plan_yaml(
        """
version: 1
rules:
  - id: assistant_blocked
    events:
      message: {kind: message, phases: [post_llm]}
    where:
      compare:
        left: {field: [message, payload, content, text]}
        operator: contains
        right: {literal: blocked}
    finding:
      code: blocked_content
      message: Assistant emitted blocked content
      subjects: [message]
"""
    )

    assert compile_author_policy(python_policy) == yaml_policy


def test_author_compiler_maps_multi_event_tool_and_relation_sugar() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
rules:
  - id: website_to_email
    events:
      output: {kind: tool_result, domain: past}
      call: {kind: tool_call, domain: pending}
    where:
      all:
        - relation:
            source: output
            target: call
            operator: derived_from_ancestor
        - tool: {binding: output, name: get_website}
        - tool: {binding: call, name: send_email}
    finding:
      code: unsafe_flow
      message: Do not send website-derived content by email
      subjects: [call]
"""
    )

    rule = plan.rules[0]
    assert rule.event_bindings == (
        EventBinding(
            name="output",
            kind=EventKind.TOOL_RESULT,
            domain=BindingDomain.PAST,
        ),
        EventBinding(
            name="call",
            kind=EventKind.TOOL_CALL,
            domain=BindingDomain.PENDING,
        ),
    )
    assert rule.finding.bindings == ("output", "call")
    assert rule.where.all is not None
    assert rule.where.all[0].relation is not None
    assert rule.where.all[0].relation.operator is RelationOperator.DERIVED_FROM_ANCESTOR
    assert rule.where.all[1].compare is not None
    assert isinstance(rule.where.all[1].compare.left, FieldValue)


@pytest.mark.asyncio
async def test_author_compiler_maps_derive_collection_and_quantifier() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
rules:
  - id: repeated_flagged_lines
    events:
      message: {kind: message}
    derive:
      lines:
        operation: split_lines
        source: {field: [message, payload, content, text]}
    collections:
      line: {from: {derived: lines}, item_type: string}
    where:
      quantify:
        operator: count
        event:
          name: later
          kind: message
        where:
          all:
            - relation:
                source: message
                target: later
                operator: precedes
            - compare:
                left: {binding: line}
                operator: contains
                right: {literal: flagged}
        minimum: 1
    finding:
      code: flagged_lines
      message: A flagged line has a later message
      subjects: [message]
"""
    )
    quantifier = plan.rules[0].where.quantify
    assert quantifier is not None
    assert quantifier.operator is QuantifierOperator.COUNT
    assert quantifier.count is not None and quantifier.count.minimum == 1
    assert plan.rules[0].finding.bindings == ("message", "line")

    matcher = SnapshotMatcher(plan, policy_version=1, policy_hash="author-policy")
    report = await matcher.analyze(
        Trace(
            id="trace-1",
            events=(
                message("m1", 0, "safe\nflagged", role=MessageRole.ASSISTANT),
                message("m2", 1, "later", role=MessageRole.ASSISTANT),
            ),
        )
    )
    assert len(report.findings) == 1


@pytest.mark.asyncio
async def test_author_compiler_preserves_pending_domains_and_subject_filter() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
scopes: [pending]
rules:
  - id: pending_email_after_history
    events:
      source: {kind: tool_call, domain: past}
      destination: {kind: tool_call, domain: pending}
    where:
      all:
        - tool: {binding: source, name: get_website}
        - tool: {binding: destination, name: send_email}
        - relation:
            source: source
            target: destination
            operator: derived_from_direct
    finding:
      code: pending_flow
      message: Pending email uses website data
      subjects: [destination]
"""
    )
    matcher = SnapshotMatcher(plan, policy_version=1, policy_hash="author-policy")
    source = call("c1", 0, "get_website")
    destination = call(
        "c2",
        1,
        "send_email",
        relations=(EventRelation(source_event_id="c1"),),
    )
    report = await matcher.analyze_pending(
        PendingTrace(
            trace=Trace(id="trace-1", events=(source,)),
            events=(destination,),
            primary_event_id="c2",
        )
    )

    assert report.errors == ()
    assert tuple(finding.subject_event_ids for finding in report.findings) == (("c2",),)


def test_parameters_compile_as_trusted_typed_values() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
parameters:
  principal: {type: string}
rules:
  - id: principal_check
    events:
      call: {kind: tool_call}
    where:
      compare:
        left: {parameter: principal}
        operator: not_equals
        right: {literal: admin}
    finding:
      code: unauthorized
      message: Principal is not authorized
      subjects: [call]
      bindings: [principal]
"""
    )

    comparison = plan.rules[0].where.compare
    assert comparison is not None
    assert comparison.left == ParameterValue(name="principal")
    assert plan.rules[0].finding.bindings == ("call", "principal")


def test_author_boolean_presence_literals_and_local_collection_compile() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
rules:
  - id: structured_conditions
    events:
      call: {kind: tool_call}
    where:
      all:
        - present: [call, payload, arguments, labels]
        - any:
            - not:
                compare:
                  left: {field: [call, payload, name]}
                  operator: in
                  right: {literal: [send_email, post_message]}
            - compare:
                left: {field: [call, payload, arguments, owner]}
                operator: equals
                right: {literal: null}
        - quantify:
            operator: exists
            collection:
              name: label
              from: {field: [call, payload, arguments, labels]}
              item_type: string
            where:
              compare:
                left: {binding: label}
                operator: equals
                right: {literal: restricted}
    finding:
      code: structured_match
      message: Structured condition matched
      subjects: [call]
"""
    )

    root = plan.rules[0].where
    assert root.all is not None
    assert root.all[0].present is not None
    assert root.all[1].any is not None
    assert root.all[1].any[0].not_ is not None
    quantifier = root.all[2].quantify
    assert quantifier is not None
    assert quantifier.operator is QuantifierOperator.EXISTS
    assert quantifier.binding.name == "label"


@pytest.mark.asyncio
async def test_capabilities_compile_but_matcher_reports_unavailable_execution() -> None:
    plan = load_match_plan_yaml(
        """
version: 1
rules:
  - id: detector_policy
    events:
      message: {kind: message}
    where:
      all:
        - predicate:
            id: allowed
            capability: rbac
            arguments: [{binding: message}]
        - detector:
            id: injection
            capability: prompt_injection
            inputs:
              - value: {field: [message, payload, content, text]}
                encoding: text
            types_any: [prompt_injection]
    finding:
      code: unsafe_message
      message: A trusted capability matched
      subjects: [message]
      evidence:
        - {source: predicate, id: allowed}
        - {source: detector, id: injection}
"""
    )
    conditions = plan.rules[0].where.all
    assert conditions is not None
    assert isinstance(conditions[0].predicate, PredicateCondition)
    assert isinstance(conditions[1].detector, DetectorCondition)

    matcher = SnapshotMatcher(plan, policy_version=1, policy_hash="author-policy")
    report = await matcher.analyze(
        Trace(
            id="trace-1",
            events=(message("m1", 0, "unsafe", role=MessageRole.USER),),
        )
    )
    assert report.findings == ()
    assert report.errors[0].code is AnalysisErrorCode.CAPABILITY_ERROR
    assert report.errors[0].capability == "rbac"


@pytest.mark.parametrize(
    "source",
    [
        """
version: 1
predicates:
  first:
    where: {use: {name: second}}
  second:
    where: {use: {name: first}}
rules:
  - id: test
    events: {message: {kind: message}}
    where: {compare: {left: {binding: message}, operator: equals, right: {binding: message}}}
    finding: {code: test, message: Safe message, subjects: [message]}
""",
        """
version: 1
predicates:
  wrapper:
    where: {use: {name: missing}}
rules:
  - id: test
    events: {message: {kind: message}}
    where: {compare: {left: {binding: message}, operator: equals, right: {binding: message}}}
    finding: {code: test, message: Safe message, subjects: [message]}
""",
        """
version: 1
predicates:
  target:
    parameters: [value]
    where: {present: [value, payload]}
  wrapper:
    where: {use: {name: target, arguments: {wrong: {literal: value}}}}
rules:
  - id: test
    events: {message: {kind: message}}
    where: {compare: {left: {binding: message}, operator: equals, right: {binding: message}}}
    finding: {code: test, message: Safe message, subjects: [message]}
""",
    ],
)
def test_declarative_predicate_graph_is_rejected_atomically(source: str) -> None:
    with pytest.raises(PolicyLoadError, match="compilation failed"):
        load_match_plan_yaml(source)


@pytest.mark.parametrize(
    "source, message_text",
    [
        (
            "- not\n- a\n- mapping\n",
            "root must be a mapping",
        ),
        (
            """
version: 1
version: 1
rules: []
""",
            "not valid YAML",
        ),
        (
            """
version: 1
shared: &shared {kind: message}
rules: []
""",
            "cannot use aliases",
        ),
        (
            """
version: 1
rules:
  - id: unsafe
    events: {message: {kind: message}}
    callback: builtins.print
    where: {present: [message, payload]}
    finding: {code: unsafe, message: Safe static text, subjects: [message]}
""",
            "schema validation failed",
        ),
        (
            """
rules:
  - id: missing_version
    events: {message: {kind: message}}
    where: {present: [message, payload]}
    finding: {code: invalid, message: Missing version, subjects: [message]}
""",
            "schema validation failed",
        ),
    ],
)
def test_match_yaml_is_strict_and_non_executable(source: str, message_text: str) -> None:
    with pytest.raises(PolicyLoadError, match=message_text):
        load_match_plan_yaml(source)


def test_invalid_compiled_references_are_redacted_policy_errors() -> None:
    source = """
version: 1
rules:
  - id: invalid_reference
    events: {message: {kind: message}}
    where:
      compare:
        left: {field: [payload_secret_value, payload, role]}
        operator: equals
        right: {literal: assistant}
    finding: {code: invalid, message: Safe message, subjects: [message]}
"""

    with pytest.raises(PolicyLoadError, match="compilation failed") as exc_info:
        load_match_plan_yaml(source)
    assert "payload_secret_value" not in str(exc_info.value)


@pytest.mark.parametrize(
    "event_spec",
    [
        "{kind: model_request}",
        "{kind: message, phases: [pre_tool]}",
        "{kind: message, phases: [post_llm, post_llm]}",
    ],
)
def test_invalid_event_binding_contracts_fail_during_compilation(event_spec: str) -> None:
    source = f"""
version: 1
rules:
  - id: invalid_event
    events: {{message: {event_spec}}}
    where: {{present: [message, payload]}}
    finding: {{code: invalid, message: Safe message, subjects: [message]}}
"""

    with pytest.raises(PolicyLoadError, match="compilation failed"):
        load_match_plan_yaml(source)


def test_load_match_plan_file_reports_only_the_path_on_io_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing-policy.yaml"
    with pytest.raises(PolicyLoadError, match=str(missing)):
        load_match_plan_file(missing)
