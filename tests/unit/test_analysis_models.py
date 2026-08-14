from __future__ import annotations

import json

import pytest
from pydantic import JsonValue, ValidationError

from agent_guardrail.models import (
    FINDING_IDENTITY_VERSION,
    AnalysisError,
    AnalysisErrorCode,
    AnalysisReport,
    AnalysisScope,
    EvidenceSource,
    Finding,
    FindingBinding,
    FindingEvidence,
    FindingLocation,
    compute_binding_key,
    compute_finding_id,
)

POLICY_HASH = "a" * 64


def binding(
    name: str,
    *,
    event_id: str | None = None,
    ordinal: int = 0,
    location: FindingLocation | None = None,
) -> FindingBinding:
    coordinate: dict[str, JsonValue] = {
        "event_id": event_id,
        "ordinal": ordinal,
        "path": list(location.path) if location is not None else None,
    }
    return FindingBinding(
        name=name,
        key=compute_binding_key(
            namespace="match.binding",
            coordinate=coordinate,
        ),
        event_id=event_id,
        location=location,
    )


def finding(
    *,
    subjects: tuple[str, ...] = ("event-2",),
    bindings: tuple[FindingBinding, ...] = (),
    locations: tuple[FindingLocation, ...] = (),
    evidence: tuple[FindingEvidence, ...] = (),
    policy_hash: str = POLICY_HASH,
    rule_id: str = "rule.blocked_content",
    code: str = "blocked_content",
) -> Finding:
    return Finding.create(
        policy_hash=policy_hash,
        rule_id=rule_id,
        code=code,
        message="Blocked content matched",
        subject_event_ids=subjects,
        bindings=bindings,
        locations=locations,
        evidence=evidence,
    )


def test_binding_key_uses_canonical_json_and_does_not_expose_input() -> None:
    raw_marker = "sensitive-marker-that-must-not-be-serialized"
    first = compute_binding_key(
        namespace="collection.item",
        coordinate={"event_id": "event-1", "path": ["payload", "items"], "index": 1},
    )
    reordered = compute_binding_key(
        namespace="collection.item",
        coordinate={"index": 1, "path": ["payload", "items"], "event_id": "event-1"},
    )
    different = compute_binding_key(
        namespace="collection.item",
        coordinate={"event_id": "event-1", "path": ["payload", "items"], "index": 2},
    )
    opaque = compute_binding_key(
        namespace="test.only",
        coordinate={"value": raw_marker},
    )

    assert first == reordered
    assert first != different
    assert len(first) == 64
    assert raw_marker not in opaque


@pytest.mark.parametrize("namespace", ["", " bad", "bad/value", "bad value"])
def test_binding_key_rejects_invalid_namespace(namespace: str) -> None:
    with pytest.raises(ValueError, match="namespace"):
        compute_binding_key(namespace=namespace, coordinate={"event_id": "event-1"})


def test_finding_identity_is_order_independent_and_output_is_redacted() -> None:
    message_location = FindingLocation(
        event_id="event-2",
        path=("payload", "content", "text"),
        start=4,
        end=10,
    )
    history_binding = binding("history", event_id="event-1")
    message_binding = binding(
        "message",
        event_id="event-2",
        location=message_location,
    )
    masked = FindingEvidence(
        source=EvidenceSource.DETECTOR,
        type="secret",
        capability="secrets",
        location=message_location,
        masked_evidence="secret-***-last4",
        fingerprint="safe_fingerprint_1",
        confidence=0.99,
    )

    first = finding(
        subjects=("event-2", "event-1"),
        bindings=(message_binding, history_binding),
        locations=(message_location,),
        evidence=(masked,),
    )
    reordered = finding(
        subjects=("event-1", "event-2"),
        bindings=(history_binding, message_binding),
        locations=(message_location,),
        evidence=(masked,),
    )

    assert first.id == reordered.id
    assert first.identity_version == FINDING_IDENTITY_VERSION
    assert first.model_dump(mode="json")["identity_version"] == 1
    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert "secret-***-last4" in serialized
    assert "unmasked-sensitive-value" not in serialized

    with pytest.raises(ValidationError, match="frozen"):
        first.message = "changed"


def test_finding_identity_changes_for_each_identity_dimension() -> None:
    first_binding = binding("message", event_id="event-1", ordinal=0)
    second_binding = binding("message", event_id="event-1", ordinal=1)
    baseline = finding(subjects=("event-1",), bindings=(first_binding,))

    variants = (
        finding(
            subjects=("event-1",),
            bindings=(first_binding,),
            policy_hash="b" * 64,
        ),
        finding(
            subjects=("event-1",),
            bindings=(first_binding,),
            rule_id="rule.other",
        ),
        finding(
            subjects=("event-1",),
            bindings=(first_binding,),
            code="other_code",
        ),
        finding(subjects=("event-2",), bindings=(first_binding,)),
        finding(subjects=("event-1",), bindings=(second_binding,)),
    )

    assert all(candidate.id != baseline.id for candidate in variants)


def test_finding_identity_ignores_explanation_text_and_safe_evidence() -> None:
    baseline = finding(subjects=("event-1",))
    changed_explanation = Finding.create(
        policy_hash=POLICY_HASH,
        rule_id=baseline.rule_id,
        code=baseline.code,
        message="A localized explanation",
        subject_event_ids=baseline.subject_event_ids,
        evidence=(
            FindingEvidence(
                source=EvidenceSource.MATCHER,
                type="field_match",
                masked_evidence="[MATCH]",
            ),
        ),
    )

    assert changed_explanation.id == baseline.id


def test_finding_rejects_caller_supplied_mismatched_identity() -> None:
    valid = finding()

    with pytest.raises(ValidationError, match="stable identity"):
        Finding.model_validate(
            {
                **valid.model_dump(mode="json"),
                "id": "fnd_" + "0" * 64,
            }
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"subject_event_ids": ("event-1", "event-1")}, "must be unique"),
        (
            {
                "bindings": (
                    binding("same", event_id="event-1"),
                    binding("same", event_id="event-2"),
                )
            },
            "binding names must be unique",
        ),
    ],
)
def test_finding_rejects_ambiguous_identity_fields(
    updates: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "policy_hash": POLICY_HASH,
        "rule_id": "rule.blocked_content",
        "code": "blocked_content",
        "message": "Blocked content matched",
        "subject_event_ids": ("event-1",),
        **updates,
    }
    with pytest.raises((ValidationError, ValueError), match=message):
        Finding.create(**arguments)  # type: ignore[arg-type]


def test_public_finding_identity_helper_validates_its_inputs() -> None:
    with pytest.raises(ValueError, match="policy_hash"):
        compute_finding_id(
            policy_hash="short",
            rule_id="rule.valid",
            code="valid",
            subject_event_ids=("event-1",),
        )
    with pytest.raises(ValueError, match="rule_id"):
        compute_finding_id(
            policy_hash=POLICY_HASH,
            rule_id="invalid rule",
            code="valid",
            subject_event_ids=("event-1",),
        )
    with pytest.raises(ValueError, match="subject_event_ids"):
        compute_finding_id(
            policy_hash=POLICY_HASH,
            rule_id="rule.valid",
            code="valid",
            subject_event_ids=(),
        )


def test_location_is_bounded_and_uses_strict_path_segments() -> None:
    location = FindingLocation(
        event_id="event-1",
        path=("payload", "items", 0, "value"),
        start=0,
        end=1,
    )

    assert location.path == ("payload", "items", 0, "value")

    invalid_locations = (
        {"event_id": "event-1", "path": (True,)},
        {"event_id": "event-1", "path": (-1,)},
        {"event_id": "event-1", "path": (" payload",)},
        {"event_id": "event-1", "path": ("x" * 65,)},
        {"event_id": "event-1", "path": ("payload",), "start": True, "end": 2},
        {"event_id": "event-1", "path": ("payload",), "start": 0},
        {"event_id": "event-1", "path": ("payload",), "start": 2, "end": 2},
        {"event_id": "event-1", "path": tuple("x" for _ in range(17))},
    )
    for value in invalid_locations:
        with pytest.raises(ValidationError):
            FindingLocation.model_validate(value)


def test_binding_and_evidence_references_are_closed() -> None:
    location = FindingLocation(event_id="event-1", path=("payload", "content", "text"))

    with pytest.raises(ValidationError, match="must identify its Event"):
        FindingBinding(
            name="message",
            key="0" * 64,
            location=location,
        )
    with pytest.raises(ValidationError, match="same Event"):
        FindingBinding(
            name="message",
            key="0" * 64,
            event_id="event-2",
            location=location,
        )
    with pytest.raises(ValidationError, match="registered capability"):
        FindingEvidence(
            source=EvidenceSource.DETECTOR,
            type="secret",
            masked_evidence="[SECRET]",
        )


def test_finding_locations_must_refer_to_subjects_or_bound_events() -> None:
    unknown = FindingLocation(event_id="unknown", path=("payload", "content", "text"))

    with pytest.raises(ValidationError, match="subject or bound Event"):
        finding(subjects=("event-1",), locations=(unknown,))
    with pytest.raises(ValidationError, match="subject or bound Event"):
        finding(
            subjects=("event-1",),
            evidence=(
                FindingEvidence(
                    source=EvidenceSource.MATCHER,
                    type="field_match",
                    location=unknown,
                ),
            ),
        )

    historical = binding("history", event_id="event-0")
    allowed = finding(
        subjects=("event-1",),
        bindings=(historical,),
        locations=(FindingLocation(event_id="event-0", path=("payload", "name")),),
    )
    assert allowed.locations[0].event_id == "event-0"


def test_snapshot_report_accepts_deterministic_all_findings() -> None:
    match = finding(subjects=("event-1",))
    report = AnalysisReport(
        scope=AnalysisScope.SNAPSHOT,
        policy_version=2,
        policy_hash=POLICY_HASH,
        trace_id="trace-1",
        event_ids=("event-1", "event-2"),
        findings=(match,),
    )

    assert report.findings == (match,)
    assert report.pending_event_ids == ()
    assert report.model_dump(mode="json")["scope"] == "snapshot"

    with pytest.raises(ValidationError, match="int_type"):
        AnalysisReport.model_validate(
            {
                **report.model_dump(mode="json"),
                "policy_version": True,
            }
        )


def test_pending_report_allows_historical_context_but_requires_pending_subject() -> None:
    history_location = FindingLocation(event_id="past-1", path=("payload", "name"))
    match = finding(
        subjects=("pending-1",),
        bindings=(binding("history", event_id="past-1", location=history_location),),
        evidence=(
            FindingEvidence(
                source=EvidenceSource.MATCHER,
                type="historical_match",
                location=history_location,
                masked_evidence="[MATCH]",
            ),
        ),
    )
    report = AnalysisReport(
        scope=AnalysisScope.PENDING,
        policy_version=2,
        policy_hash=POLICY_HASH,
        trace_id="trace-1",
        event_ids=("past-1", "pending-1", "pending-2"),
        pending_event_ids=("pending-1", "pending-2"),
        findings=(match,),
    )

    assert report.findings[0].subject_event_ids == ("pending-1",)


def test_pending_report_rejects_past_only_finding() -> None:
    with pytest.raises(ValidationError, match="pending subject"):
        AnalysisReport(
            scope=AnalysisScope.PENDING,
            policy_version=2,
            policy_hash=POLICY_HASH,
            trace_id="trace-1",
            event_ids=("past-1", "pending-1"),
            pending_event_ids=("pending-1",),
            findings=(finding(subjects=("past-1",)),),
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "scope": AnalysisScope.SNAPSHOT,
                "pending_event_ids": ("event-1",),
                "event_ids": ("event-1",),
            },
            "snapshot analysis",
        ),
        (
            {"scope": AnalysisScope.PENDING, "pending_event_ids": ()},
            "must declare pending",
        ),
        (
            {
                "scope": AnalysisScope.PENDING,
                "pending_event_ids": ("unknown",),
                "event_ids": ("event-1",),
            },
            "part of the analyzed snapshot",
        ),
        (
            {"event_ids": ("event-1", "event-1")},
            "must be unique",
        ),
    ],
)
def test_report_rejects_invalid_snapshot_identity(
    kwargs: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "scope": AnalysisScope.SNAPSHOT,
        "policy_version": 2,
        "policy_hash": POLICY_HASH,
        "trace_id": "trace-1",
        "event_ids": ("event-1",),
        **kwargs,
    }
    with pytest.raises(ValidationError, match=message):
        AnalysisReport.model_validate(arguments)


def test_report_rejects_finding_outside_policy_or_snapshot() -> None:
    wrong_policy = finding(subjects=("event-1",), policy_hash="b" * 64)
    unknown_event = finding(subjects=("unknown",))

    with pytest.raises(ValidationError, match="policy hashes"):
        AnalysisReport(
            scope=AnalysisScope.SNAPSHOT,
            policy_version=2,
            policy_hash=POLICY_HASH,
            trace_id="trace-1",
            event_ids=("event-1",),
            findings=(wrong_policy,),
        )
    with pytest.raises(ValidationError, match="outside the analyzed snapshot"):
        AnalysisReport(
            scope=AnalysisScope.SNAPSHOT,
            policy_version=2,
            policy_hash=POLICY_HASH,
            trace_id="trace-1",
            event_ids=("event-1",),
            findings=(unknown_event,),
        )


def test_report_rejects_duplicate_findings_and_unknown_error_events() -> None:
    match = finding(subjects=("event-1",))

    with pytest.raises(ValidationError, match="duplicate findings"):
        AnalysisReport(
            scope=AnalysisScope.SNAPSHOT,
            policy_version=2,
            policy_hash=POLICY_HASH,
            trace_id="trace-1",
            event_ids=("event-1",),
            findings=(match, match),
        )
    with pytest.raises(ValidationError, match="analysis error"):
        AnalysisReport(
            scope=AnalysisScope.SNAPSHOT,
            policy_version=2,
            policy_hash=POLICY_HASH,
            trace_id="trace-1",
            event_ids=("event-1",),
            errors=(
                AnalysisError(
                    code=AnalysisErrorCode.DETECTOR_TIMEOUT,
                    message="Detector timed out",
                    event_ids=("unknown",),
                    capability="prompt_injection",
                    retryable=True,
                ),
            ),
        )


def test_analysis_error_is_closed_frozen_and_safe_to_serialize() -> None:
    error = AnalysisError(
        code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
        message="Binding combination budget exhausted",
        rule_id="rule.multi_binding",
        event_ids=("event-1",),
        retryable=False,
    )
    serialized = error.model_dump(mode="json")

    assert serialized == {
        "code": "resource_exhausted",
        "message": "Binding combination budget exhausted",
        "rule_id": "rule.multi_binding",
        "event_ids": ["event-1"],
        "capability": None,
        "retryable": False,
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AnalysisError.model_validate({**serialized, "raw_exception": "secret"})
    with pytest.raises(ValidationError, match="frozen"):
        error.retryable = True
