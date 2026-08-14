"""Provider-neutral findings and analysis reports for the future Policy SDK."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from hashlib import sha256
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from agent_guardrail.models.core import MAX_TRACE_EVENTS

FINDING_IDENTITY_VERSION = 1
MAX_FINDING_SUBJECTS = 64
MAX_FINDING_BINDINGS = 128
MAX_FINDING_LOCATIONS = 64
MAX_FINDING_EVIDENCE = 64
MAX_ANALYSIS_FINDINGS = 1_000
MAX_ANALYSIS_ERRORS = 100
MAX_LOCATION_PATH_SEGMENTS = 16
MAX_LOCATION_PATH_SEGMENT_LENGTH = 64

_IDENTIFIER_PATTERN = r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$"
_BINDING_KEY_PATTERN = r"^[0-9a-f]{64}$"
_FINDING_ID_PATTERN = r"^fnd_[0-9a-f]{64}$"
_SAFE_FINGERPRINT_PATTERN = r"^[A-Za-z0-9_-]{8,128}$"


class AnalysisModel(BaseModel):
    """Closed and immutable base for public analysis output."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AnalysisScope(StrEnum):
    """Which event set was visible during one analysis."""

    SNAPSHOT = "snapshot"
    PENDING = "pending"


class EvidenceSource(StrEnum):
    """The trusted subsystem that produced safe evidence."""

    MATCHER = "matcher"
    PREDICATE = "predicate"
    DETECTOR = "detector"


class AnalysisErrorCode(StrEnum):
    """Stable, input-redacted analysis failure categories."""

    RESOURCE_EXHAUSTED = "resource_exhausted"
    DETECTOR_TIMEOUT = "detector_timeout"
    PARAMETER_ERROR = "parameter_error"
    INPUT_ERROR = "input_error"
    CAPABILITY_ERROR = "capability_error"
    INTERNAL_ERROR = "internal_error"


class FindingLocation(AnalysisModel):
    """A bounded location in one canonical Event without storing its raw value."""

    event_id: str = Field(min_length=1, max_length=256)
    path: tuple[StrictStr | StrictInt, ...] = Field(
        min_length=1,
        max_length=MAX_LOCATION_PATH_SEGMENTS,
    )
    start: StrictInt | None = Field(default=None, ge=0)
    end: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_location(self) -> Self:
        _require_trimmed(self.event_id, "location event_id")
        for segment in self.path:
            if isinstance(segment, bool):
                raise ValueError("location path cannot contain boolean segments")
            if isinstance(segment, int):
                if segment < 0:
                    raise ValueError("location path indexes must be non-negative")
                continue
            _require_trimmed(segment, "location path segment")
            if len(segment) > MAX_LOCATION_PATH_SEGMENT_LENGTH:
                raise ValueError("location path segment is too long")
        if (self.start is None) != (self.end is None):
            raise ValueError("location start and end must be set together")
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("location end must be greater than start")
        return self


class FindingBinding(AnalysisModel):
    """A redacted binding coordinate used for explanation and stable identity."""

    name: str = Field(pattern=_IDENTIFIER_PATTERN)
    key: str = Field(pattern=_BINDING_KEY_PATTERN)
    event_id: str | None = Field(default=None, min_length=1, max_length=256)
    location: FindingLocation | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.event_id is not None:
            _require_trimmed(self.event_id, "binding event_id")
        if self.location is not None:
            if self.event_id is None:
                raise ValueError("a located binding must identify its Event")
            if self.location.event_id != self.event_id:
                raise ValueError("binding and location must identify the same Event")
        return self


class FindingEvidence(AnalysisModel):
    """Masked evidence; original Detector or payload values are intentionally absent."""

    source: EvidenceSource
    type: str = Field(pattern=_IDENTIFIER_PATTERN)
    capability: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    location: FindingLocation | None = None
    masked_evidence: str | None = Field(default=None, min_length=1, max_length=256)
    fingerprint: str | None = Field(default=None, pattern=_SAFE_FINGERPRINT_PATTERN)
    confidence: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.source is EvidenceSource.DETECTOR and self.capability is None:
            raise ValueError("detector evidence must identify its registered capability")
        return self


class Finding(AnalysisModel):
    """One policy match with a reproducible, policy-scoped identity."""

    model_version: Literal[1] = 1
    identity_version: Literal[1] = FINDING_IDENTITY_VERSION
    id: str = Field(pattern=_FINDING_ID_PATTERN)
    policy_hash: str = Field(min_length=8, max_length=128)
    rule_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    code: str = Field(pattern=_IDENTIFIER_PATTERN)
    message: str = Field(min_length=1, max_length=512)
    subject_event_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_FINDING_SUBJECTS,
    )
    bindings: tuple[FindingBinding, ...] = Field(
        default=(),
        max_length=MAX_FINDING_BINDINGS,
    )
    locations: tuple[FindingLocation, ...] = Field(
        default=(),
        max_length=MAX_FINDING_LOCATIONS,
    )
    evidence: tuple[FindingEvidence, ...] = Field(
        default=(),
        max_length=MAX_FINDING_EVIDENCE,
    )

    @classmethod
    def create(
        cls,
        *,
        policy_hash: str,
        rule_id: str,
        code: str,
        message: str,
        subject_event_ids: tuple[str, ...],
        bindings: tuple[FindingBinding, ...] = (),
        locations: tuple[FindingLocation, ...] = (),
        evidence: tuple[FindingEvidence, ...] = (),
    ) -> Finding:
        """Build a Finding and derive its identity instead of accepting caller entropy."""

        finding_id = compute_finding_id(
            policy_hash=policy_hash,
            rule_id=rule_id,
            code=code,
            subject_event_ids=subject_event_ids,
            bindings=bindings,
        )
        return cls(
            id=finding_id,
            policy_hash=policy_hash,
            rule_id=rule_id,
            code=code,
            message=message,
            subject_event_ids=subject_event_ids,
            bindings=bindings,
            locations=locations,
            evidence=evidence,
        )

    @model_validator(mode="after")
    def validate_finding(self) -> Self:
        _require_trimmed(self.policy_hash, "finding policy_hash")
        _require_trimmed(self.message, "finding message")
        _require_unique_trimmed(self.subject_event_ids, "finding subject_event_ids")
        binding_names = [binding.name for binding in self.bindings]
        if len(binding_names) != len(set(binding_names)):
            raise ValueError("finding binding names must be unique")
        expected_id = compute_finding_id(
            policy_hash=self.policy_hash,
            rule_id=self.rule_id,
            code=self.code,
            subject_event_ids=self.subject_event_ids,
            bindings=self.bindings,
        )
        if self.id != expected_id:
            raise ValueError("finding id does not match its stable identity fields")

        referenced_events = set(self.subject_event_ids)
        referenced_events.update(
            binding.event_id for binding in self.bindings if binding.event_id is not None
        )
        location_event_ids = {location.event_id for location in self.locations}
        location_event_ids.update(
            evidence.location.event_id
            for evidence in self.evidence
            if evidence.location is not None
        )
        if not location_event_ids.issubset(referenced_events):
            raise ValueError("finding locations must refer to a subject or bound Event")
        return self


class AnalysisError(AnalysisModel):
    """A safe failure produced while analyzing a snapshot or pending batch."""

    code: AnalysisErrorCode
    message: str = Field(min_length=1, max_length=512)
    rule_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    event_ids: tuple[str, ...] = Field(default=(), max_length=MAX_FINDING_SUBJECTS)
    capability: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    retryable: StrictBool = False

    @model_validator(mode="after")
    def validate_error(self) -> Self:
        _require_trimmed(self.message, "analysis error message")
        _require_unique_trimmed(self.event_ids, "analysis error event_ids")
        return self


class AnalysisReport(AnalysisModel):
    """Deterministic Policy/Monitor output; it never executes enforcement actions."""

    model_version: Literal[1] = 1
    scope: AnalysisScope
    policy_version: StrictInt = Field(ge=1)
    policy_hash: str = Field(min_length=8, max_length=128)
    trace_id: str = Field(min_length=1, max_length=256)
    event_ids: tuple[str, ...] = Field(default=(), max_length=MAX_TRACE_EVENTS)
    pending_event_ids: tuple[str, ...] = Field(default=(), max_length=MAX_TRACE_EVENTS)
    findings: tuple[Finding, ...] = Field(default=(), max_length=MAX_ANALYSIS_FINDINGS)
    errors: tuple[AnalysisError, ...] = Field(default=(), max_length=MAX_ANALYSIS_ERRORS)

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        _require_trimmed(self.policy_hash, "analysis policy_hash")
        _require_trimmed(self.trace_id, "analysis trace_id")
        _require_unique_trimmed(self.event_ids, "analysis event_ids")
        _require_unique_trimmed(self.pending_event_ids, "analysis pending_event_ids")
        event_ids = set(self.event_ids)
        pending_ids = set(self.pending_event_ids)
        if not pending_ids.issubset(event_ids):
            raise ValueError("pending Event IDs must be part of the analyzed snapshot")
        if self.scope is AnalysisScope.SNAPSHOT and self.pending_event_ids:
            raise ValueError("snapshot analysis cannot declare pending Event IDs")
        if self.scope is AnalysisScope.PENDING and not self.pending_event_ids:
            raise ValueError("pending analysis must declare pending Event IDs")

        finding_ids = [finding.id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("analysis report cannot contain duplicate findings")
        for finding in self.findings:
            if finding.policy_hash != self.policy_hash:
                raise ValueError("finding and report policy hashes must match")
            referenced = _finding_event_ids(finding)
            if not referenced.issubset(event_ids):
                raise ValueError("finding refers to an Event outside the analyzed snapshot")
            if self.scope is AnalysisScope.PENDING:
                if not pending_ids.intersection(finding.subject_event_ids):
                    raise ValueError("pending findings must identify at least one pending subject")
        if any(not set(error.event_ids).issubset(event_ids) for error in self.errors):
            raise ValueError("analysis error refers to an Event outside the snapshot")
        return self


def compute_binding_key(*, namespace: str, coordinate: JsonValue) -> str:
    """Hash one structural binding coordinate without exposing its original value."""

    if not _matches_identifier(namespace):
        raise ValueError("binding key namespace must be a valid identifier")
    canonical = json.dumps(
        {
            "binding_key_version": FINDING_IDENTITY_VERSION,
            "namespace": namespace,
            "coordinate": coordinate,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def compute_finding_id(
    *,
    policy_hash: str,
    rule_id: str,
    code: str,
    subject_event_ids: tuple[str, ...],
    bindings: tuple[FindingBinding, ...] = (),
) -> str:
    """Compute identity v1 from policy, rule, subjects and redacted binding keys."""

    if not 8 <= len(policy_hash) <= 128:
        raise ValueError("finding policy_hash must contain between 8 and 128 characters")
    _require_trimmed(policy_hash, "finding policy_hash")
    if not _matches_identifier(rule_id):
        raise ValueError("finding rule_id must be a valid identifier")
    if not _matches_identifier(code):
        raise ValueError("finding code must be a valid identifier")
    if not 1 <= len(subject_event_ids) <= MAX_FINDING_SUBJECTS:
        raise ValueError("finding subject_event_ids exceed their identity bounds")
    _require_unique_trimmed(subject_event_ids, "finding subject_event_ids")
    if len(bindings) > MAX_FINDING_BINDINGS:
        raise ValueError("finding bindings exceed their identity bounds")
    binding_names = [binding.name for binding in bindings]
    if len(binding_names) != len(set(binding_names)):
        raise ValueError("finding binding names must be unique")

    canonical = json.dumps(
        {
            "finding_identity_version": FINDING_IDENTITY_VERSION,
            "policy_hash": policy_hash,
            "rule_id": rule_id,
            "code": code,
            "subject_event_ids": sorted(subject_event_ids),
            "bindings": sorted((binding.name, binding.key) for binding in bindings),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    return "fnd_" + sha256(canonical.encode("utf-8")).hexdigest()


def _finding_event_ids(finding: Finding) -> set[str]:
    event_ids = set(finding.subject_event_ids)
    event_ids.update(
        binding.event_id for binding in finding.bindings if binding.event_id is not None
    )
    event_ids.update(location.event_id for location in finding.locations)
    event_ids.update(
        evidence.location.event_id
        for evidence in finding.evidence
        if evidence.location is not None
    )
    return event_ids


def _matches_identifier(value: str) -> bool:
    return re.fullmatch(_IDENTIFIER_PATTERN, value) is not None


def _require_trimmed(value: str, field: str) -> None:
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a non-blank trimmed string")


def _require_unique_trimmed(values: tuple[str, ...], field: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must be unique")
    for value in values:
        _require_trimmed(value, field)
