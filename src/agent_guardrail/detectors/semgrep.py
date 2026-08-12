"""Deployment-fixed Semgrep adapter with bounded, redacted findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Protocol, runtime_checkable

from agent_guardrail.models import Detection, DetectionContext

SEMGREP_TYPES = frozenset({"semgrep_error", "semgrep_info", "semgrep_warning"})


class SemgrepSeverity(StrEnum):
    """Closed Semgrep severities exposed as stable detection types."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class SemgrepFinding:
    """One backend-normalized finding without source text or filesystem paths.

    ``start`` and ``end`` are zero-based Python character offsets into the exact
    input string, never UTF-8 byte offsets or line/column coordinates. A real
    backend adapter must normalize its native locations before constructing this
    value.
    """

    rule_id: str
    severity: SemgrepSeverity
    start: int | None = None
    end: int | None = None
    confidence: float = 0.95

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        if not isinstance(self.severity, SemgrepSeverity):
            raise TypeError("Semgrep finding severity must be SemgrepSeverity")
        _validate_span(self.start, self.end)
        if type(self.confidence) is not float or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Semgrep finding confidence must be a float in [0, 1]")


@dataclass(frozen=True, slots=True)
class SemgrepProfile:
    """Deployment-owned identity and allowlist for one pinned Semgrep ruleset."""

    profile_id: str
    profile_version: str
    language: str
    allowed_rule_ids: frozenset[str]
    max_findings: int = 64

    def __post_init__(self) -> None:
        _validate_identity(self.profile_id, "Semgrep profile id")
        _validate_identity(self.profile_version, "Semgrep profile version")
        _validate_identity(self.language, "Semgrep language")
        if not isinstance(self.allowed_rule_ids, frozenset) or not self.allowed_rule_ids:
            raise ValueError("Semgrep profile must pin at least one rule id")
        for rule_id in self.allowed_rule_ids:
            _validate_rule_id(rule_id)
        if (
            isinstance(self.max_findings, bool)
            or not isinstance(self.max_findings, int)
            or not 1 <= self.max_findings <= 64
        ):
            raise ValueError("Semgrep max_findings must be an integer in [1, 64]")


@runtime_checkable
class SemgrepBackend(Protocol):
    """A deployment-owned scanner already pinned to an isolated ruleset."""

    name: str
    version: str

    async def scan(self, text: str) -> list[SemgrepFinding] | tuple[SemgrepFinding, ...]: ...


class SemgrepDetector:
    """Convert a fixed Semgrep backend profile into safe detector facts.

    This class never selects a process, executable, working directory, language,
    file, or rule configuration. Those choices belong to the injected backend
    and profile, which structured Policy cannot access.
    """

    name = "semgrep"
    adapter_version = "1"

    def __init__(self, backend: SemgrepBackend, *, profile: SemgrepProfile) -> None:
        if not isinstance(backend, SemgrepBackend):
            raise TypeError("backend must implement SemgrepBackend")
        _validate_identity(backend.name, "Semgrep backend name")
        _validate_identity(backend.version, "Semgrep backend version")
        if not isinstance(profile, SemgrepProfile):
            raise TypeError("profile must be SemgrepProfile")
        self._backend = backend
        self._profile = profile
        identity_material = json.dumps(
            (
                backend.name,
                backend.version,
                profile.profile_id,
                profile.profile_version,
                profile.language,
                sorted(profile.allowed_rule_ids),
                profile.max_findings,
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        identity = sha256(identity_material.encode("utf-8")).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    @property
    def profile(self) -> SemgrepProfile:
        """Return the immutable deployment profile for registry construction."""

        return self._profile

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        raw = await self._backend.scan(text)
        if type(raw) not in (list, tuple):
            raise TypeError("Semgrep backend must return a list or tuple")
        if len(raw) > self._profile.max_findings:
            raise ValueError("Semgrep backend result limit exceeded")

        findings: dict[tuple[str, SemgrepSeverity, int | None, int | None], SemgrepFinding] = {}
        for finding in raw:
            if not isinstance(finding, SemgrepFinding):
                raise TypeError("Semgrep backend returned an invalid finding")
            if finding.rule_id not in self._profile.allowed_rule_ids:
                raise ValueError("Semgrep backend returned an unpinned rule id")
            if finding.end is not None and finding.end > len(text):
                raise ValueError("Semgrep backend returned an out-of-range span")
            key = (finding.rule_id, finding.severity, finding.start, finding.end)
            previous = findings.get(key)
            if previous is None or finding.confidence > previous.confidence:
                findings[key] = finding

        ordered = sorted(
            findings.values(),
            key=lambda item: (
                item.start if item.start is not None else len(text) + 1,
                item.end if item.end is not None else len(text) + 1,
                item.severity.value,
                item.rule_id,
            ),
        )
        return [self._to_detection(item, context=context) for item in ordered]

    def _to_detection(
        self,
        finding: SemgrepFinding,
        *,
        context: DetectionContext,
    ) -> Detection:
        detection_type = f"semgrep_{finding.severity.value}"
        fingerprint = _finding_fingerprint(
            detector=self.name,
            detector_version=self.version,
            backend_name=self._backend.name,
            backend_version=self._backend.version,
            profile_id=self._profile.profile_id,
            profile_version=self._profile.profile_version,
            item_id=finding.rule_id,
            detection_type=detection_type,
            start=finding.start,
            end=finding.end,
            context=context,
        )
        return Detection(
            type=detection_type,
            detector=self.name,
            detector_version=self.version,
            confidence=finding.confidence,
            start=finding.start,
            end=finding.end,
            masked_evidence=f"<{self.name}:{detection_type}:{fingerprint}>",
            fingerprint=fingerprint,
        )


def _finding_fingerprint(
    *,
    detector: str,
    detector_version: str,
    backend_name: str,
    backend_version: str,
    profile_id: str,
    profile_version: str,
    item_id: str,
    detection_type: str,
    start: int | None,
    end: int | None,
    context: DetectionContext,
) -> str:
    material = json.dumps(
        (
            detector,
            detector_version,
            backend_name,
            backend_version,
            profile_id,
            profile_version,
            item_id,
            context.trace_id,
            context.event_id,
            context.phase.value,
            detection_type,
            start,
            end,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return sha256(material.encode("utf-8")).hexdigest()[:16]


def _validate_identity(value: str, subject: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(character in value for character in ("/", "\\", "\x00", "\r", "\n"))
    ):
        raise ValueError(f"{subject} is invalid")


def _validate_rule_id(rule_id: str) -> None:
    if (
        not isinstance(rule_id, str)
        or not rule_id
        or len(rule_id) > 256
        or rule_id != rule_id.strip()
        or any(character in rule_id for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError("Semgrep rule id is invalid")


def _validate_span(start: int | None, end: int | None) -> None:
    if (start is None) != (end is None):
        raise ValueError("Semgrep finding span must be complete")
    if start is not None and (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 0
        or end <= start
    ):
        raise ValueError("Semgrep finding span is invalid")
