"""Deployment-fixed YARA injection-signature adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, runtime_checkable

from agent_guardrail.models import Detection, DetectionContext

YARA_INJECTION_TYPES = frozenset(
    {
        "yara_code_injection",
        "yara_prompt_injection",
        "yara_sql_injection",
        "yara_template_injection",
        "yara_xss",
    }
)


@dataclass(frozen=True, slots=True)
class YaraRuleBinding:
    """Bind one precompiled rule id to a closed public detection category."""

    rule_id: str
    detection_type: str
    confidence: float = 0.98

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        if self.detection_type not in YARA_INJECTION_TYPES:
            raise ValueError("YARA binding detection type is not supported")
        if type(self.confidence) is not float or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("YARA binding confidence must be a float in [0, 1]")


@dataclass(frozen=True, slots=True)
class YaraInjectionProfile:
    """Deployment-owned identity and rule mapping for precompiled YARA rules."""

    profile_id: str
    profile_version: str
    rules: tuple[YaraRuleBinding, ...]
    max_matches: int = 64

    def __post_init__(self) -> None:
        _validate_identity(self.profile_id, "YARA profile id")
        _validate_identity(self.profile_version, "YARA profile version")
        if not isinstance(self.rules, tuple) or not self.rules:
            raise ValueError("YARA profile must bind at least one rule")
        if len(self.rules) > 64 or any(
            not isinstance(binding, YaraRuleBinding) for binding in self.rules
        ):
            raise ValueError("YARA profile rule bindings are invalid")
        rule_ids = tuple(binding.rule_id for binding in self.rules)
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("YARA profile rule ids must be unique")
        if (
            isinstance(self.max_matches, bool)
            or not isinstance(self.max_matches, int)
            or not 1 <= self.max_matches <= 64
        ):
            raise ValueError("YARA max_matches must be an integer in [1, 64]")

    @property
    def rule_bindings(self) -> dict[str, YaraRuleBinding]:
        """Return a fresh lookup without exposing mutable profile state."""

        return {binding.rule_id: binding for binding in self.rules}


@dataclass(frozen=True, slots=True)
class YaraSignatureMatch:
    """One normalized precompiled-rule match without matched plaintext.

    ``start`` and ``end`` are zero-based Python character offsets into the exact
    input string. A yara-python adapter must convert native byte offsets before
    constructing this value; it may use ``None`` when a reliable mapping is not
    available.
    """

    rule_id: str
    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        _validate_span(self.start, self.end)


@runtime_checkable
class YaraInjectionBackend(Protocol):
    """A deployment-owned backend containing already compiled YARA rules."""

    name: str
    version: str

    async def match(
        self,
        text: str,
    ) -> list[YaraSignatureMatch] | tuple[YaraSignatureMatch, ...]: ...


class YaraInjectionDetector:
    """Convert fixed, precompiled YARA matches into redacted detector facts.

    Rule source, paths, compilation, process selection, and remediation are
    deliberately absent. The injected backend and profile are deployment
    configuration and cannot be selected by structured Policy.
    """

    name = "yara_injection_signatures"
    adapter_version = "1"

    def __init__(
        self,
        backend: YaraInjectionBackend,
        *,
        profile: YaraInjectionProfile,
    ) -> None:
        if not isinstance(backend, YaraInjectionBackend):
            raise TypeError("backend must implement YaraInjectionBackend")
        _validate_identity(backend.name, "YARA backend name")
        _validate_identity(backend.version, "YARA backend version")
        if not isinstance(profile, YaraInjectionProfile):
            raise TypeError("profile must be YaraInjectionProfile")
        self._backend = backend
        self._profile = profile
        identity_material = json.dumps(
            (
                backend.name,
                backend.version,
                profile.profile_id,
                profile.profile_version,
                tuple(
                    (
                        binding.rule_id,
                        binding.detection_type,
                        binding.confidence,
                    )
                    for binding in profile.rules
                ),
                profile.max_matches,
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        identity = sha256(identity_material.encode("utf-8")).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    @property
    def profile(self) -> YaraInjectionProfile:
        """Return the immutable deployment profile for registry construction."""

        return self._profile

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        raw = await self._backend.match(text)
        if type(raw) not in (list, tuple):
            raise TypeError("YARA backend must return a list or tuple")
        if len(raw) > self._profile.max_matches:
            raise ValueError("YARA backend result limit exceeded")

        bindings = self._profile.rule_bindings
        matches: dict[tuple[str, int | None, int | None], YaraSignatureMatch] = {}
        for match in raw:
            if not isinstance(match, YaraSignatureMatch):
                raise TypeError("YARA backend returned an invalid match")
            if match.rule_id not in bindings:
                raise ValueError("YARA backend returned an unpinned rule id")
            if match.end is not None and match.end > len(text):
                raise ValueError("YARA backend returned an out-of-range span")
            matches.setdefault((match.rule_id, match.start, match.end), match)

        ordered = sorted(
            matches.values(),
            key=lambda item: (
                item.start if item.start is not None else len(text) + 1,
                item.end if item.end is not None else len(text) + 1,
                item.rule_id,
            ),
        )
        return [
            self._to_detection(match, binding=bindings[match.rule_id], context=context)
            for match in ordered
        ]

    def _to_detection(
        self,
        match: YaraSignatureMatch,
        *,
        binding: YaraRuleBinding,
        context: DetectionContext,
    ) -> Detection:
        fingerprint = _match_fingerprint(
            detector=self.name,
            detector_version=self.version,
            backend_name=self._backend.name,
            backend_version=self._backend.version,
            profile_id=self._profile.profile_id,
            profile_version=self._profile.profile_version,
            rule_id=match.rule_id,
            detection_type=binding.detection_type,
            start=match.start,
            end=match.end,
            context=context,
        )
        return Detection(
            type=binding.detection_type,
            detector=self.name,
            detector_version=self.version,
            confidence=binding.confidence,
            start=match.start,
            end=match.end,
            masked_evidence=f"<{self.name}:{binding.detection_type}:{fingerprint}>",
            fingerprint=fingerprint,
        )


def _match_fingerprint(
    *,
    detector: str,
    detector_version: str,
    backend_name: str,
    backend_version: str,
    profile_id: str,
    profile_version: str,
    rule_id: str,
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
            rule_id,
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
        or len(rule_id) > 128
        or rule_id != rule_id.strip()
        or any(character in rule_id for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError("YARA rule id is invalid")


def _validate_span(start: int | None, end: int | None) -> None:
    if (start is None) != (end is None):
        raise ValueError("YARA match span must be complete")
    if start is not None and (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 0
        or end <= start
    ):
        raise ValueError("YARA match span is invalid")
