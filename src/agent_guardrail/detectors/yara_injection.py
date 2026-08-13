"""Deployment-fixed YARA injection-signature adapter."""

from __future__ import annotations

import asyncio
import inspect
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
MAX_YARA_INPUT_BYTES = 16_384


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


class YaraPythonBackend:
    """Adapt precompiled yara-python rules with native and result bounds."""

    name = "yara-python"

    def __init__(
        self,
        rules: object,
        *,
        engine_version: str,
        ruleset_digest: str,
        max_matches: int = 64,
        native_timeout_seconds: int = 1,
    ) -> None:
        match = getattr(rules, "match", None)
        if not callable(match):
            raise TypeError("compiled YARA rules must provide a callable match method")
        _validate_identity(engine_version, "YARA engine version")
        if (
            not isinstance(ruleset_digest, str)
            or len(ruleset_digest) != 64
            or any(character not in "0123456789abcdef" for character in ruleset_digest)
        ):
            raise ValueError("YARA ruleset digest must be a lowercase SHA-256")
        if (
            isinstance(max_matches, bool)
            or not isinstance(max_matches, int)
            or not 1 <= max_matches <= 64
        ):
            raise ValueError("YARA max matches must be an integer in [1, 64]")
        if (
            isinstance(native_timeout_seconds, bool)
            or not isinstance(native_timeout_seconds, int)
            or not 1 <= native_timeout_seconds <= 30
        ):
            raise ValueError("YARA native timeout must be an integer in [1, 30]")
        self.version = f"{engine_version}+rules.{ruleset_digest[:12]}"
        self._match = match
        self._max_matches = max_matches
        self._native_timeout_seconds = native_timeout_seconds

    async def match(self, text: str) -> list[YaraSignatureMatch]:
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_YARA_INPUT_BYTES:
            raise ValueError("YARA input exceeds its hard byte bound")
        raw = await asyncio.to_thread(
            self._match,
            data=encoded,
            timeout=self._native_timeout_seconds,
        )
        if inspect.isawaitable(raw):
            raw = await raw
        if type(raw) is not list:
            raise TypeError("YARA backend returned an invalid result collection")

        normalized: list[YaraSignatureMatch] = []
        for raw_match in raw:
            rule_id = getattr(raw_match, "rule", None)
            strings = getattr(raw_match, "strings", None)
            if not isinstance(rule_id, str):
                raise TypeError("YARA backend returned an invalid rule id")
            _validate_rule_id(rule_id)
            if type(strings) is not list:
                raise TypeError("YARA backend returned invalid string matches")
            spans: set[tuple[int, int]] = set()
            for string_match in strings:
                instances = getattr(string_match, "instances", None)
                if type(instances) is not list:
                    raise TypeError("YARA backend returned invalid string instances")
                for instance in instances:
                    offset = getattr(instance, "offset", None)
                    matched_length = getattr(instance, "matched_length", None)
                    spans.add(
                        _yara_character_span(
                            encoded,
                            offset=offset,
                            matched_length=matched_length,
                        )
                    )
            if spans:
                for start, end in sorted(spans):
                    normalized.append(
                        YaraSignatureMatch(rule_id=rule_id, start=start, end=end)
                    )
                    if len(normalized) > self._max_matches:
                        raise ValueError("YARA backend result limit exceeded")
            else:
                normalized.append(YaraSignatureMatch(rule_id=rule_id))
                if len(normalized) > self._max_matches:
                    raise ValueError("YARA backend result limit exceeded")
        return normalized


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


def _yara_character_span(
    encoded: bytes,
    *,
    offset: object,
    matched_length: object,
) -> tuple[int, int]:
    if (
        isinstance(offset, bool)
        or isinstance(matched_length, bool)
        or not isinstance(offset, int)
        or not isinstance(matched_length, int)
        or offset < 0
        or matched_length <= 0
        or offset + matched_length > len(encoded)
    ):
        raise ValueError("YARA backend returned an invalid byte span")
    try:
        start = len(encoded[:offset].decode("utf-8"))
        end = len(encoded[: offset + matched_length].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("YARA returned a non-character-aligned byte span") from exc
    return start, end
