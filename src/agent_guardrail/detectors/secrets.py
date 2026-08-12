"""Deterministic local secret detection with audit-safe evidence."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass
from re import Pattern

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

SecretValidator = Callable[[str], bool]
MAX_SECRET_DETECTIONS = 64


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """One code-reviewed provider or contextual secret recognizer."""

    type: str
    regex: Pattern[str]
    confidence: float = 0.95
    priority: int = 0
    capture_group: int | str = 0
    validator: SecretValidator | None = None


def _not_placeholder(value: str) -> bool:
    """Reject low-signal values used in documentation and templates."""

    normalized = value.strip("'\" ").casefold()
    compact = re.sub(r"[^a-z0-9]", "", normalized)
    if len(set(compact)) < 4:
        return False
    placeholder_fragments = (
        "changeme",
        "dummy",
        "example",
        "placeholder",
        "redacted",
        "replaceme",
        "sample",
        "yourapikey",
        "yourtoken",
    )
    return not any(fragment in compact for fragment in placeholder_fragments)


def _valid_aws_secret(value: str) -> bool:
    return len(value) == 40 and len(set(value)) >= 10


def _valid_azure_storage_key(value: str) -> bool:
    if len(value) != 88 or len(set(value)) < 10:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def _valid_slack_token(value: str) -> bool:
    return len(value) >= 20 and len(set(value.casefold())) >= 6


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    # Provider-specific recognizers have higher priority than generic assigned
    # secret or Bearer recognizers so one occurrence yields one stable fact.
    SecretPattern(
        type="private_key",
        regex=re.compile(
            r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----"
            r"|-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ),
        confidence=0.99,
        priority=100,
    ),
    SecretPattern(
        type="github_token",
        regex=re.compile(
            r"(?<![A-Za-z0-9_])(?:"
            r"gh[pousr]_[A-Za-z0-9_]{36}"
            r"|github_pat_[A-Za-z0-9_]{22,255}"
            r")(?![A-Za-z0-9_])"
        ),
        confidence=0.99,
        priority=100,
    ),
    SecretPattern(
        type="aws_access_key",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}"
            r"(?![A-Za-z0-9])"
        ),
        confidence=0.99,
        priority=100,
    ),
    SecretPattern(
        type="aws_access_key",
        regex=re.compile(
            r"\baws[^\r\n]{0,20}?"
            r"(?:secret(?:[_ -]?access)?[_ -]?key|key|pwd|pw|password|pass|token)"
            r"[^\r\n]{0,20}?[\"'](?P<aws_secret>[0-9A-Za-z/+]{40})[\"']",
            re.IGNORECASE,
        ),
        confidence=0.98,
        priority=100,
        capture_group="aws_secret",
        validator=_valid_aws_secret,
    ),
    SecretPattern(
        type="azure_storage_key",
        regex=re.compile(
            r"(?<![A-Za-z0-9])AccountKey=(?P<azure_key>[A-Za-z0-9+/=]{88})"
            r"(?![A-Za-z0-9+/=])",
            re.IGNORECASE,
        ),
        confidence=0.99,
        priority=100,
        capture_group="azure_key",
        validator=_valid_azure_storage_key,
    ),
    SecretPattern(
        type="slack_token",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?P<slack_token>"
            r"xox(?:a|b|p|o|s|r)-(?:\d+-)+[A-Za-z0-9]+"
            r")(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
        confidence=0.99,
        priority=100,
        capture_group="slack_token",
        validator=_valid_slack_token,
    ),
    SecretPattern(
        type="slack_token",
        regex=re.compile(
            r"https://hooks\.slack\.com/services/"
            r"T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
            re.IGNORECASE,
        ),
        confidence=0.99,
        priority=100,
        validator=_valid_slack_token,
    ),
    SecretPattern(
        type="openai_api_key",
        regex=re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}"
            r"(?![A-Za-z0-9_-])"
        ),
        confidence=0.98,
        priority=90,
    ),
    SecretPattern(
        type="bearer_token",
        regex=re.compile(
            r"\bBearer\s+(?P<bearer>[A-Za-z0-9._~+/=-]{12,})",
            re.IGNORECASE,
        ),
        confidence=0.92,
        priority=30,
        capture_group="bearer",
        validator=_not_placeholder,
    ),
    SecretPattern(
        type="assigned_secret",
        regex=re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*"
            r"(?:['\"])?(?P<assigned>[A-Za-z0-9._~+/=-]{12,})",
            re.IGNORECASE,
        ),
        confidence=0.90,
        priority=10,
        capture_group="assigned",
        validator=_not_placeholder,
    ),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    type: str
    confidence: float
    priority: int


class SecretDetector:
    """Find reviewed credential shapes without retaining their values."""

    name = "secrets"
    version = "2"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        candidates = _secret_candidates(text)
        selected: list[_Candidate] = []
        occupied: list[tuple[int, int]] = []
        for candidate in sorted(
            candidates,
            key=lambda item: (
                -item.priority,
                item.start,
                -(item.end - item.start),
                item.type,
            ),
        ):
            if any(
                candidate.start < occupied_end and candidate.end > occupied_start
                for occupied_start, occupied_end in occupied
            ):
                continue
            selected.append(candidate)
            occupied.append((candidate.start, candidate.end))

        if len(selected) > MAX_SECRET_DETECTIONS:
            raise ValueError("secret detector result limit exceeded")

        detections: list[Detection] = []
        for candidate in sorted(
            selected,
            key=lambda item: (item.start, item.end, item.type),
        ):
            fingerprint = occurrence_fingerprint(
                context=context,
                detector=self.name,
                detector_version=self.version,
                detection_type=candidate.type,
                start=candidate.start,
                end=candidate.end,
            )
            detections.append(
                Detection(
                    type=candidate.type,
                    detector=self.name,
                    detector_version=self.version,
                    confidence=candidate.confidence,
                    start=candidate.start,
                    end=candidate.end,
                    masked_evidence=f"<{self.name}:{candidate.type}:{fingerprint}>",
                    fingerprint=fingerprint,
                )
            )
        return detections


def _secret_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(pattern.capture_group)
            if pattern.validator is not None and not pattern.validator(value):
                continue
            start, end = match.span(pattern.capture_group)
            candidates.append(
                _Candidate(
                    start=start,
                    end=end,
                    type=pattern.type,
                    confidence=pattern.confidence,
                    priority=pattern.priority,
                )
            )
    return candidates
