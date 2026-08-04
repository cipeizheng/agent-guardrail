"""Deterministic local secret detection with audit-safe evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from re import Pattern

from agent_guardrail.models import Detection, DetectionContext


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """A named, version-controlled secret pattern."""

    type: str
    regex: Pattern[str]


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        type="private_key",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    SecretPattern(
        type="github_token",
        regex=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    ),
    SecretPattern(
        type="openai_api_key",
        regex=re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    ),
    SecretPattern(
        type="bearer_token",
        regex=re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    ),
    SecretPattern(
        type="assigned_secret",
        regex=re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9._~+/=-]{12,})",
            re.IGNORECASE,
        ),
    ),
)


class SecretDetector:
    """Find common credential shapes without returning their raw values."""

    name = "secrets"
    version = "1"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        del context  # Detection is deliberately content-only and therefore cacheable.
        detections: list[Detection] = []
        occupied_spans: list[tuple[int, int]] = []

        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(text):
                start, end = match.span()
                if any(
                    start < occupied_end and end > occupied_start
                    for occupied_start, occupied_end in occupied_spans
                ):
                    continue
                raw_match = match.group(0)
                fingerprint = sha256(raw_match.encode("utf-8")).hexdigest()[:16]
                detections.append(
                    Detection(
                        type=pattern.type,
                        detector=self.name,
                        detector_version=self.version,
                        confidence=0.95,
                        start=start,
                        end=end,
                        masked_evidence=f"<{pattern.type}:{fingerprint}>",
                        fingerprint=fingerprint,
                    )
                )
                occupied_spans.append((start, end))

        return sorted(detections, key=lambda detection: (detection.start or 0, detection.end or 0))
