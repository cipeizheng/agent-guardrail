"""Shared bounded execution for reviewed fixed-pattern detectors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from re import Pattern

from agent_guardrail.models import Detection, DetectionContext

MAX_PATTERN_DETECTIONS = 64


@dataclass(frozen=True, slots=True)
class DetectionPattern:
    """One immutable, code-reviewed detector pattern."""

    type: str
    regex: Pattern[str]
    confidence: float
    priority: int = 0


def detect_patterns(
    text: str,
    *,
    context: DetectionContext,
    detector: str,
    detector_version: str,
    patterns: tuple[DetectionPattern, ...],
) -> list[Detection]:
    """Return deterministic detections without losing overlapping fact types.

    Overlapping patterns of the same type are alternatives and collapse to the
    highest-priority occurrence. Different types remain independent facts so a
    broad match cannot hide a higher-signal type selected by Policy.
    """

    candidates = [
        (match.start(), match.end(), pattern)
        for pattern in patterns
        for match in pattern.regex.finditer(text)
    ]
    preferred = sorted(
        candidates,
        key=lambda candidate: (
            -candidate[2].priority,
            candidate[0],
            -(candidate[1] - candidate[0]),
            candidate[2].type,
        ),
    )
    selected: list[tuple[int, int, DetectionPattern]] = []
    occupied_by_type: dict[str, list[tuple[int, int]]] = {}
    for start, end, pattern in preferred:
        overlaps = any(
            start < occupied_end and end > occupied_start
            for occupied_start, occupied_end in occupied_by_type.get(pattern.type, [])
        )
        if overlaps:
            continue
        if len(selected) >= MAX_PATTERN_DETECTIONS:
            raise ValueError("fixed-pattern detector result limit exceeded")
        selected.append((start, end, pattern))
        occupied_by_type.setdefault(pattern.type, []).append((start, end))

    detections: list[Detection] = []
    for start, end, pattern in sorted(
        selected,
        key=lambda candidate: (candidate[0], candidate[1], candidate[2].type),
    ):
        fingerprint = occurrence_fingerprint(
            context=context,
            detector=detector,
            detector_version=detector_version,
            detection_type=pattern.type,
            start=start,
            end=end,
        )
        detections.append(
            Detection(
                type=pattern.type,
                detector=detector,
                detector_version=detector_version,
                confidence=pattern.confidence,
                start=start,
                end=end,
                masked_evidence=f"<{detector}:{pattern.type}:{fingerprint}>",
                fingerprint=fingerprint,
            )
        )
    return detections


def occurrence_fingerprint(
    *,
    context: DetectionContext,
    detector: str,
    detector_version: str,
    detection_type: str,
    start: int,
    end: int,
) -> str:
    """Build a payload-free fingerprint bound to one detector occurrence."""

    material = json.dumps(
        (
            detector,
            detector_version,
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
