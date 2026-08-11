"""Shared bounded execution for reviewed fixed-pattern detectors."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from re import Pattern

from agent_guardrail.models import Detection, DetectionContext


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
    """Return deterministic, non-overlapping detections without raw evidence."""

    candidates = [
        (match.start(), match.end(), pattern)
        for pattern in patterns
        for match in pattern.regex.finditer(text)
    ]
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            candidate[0],
            -candidate[2].priority,
            -(candidate[1] - candidate[0]),
            candidate[2].type,
        ),
    )
    detections: list[Detection] = []
    occupied: list[tuple[int, int]] = []
    for start, end, pattern in ordered:
        overlaps = any(
            start < occupied_end and end > occupied_start
            for occupied_start, occupied_end in occupied
        )
        if overlaps:
            continue
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
        occupied.append((start, end))
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

    material = (
        f"{detector}:{detector_version}:{context.trace_id}:{context.event_id}:"
        f"{context.phase.value}:{detection_type}:{start}:{end}"
    )
    return sha256(material.encode("utf-8")).hexdigest()[:16]
