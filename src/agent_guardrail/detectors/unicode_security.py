"""Deterministic Unicode control, formatting, and confusable detection."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

MAX_UNICODE_SECURITY_DETECTIONS = 64

# Newline, carriage return, and horizontal tab are ordinary text layout. Other
# C0/C1 controls remain security-relevant facts.
_ALLOWED_TEXT_CONTROLS = frozenset({"\t", "\n", "\r"})
_BIDI_CONTROLS = frozenset(
    {
        "\u061c",  # ARABIC LETTER MARK
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    }
)
_ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)

# A deliberately small UTS #39-inspired high-risk skeleton. It only emits a
# confusable fact when a token mixes Latin with one of these Greek/Cyrillic
# lookalikes, which avoids labelling ordinary non-Latin text as malicious.
_CONFUSABLE_TO_ASCII = {
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "ο": "o",
    "ρ": "p",
    "υ": "y",
    "χ": "x",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
}

UNICODE_SECURITY_TYPES = frozenset(
    {
        "bidi_control",
        "control_character",
        "format_control",
        "mixed_script_confusable",
        "zero_width",
    }
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    type: str
    confidence: float
    priority: int


class UnicodeSecurityDetector:
    """Report Unicode facts that can hide or visually reorder security text."""

    name = "unicode_security"
    version = "2"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        candidates = [*_character_candidates(text), *_confusable_candidates(text)]
        ordered = sorted(
            candidates,
            key=lambda item: (item.start, -item.priority, -(item.end - item.start), item.type),
        )
        detections: list[Detection] = []
        occupied: list[tuple[int, int]] = []
        for candidate in ordered:
            if any(
                candidate.start < occupied_end and candidate.end > occupied_start
                for occupied_start, occupied_end in occupied
            ):
                continue
            if len(detections) >= MAX_UNICODE_SECURITY_DETECTIONS:
                raise ValueError("Unicode security detector result limit exceeded")
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
            occupied.append((candidate.start, candidate.end))
        return detections


def _character_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for index, character in enumerate(text):
        if character in _BIDI_CONTROLS:
            candidates.append(_Candidate(index, index + 1, "bidi_control", 0.99, 40))
        elif character in _ZERO_WIDTH:
            candidates.append(_Candidate(index, index + 1, "zero_width", 0.96, 30))
        elif unicodedata.category(character) == "Cf":
            candidates.append(_Candidate(index, index + 1, "format_control", 0.90, 20))
        elif (
            unicodedata.category(character) in {"Cc", "Cs"}
            and character not in _ALLOWED_TEXT_CONTROLS
        ):
            candidates.append(_Candidate(index, index + 1, "control_character", 0.98, 30))
    return candidates


def _confusable_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        has_latin = any(_script(character) == "latin" for character in token)
        has_confusable = any(character in _CONFUSABLE_TO_ASCII for character in token)
        if has_latin and has_confusable:
            candidates.append(
                _Candidate(
                    match.start(),
                    match.end(),
                    "mixed_script_confusable",
                    0.88,
                    10,
                )
            )
    return candidates


def _script(character: str) -> str:
    name = unicodedata.name(character, "")
    if name.startswith("LATIN "):
        return "latin"
    if name.startswith("GREEK "):
        return "greek"
    if name.startswith("CYRILLIC "):
        return "cyrillic"
    return "other"
