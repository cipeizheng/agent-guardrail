"""Deterministic detection of a deliberately small set of PII shapes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from re import Pattern
from typing import Literal

from agent_guardrail.models import Detection, DetectionContext

PIIEntityType = Literal[
    "email_address",
    "phone_number",
    "us_ssn",
    "credit_card",
    "cn_resident_id",
    "cn_mobile_phone",
]


@dataclass(frozen=True, slots=True)
class PIIPattern:
    """A named, version-controlled PII pattern."""

    type: PIIEntityType
    regex: Pattern[str]
    confidence: float


PII_PATTERNS: tuple[PIIPattern, ...] = (
    PIIPattern(
        type="email_address",
        regex=re.compile(
            r"(?<![A-Za-z0-9._%+-])"
            r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
            r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
            r"(?![A-Za-z0-9_-])"
        ),
        confidence=0.95,
    ),
    PIIPattern(
        type="us_ssn",
        regex=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}(?P<ssn_separator>[- ])"
            r"(?!00)\d{2}(?P=ssn_separator)(?!0000)\d{4}\b"
        ),
        confidence=0.98,
    ),
    PIIPattern(
        type="phone_number",
        regex=re.compile(
            r"(?<!\d)(?:\+?1[ .-])?"
            r"(?:\([2-9]\d{2}\)[ .-]?[2-9]\d{2}"
            r"(?P<parenthesized_separator>[ .-])\d{4}|"
            r"[2-9]\d{2}(?P<plain_separator>[ .-])[2-9]\d{2}"
            r"(?P=plain_separator)\d{4})(?!\d)"
        ),
        confidence=0.85,
    ),
    PIIPattern(
        type="cn_mobile_phone",
        regex=re.compile(
            r"(?<![0-9A-Za-z])(?:\+?86[ -]?)?"
            r"(?:1[3-9]\d{9}|1[3-9]\d(?P<cn_mobile_separator>[ -])"
            r"\d{4}(?P=cn_mobile_separator)\d{4})(?![0-9A-Za-z])"
        ),
        confidence=0.9,
    ),
)

_CN_RESIDENT_ID_CANDIDATE = re.compile(r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])")
_CREDIT_CARD_CANDIDATE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")

_CN_MAINLAND_PROVINCE_CODES = frozenset(
    {
        "11",
        "12",
        "13",
        "14",
        "15",
        "21",
        "22",
        "23",
        "31",
        "32",
        "33",
        "34",
        "35",
        "36",
        "37",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "50",
        "51",
        "52",
        "53",
        "54",
        "61",
        "62",
        "63",
        "64",
        "65",
    }
)
_CN_RESIDENT_ID_WEIGHTS = (
    7,
    9,
    10,
    5,
    8,
    4,
    2,
    1,
    6,
    3,
    7,
    9,
    10,
    5,
    8,
    4,
    2,
)
_CN_RESIDENT_ID_CHECK_CHARACTERS = "10X98765432"


class PIIDetector:
    """Find selected PII shapes without returning or hashing their raw values."""

    name = "pii"
    version = "2"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        candidates: list[tuple[int, int, PIIEntityType, float, int]] = []
        for pattern in PII_PATTERNS:
            candidates.extend(
                (match.start(), match.end(), pattern.type, pattern.confidence, 0)
                for match in pattern.regex.finditer(text)
            )

        for match in _CN_RESIDENT_ID_CANDIDATE.finditer(text):
            if _passes_cn_resident_id_validation(match.group(0)):
                candidates.append((match.start(), match.end(), "cn_resident_id", 0.99, 100))

        for match in _CREDIT_CARD_CANDIDATE.finditer(text):
            digits = "".join(character for character in match.group(0) if character.isdigit())
            if _passes_luhn(digits):
                candidates.append((match.start(), match.end(), "credit_card", 0.99, 0))

        detections: list[Detection] = []
        occupied_spans: list[tuple[int, int]] = []
        ordered = sorted(
            candidates,
            key=lambda candidate: (
                candidate[0],
                -candidate[4],
                -(candidate[1] - candidate[0]),
                candidate[2],
            ),
        )
        for start, end, entity_type, confidence, _priority in ordered:
            if any(
                start < occupied_end and end > occupied_start
                for occupied_start, occupied_end in occupied_spans
            ):
                continue
            fingerprint = _occurrence_fingerprint(
                context=context,
                entity_type=entity_type,
                start=start,
                end=end,
            )
            detections.append(
                Detection(
                    type=entity_type,
                    detector=self.name,
                    detector_version=self.version,
                    confidence=confidence,
                    start=start,
                    end=end,
                    masked_evidence=f"<pii:{entity_type}:{fingerprint}>",
                    fingerprint=fingerprint,
                )
            )
            occupied_spans.append((start, end))

        return detections


def _passes_cn_resident_id_validation(value: str) -> bool:
    master_number = value[:17]
    if value[:2] not in _CN_MAINLAND_PROVINCE_CODES:
        return False

    birth_date = value[6:14]
    try:
        date(
            year=int(birth_date[:4]),
            month=int(birth_date[4:6]),
            day=int(birth_date[6:8]),
        )
    except ValueError:
        return False

    checksum = sum(
        int(character) * weight
        for character, weight in zip(master_number, _CN_RESIDENT_ID_WEIGHTS, strict=True)
    )
    expected = _CN_RESIDENT_ID_CHECK_CHARACTERS[checksum % 11]
    return value[-1].upper() == expected


def _passes_luhn(digits: str) -> bool:
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


def _occurrence_fingerprint(
    *,
    context: DetectionContext,
    entity_type: PIIEntityType,
    start: int,
    end: int,
) -> str:
    """Identify an occurrence without making low-entropy PII enumerable."""

    material = (
        f"{context.trace_id}:{context.event_id}:{context.phase.value}:{entity_type}:{start}:{end}"
    )
    return sha256(material.encode("utf-8")).hexdigest()[:16]
