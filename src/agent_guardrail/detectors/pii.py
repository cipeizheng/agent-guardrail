"""Deterministic PII recognizers plus an explicit optional NLP backend."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from re import Pattern
from typing import Literal, Protocol, TypeGuard, runtime_checkable

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

PIIEntityType = Literal[
    "email_address",
    "phone_number",
    "us_ssn",
    "credit_card",
    "cn_resident_id",
    "cn_mobile_phone",
    "iban_code",
    "ip_address",
    "crypto_address",
    "us_bank_number",
    "us_driver_license",
    "us_itin",
    "us_passport",
    "uk_nhs",
    "person",
    "location",
    "nrp",
    "organization",
    "date_time",
    "medical_license",
    "url",
]

PII_ENTITY_TYPES: frozenset[PIIEntityType] = frozenset(
    {
        "email_address",
        "phone_number",
        "us_ssn",
        "credit_card",
        "cn_resident_id",
        "cn_mobile_phone",
        "iban_code",
        "ip_address",
        "crypto_address",
        "us_bank_number",
        "us_driver_license",
        "us_itin",
        "us_passport",
        "uk_nhs",
        "person",
        "location",
        "nrp",
        "organization",
        "date_time",
        "medical_license",
        "url",
    }
)

PIIValidator = Callable[[str], bool]
MAX_PII_DETECTIONS = 64


@dataclass(frozen=True, slots=True)
class PIIPattern:
    """One local, code-reviewed PII recognizer."""

    type: PIIEntityType
    regex: Pattern[str]
    confidence: float
    priority: int = 0
    capture_group: int | str = 0
    validator: PIIValidator | None = None
    context_terms: tuple[str, ...] = ()
    context_window: int = 48


@dataclass(frozen=True, slots=True)
class PIIBackendResult:
    """A payload-free result with exact Python-character offsets into the input."""

    type: PIIEntityType
    start: int
    end: int
    confidence: float

    def __post_init__(self) -> None:
        if not isinstance(self.type, str) or self.type not in PII_ENTITY_TYPES:
            raise ValueError("PII backend result type is not published")
        if (
            isinstance(self.start, bool)
            or isinstance(self.end, bool)
            or not isinstance(self.start, int)
            or not isinstance(self.end, int)
            or self.start < 0
            or self.end <= self.start
        ):
            raise ValueError("PII backend result span is invalid")
        if (
            type(self.confidence) is not float
            or not math.isfinite(self.confidence)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("PII backend result confidence is invalid")


@runtime_checkable
class PIIBackend(Protocol):
    """A deployment-owned PII backend with a fixed model and profile."""

    name: str
    version: str
    detection_types: frozenset[PIIEntityType]

    async def analyze(
        self,
        text: str,
    ) -> list[PIIBackendResult] | tuple[PIIBackendResult, ...]: ...


PRESIDIO_DEFAULT_ENTITY_MAPPING: tuple[tuple[str, PIIEntityType], ...] = (
    ("EMAIL_ADDRESS", "email_address"),
    ("PHONE_NUMBER", "phone_number"),
    ("US_SSN", "us_ssn"),
    ("CREDIT_CARD", "credit_card"),
    ("IBAN_CODE", "iban_code"),
    ("IP_ADDRESS", "ip_address"),
    ("CRYPTO", "crypto_address"),
    ("US_BANK_NUMBER", "us_bank_number"),
    ("US_DRIVER_LICENSE", "us_driver_license"),
    ("US_ITIN", "us_itin"),
    ("US_PASSPORT", "us_passport"),
    ("UK_NHS", "uk_nhs"),
    ("PERSON", "person"),
    ("LOCATION", "location"),
    ("NRP", "nrp"),
    ("ORGANIZATION", "organization"),
    ("DATE_TIME", "date_time"),
    ("MEDICAL_LICENSE", "medical_license"),
    ("URL", "url"),
)


@dataclass(frozen=True, slots=True)
class PresidioPIIProfile:
    """Deployment-fixed Presidio language, threshold, and finite label map."""

    language: str = "en"
    threshold: float = 0.5
    entity_mapping: tuple[
        tuple[str, PIIEntityType], ...
    ] = PRESIDIO_DEFAULT_ENTITY_MAPPING

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z]{2,8}(?:-[a-z0-9]{2,8})?", self.language):
            raise ValueError("Presidio profile language is invalid")
        if (
            type(self.threshold) is not float
            or not math.isfinite(self.threshold)
            or not 0.0 <= self.threshold < 1.0
        ):
            raise ValueError("Presidio profile threshold must be a float in [0, 1)")
        if (
            not isinstance(self.entity_mapping, tuple)
            or not self.entity_mapping
            or len(self.entity_mapping) > len(PII_ENTITY_TYPES)
        ):
            raise ValueError("Presidio profile entity mapping must not be empty")
        labels: set[str] = set()
        for item in self.entity_mapping:
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError("Presidio profile entity mapping is invalid")
            label, detection_type = item
            if (
                not isinstance(label, str)
                or not isinstance(detection_type, str)
                or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", label)
                or label in labels
                or detection_type not in PII_ENTITY_TYPES
            ):
                raise ValueError("Presidio profile entity mapping is invalid")
            labels.add(label)

    @property
    def mapping(self) -> dict[str, PIIEntityType]:
        return dict(self.entity_mapping)


class PresidioAnalyzerBackend:
    """Adapt a preconfigured Presidio AnalyzerEngine without importing models.

    The deployment constructs the analyzer, installs recognizers, and pins the
    NLP model. This adapter never downloads a model or lets Policy choose a
    language, recognizer, label, file, or endpoint.
    """

    def __init__(
        self,
        analyzer: object,
        *,
        backend_name: str,
        backend_version: str,
        profile: PresidioPIIProfile | None = None,
    ) -> None:
        analyze = getattr(analyzer, "analyze", None)
        if not callable(analyze):
            raise TypeError("analyzer must provide a callable analyze method")
        if (
            not isinstance(backend_name, str)
            or not backend_name.strip()
            or not isinstance(backend_version, str)
            or not backend_version.strip()
        ):
            raise ValueError("PII backend identity must be non-empty")
        if profile is not None and not isinstance(profile, PresidioPIIProfile):
            raise TypeError("profile must be a PresidioPIIProfile")
        self.name = backend_name.strip()
        self._analyze = analyze
        self._profile = profile if profile is not None else PresidioPIIProfile()
        self.detection_types = frozenset(self._profile.mapping.values())
        profile_material = json.dumps(
            (
                backend_version.strip(),
                self._profile.language,
                self._profile.threshold,
                self._profile.entity_mapping,
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        profile_fingerprint = sha256(profile_material.encode("utf-8")).hexdigest()[:12]
        self.version = f"{backend_version.strip()}+profile.{profile_fingerprint}"

    async def analyze(self, text: str) -> list[PIIBackendResult]:
        mapping = self._profile.mapping
        raw = await asyncio.to_thread(
            self._analyze,
            text=text,
            language=self._profile.language,
            entities=list(mapping),
        )
        if inspect.isawaitable(raw):
            raw = await raw
        if not _is_builtin_result_collection(raw):
            raise TypeError("PII backend returned an invalid result collection")
        if len(raw) > MAX_PII_DETECTIONS:
            raise ValueError("PII backend result limit exceeded")

        results: list[PIIBackendResult] = []
        for item in raw:
            label = _backend_field(item, "entity_type")
            start = _backend_field(item, "start")
            end = _backend_field(item, "end")
            score = _backend_field(item, "score")
            if (
                not isinstance(label, str)
                or label not in mapping
                or isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(end, bool)
                or not isinstance(end, int)
                or isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(float(score))
            ):
                raise TypeError("PII backend returned an invalid result")
            confidence = float(score)
            if not 0.0 <= confidence <= 1.0:
                raise TypeError("PII backend returned an invalid result")
            if confidence <= self._profile.threshold:
                continue
            results.append(
                PIIBackendResult(
                    type=mapping[label],
                    start=start,
                    end=end,
                    confidence=confidence,
                )
            )
        return sorted(results, key=lambda item: (item.start, item.end, item.type))


def _backend_field(item: object, name: str) -> object:
    if isinstance(item, Mapping):
        return item.get(name)
    return getattr(item, name, None)


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
_CN_RESIDENT_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_RESIDENT_ID_CHECK_CHARACTERS = "10X98765432"

_IBAN_LENGTHS = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "CH": 21,
    "CR": 22,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IS": 26,
    "IT": 27,
    "JO": 30,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PL": 28,
    "PS": 29,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "RS": 22,
    "SA": 24,
    "SC": 31,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "ST": 25,
    "SV": 28,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "VA": 22,
    "VG": 24,
    "XK": 20,
}

_PASSPORT_CONTEXT = (
    "passport",
    "pasaporte",
    "passeport",
    "reisepass",
    "护照",
)
_DRIVER_LICENSE_CONTEXT = (
    "driver license",
    "driver's license",
    "driving licence",
    "license number",
    "permis de conduire",
    "驾照",
    "驾驶证",
)
_BANK_ACCOUNT_CONTEXT = (
    "account number",
    "bank account",
    "银行账号",
    "银行账户",
)
_BANK_ROUTING_CONTEXT = (
    "routing number",
    "aba number",
    "路由号码",
)
_NHS_CONTEXT = ("nhs", "national health service", "英国医疗号")


def _passes_cn_resident_id_validation(value: str) -> bool:
    master_number = value[:17]
    if value[:2] not in _CN_MAINLAND_PROVINCE_CODES:
        return False
    try:
        date(
            year=int(value[6:10]),
            month=int(value[10:12]),
            day=int(value[12:14]),
        )
    except ValueError:
        return False
    checksum = sum(
        int(character) * weight
        for character, weight in zip(master_number, _CN_RESIDENT_ID_WEIGHTS, strict=True)
    )
    return value[-1].upper() == _CN_RESIDENT_ID_CHECK_CHARACTERS[checksum % 11]


def _passes_luhn(value: str) -> bool:
    digits = "".join(character for character in value if character.isdigit())
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _passes_international_phone(value: str) -> bool:
    digits = "".join(character for character in value if character.isdigit())
    return 8 <= len(digits) <= 15 and len(set(digits)) >= 4


def _passes_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _passes_iban(value: str) -> bool:
    compact = "".join(character for character in value.upper() if character != " ")
    expected_length = _IBAN_LENGTHS.get(compact[:2])
    if expected_length is None or len(compact) != expected_length or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        character if character.isdigit() else str(ord(character) - ord("A") + 10)
        for character in rearranged
    )
    return int(numeric) % 97 == 1


def _passes_us_routing_number(value: str) -> bool:
    if len(value) != 9 or len(set(value)) == 1:
        return False
    digits = [int(character) for character in value]
    checksum = (
        3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + digits[2]
        + digits[5]
        + digits[8]
    )
    return checksum % 10 == 0


def _passes_account_number(value: str) -> bool:
    return 8 <= len(value) <= 17 and len(set(value)) >= 4


def _passes_uk_nhs_number(value: str) -> bool:
    digits = "".join(character for character in value if character.isdigit())
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    remainder = sum(int(digits[index]) * (10 - index) for index in range(9)) % 11
    check_digit = 11 - remainder
    if check_digit == 11:
        check_digit = 0
    return check_digit != 10 and check_digit == int(digits[-1])


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _passes_base58check(value: str) -> bool:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_ALPHABET.index(character)
    except ValueError:
        return False
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    decoded = b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded
    if len(decoded) != 25:
        return False
    checksum = sha256(sha256(decoded[:-4]).digest()).digest()[:4]
    return decoded[-4:] == checksum


def _not_uniform_identifier(value: str) -> bool:
    compact = "".join(character for character in value if character.isalnum())
    return len(set(compact.casefold())) >= 4


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
        priority=60,
    ),
    PIIPattern(
        type="us_ssn",
        regex=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}(?P<ssn_separator>[- ])"
            r"(?!00)\d{2}(?P=ssn_separator)(?!0000)\d{4}\b"
        ),
        confidence=0.98,
        priority=80,
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
        priority=40,
    ),
    PIIPattern(
        type="cn_mobile_phone",
        regex=re.compile(
            r"(?<![0-9A-Za-z])(?:\+?86[ -]?)?"
            r"(?:1[3-9]\d{9}|1[3-9]\d(?P<cn_mobile_separator>[ -])"
            r"\d{4}(?P=cn_mobile_separator)\d{4})(?![0-9A-Za-z])"
        ),
        confidence=0.90,
        priority=60,
    ),
    PIIPattern(
        type="phone_number",
        regex=re.compile(
            r"(?<![\w+])(?P<international_phone>\+[1-9]\d{0,2}"
            r"(?:[ .-]?\(?\d{1,4}\)?){2,6})(?!\w)"
        ),
        confidence=0.82,
        priority=20,
        capture_group="international_phone",
        validator=_passes_international_phone,
    ),
    PIIPattern(
        type="cn_resident_id",
        regex=re.compile(r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])"),
        confidence=0.99,
        priority=100,
        validator=_passes_cn_resident_id_validation,
    ),
    PIIPattern(
        type="credit_card",
        regex=re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)"),
        confidence=0.99,
        priority=90,
        validator=_passes_luhn,
    ),
    PIIPattern(
        type="us_itin",
        regex=re.compile(
            r"(?<!\d)9\d{2}(?P<itin_separator>[- ])"
            r"(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])"
            r"(?P=itin_separator)\d{4}(?!\d)"
        ),
        confidence=0.98,
        priority=80,
    ),
    PIIPattern(
        type="iban_code",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?P<iban>[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30})"
            r"(?![A-Za-z0-9])"
        ),
        confidence=0.99,
        priority=90,
        capture_group="iban",
        validator=_passes_iban,
    ),
    PIIPattern(
        type="iban_code",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?P<spaced_iban>[A-Za-z]{2}\d{2}"
            r"(?: [A-Za-z0-9]{2,4}){3,8})(?![A-Za-z0-9])"
        ),
        confidence=0.99,
        priority=90,
        capture_group="spaced_iban",
        validator=_passes_iban,
    ),
    PIIPattern(
        type="ip_address",
        regex=re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        confidence=0.95,
        priority=50,
        validator=_passes_ip_address,
    ),
    PIIPattern(
        type="ip_address",
        regex=re.compile(
            r"(?<![0-9A-Fa-f:.])(?=[0-9A-Fa-f:]{2,45}(?![0-9A-Fa-f:.]))"
            r"(?P<ipv6>[0-9A-Fa-f]*:[0-9A-Fa-f:]+)(?![0-9A-Fa-f:.])"
        ),
        confidence=0.95,
        priority=50,
        capture_group="ipv6",
        validator=_passes_ip_address,
    ),
    PIIPattern(
        type="crypto_address",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?P<bitcoin>[13][a-km-zA-HJ-NP-Z1-9]{25,34})"
            r"(?![A-Za-z0-9])"
        ),
        confidence=0.99,
        priority=90,
        capture_group="bitcoin",
        validator=_passes_base58check,
    ),
    PIIPattern(
        type="us_bank_number",
        regex=re.compile(r"(?<!\d)\d{9}(?!\d)"),
        confidence=0.94,
        priority=75,
        validator=_passes_us_routing_number,
        context_terms=_BANK_ROUTING_CONTEXT,
    ),
    PIIPattern(
        type="us_bank_number",
        regex=re.compile(r"(?<!\d)\d{8,17}(?!\d)"),
        confidence=0.82,
        priority=70,
        validator=_passes_account_number,
        context_terms=_BANK_ACCOUNT_CONTEXT,
    ),
    PIIPattern(
        type="us_passport",
        regex=re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]\d{8}|\d{9})(?![A-Za-z0-9])"),
        confidence=0.82,
        priority=75,
        validator=_not_uniform_identifier,
        context_terms=_PASSPORT_CONTEXT,
    ),
    PIIPattern(
        type="us_driver_license",
        regex=re.compile(
            r"(?<![A-Za-z0-9])(?:[A-Z]\d{7,8}|\d{7,9})(?![A-Za-z0-9])"
        ),
        confidence=0.78,
        priority=75,
        validator=_not_uniform_identifier,
        context_terms=_DRIVER_LICENSE_CONTEXT,
    ),
    PIIPattern(
        type="uk_nhs",
        regex=re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{4}(?!\d)"),
        confidence=0.98,
        priority=80,
        validator=_passes_uk_nhs_number,
        context_terms=_NHS_CONTEXT,
    ),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    type: PIIEntityType
    confidence: float
    priority: int


class PIIDetector:
    """Find local PII shapes and optional deployment-profile NLP facts."""

    name = "pii"
    version = "4"

    def __init__(self, backend: PIIBackend | None = None) -> None:
        if backend is not None:
            if not isinstance(backend, PIIBackend):
                raise TypeError("backend must implement PIIBackend")
            if (
                not isinstance(backend.name, str)
                or not backend.name.strip()
                or not isinstance(backend.version, str)
                or not backend.version.strip()
                or not isinstance(backend.detection_types, frozenset)
                or not backend.detection_types
                or not backend.detection_types.issubset(PII_ENTITY_TYPES)
            ):
                raise ValueError("PII backend identity must be non-empty")
            backend_material = json.dumps(
                (
                    backend.name.strip(),
                    backend.version.strip(),
                    sorted(backend.detection_types),
                ),
                ensure_ascii=True,
                separators=(",", ":"),
            )
            backend_fingerprint = sha256(backend_material.encode("utf-8")).hexdigest()[:12]
            self.version = f"4+backend.{backend_fingerprint}"
        self._backend = backend

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        candidates = _local_candidates(text)
        if self._backend is not None:
            raw_backend_results = await self._backend.analyze(text)
            if not _is_builtin_result_collection(raw_backend_results):
                raise TypeError("PII backend returned an invalid result collection")
            if len(raw_backend_results) > MAX_PII_DETECTIONS:
                raise ValueError("PII backend result limit exceeded")
            for result in raw_backend_results:
                if (
                    not isinstance(result, PIIBackendResult)
                    or result.type not in self._backend.detection_types
                    or result.end > len(text)
                ):
                    raise TypeError("PII backend returned an invalid result")
                candidates.append(
                    _Candidate(
                        start=result.start,
                        end=result.end,
                        type=result.type,
                        confidence=result.confidence,
                        priority=0,
                    )
                )

        selected: list[_Candidate] = []
        occupied_by_type: dict[PIIEntityType, list[tuple[int, int]]] = {}
        for candidate in sorted(
            candidates,
            key=lambda item: (
                -item.priority,
                item.start,
                -(item.end - item.start),
                item.type,
                -item.confidence,
            ),
        ):
            occupied = occupied_by_type.setdefault(candidate.type, [])
            if any(
                candidate.start < occupied_end and candidate.end > occupied_start
                for occupied_start, occupied_end in occupied
            ):
                continue
            selected.append(candidate)
            occupied.append((candidate.start, candidate.end))

        if len(selected) > MAX_PII_DETECTIONS:
            raise ValueError("PII detector result limit exceeded")

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


def _is_builtin_result_collection(
    value: object,
) -> TypeGuard[list[object] | tuple[object, ...]]:
    return type(value) is list or type(value) is tuple


def _local_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for pattern in PII_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(pattern.capture_group)
            start, end = match.span(pattern.capture_group)
            if pattern.validator is not None and not pattern.validator(value):
                continue
            if pattern.context_terms and not _has_context(
                text,
                start=start,
                end=end,
                terms=pattern.context_terms,
                window=pattern.context_window,
            ):
                continue
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


def _has_context(
    text: str,
    *,
    start: int,
    end: int,
    terms: tuple[str, ...],
    window: int,
) -> bool:
    nearby = text[max(0, start - window) : min(len(text), end + window)].casefold()
    return any(term.casefold() in nearby for term in terms)


def _occurrence_fingerprint(
    *,
    context: DetectionContext,
    entity_type: PIIEntityType,
    start: int,
    end: int,
) -> str:
    """Compatibility wrapper for the payload-free shared fingerprint."""

    return occurrence_fingerprint(
        context=context,
        detector=PIIDetector.name,
        detector_version=PIIDetector.version,
        detection_type=entity_type,
        start=start,
        end=end,
    )
