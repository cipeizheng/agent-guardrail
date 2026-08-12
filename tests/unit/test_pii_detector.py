from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import cast

import pytest

from agent_guardrail.detectors.pii import (
    PIIBackend,
    PIIBackendResult,
    PIIDetector,
    PIIEntityType,
    PresidioAnalyzerBackend,
    PresidioPIIProfile,
)
from agent_guardrail.models import DetectionContext, Phase
from tests.support import (
    FAKE_CN_MOBILE,
    FAKE_CN_RESIDENT_ID,
    fake_cn_resident_id,
)

MAX_COMBINED_LOCAL_ENTITIES = 64


def detection_context(*, event_id: str = "event-1") -> DetectionContext:
    return DetectionContext(
        trace_id="trace-1",
        event_id=event_id,
        phase=Phase.PRE_TOOL,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "entity_type"),
    [
        ("customer@example.test", "email_address"),
        ("(415) 555-2671", "phone_number"),
        ("123-45-6789", "us_ssn"),
        ("4242 4242 4242 4242", "credit_card"),
        (FAKE_CN_RESIDENT_ID, "cn_resident_id"),
        (FAKE_CN_MOBILE, "cn_mobile_phone"),
        ("+86 139-0000-0001", "cn_mobile_phone"),
    ],
)
async def test_supported_pii_shapes_are_detected_without_raw_evidence(
    value: str,
    entity_type: str,
) -> None:
    detections = await PIIDetector().detect(
        f"Before {value} after",
        context=detection_context(),
    )

    matching = next(detection for detection in detections if detection.type == entity_type)
    assert matching.masked_evidence.startswith(f"<pii:{entity_type}:")
    assert value not in matching.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "4242 4242 4242 4241",
        "123456789",
        "4155552671",
        "000-12-3456",
        "123-45 6789",
        "415-555.2671",
        "customer.@example.test",
        "not-an-email@localhost",
    ],
)
async def test_unsupported_or_invalid_shapes_are_not_detected(value: str) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert detections == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        FAKE_CN_RESIDENT_ID[:-1] + ("0" if FAKE_CN_RESIDENT_ID[-1] != "0" else "1"),
        fake_cn_resident_id("11000020000230001"),
        fake_cn_resident_id("99000020000101001"),
    ],
)
async def test_invalid_cn_resident_ids_are_not_classified_as_resident_ids(
    value: str,
) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert "cn_resident_id" not in {detection.type for detection in detections}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "129 0000 0001",
        "139-0000 0001",
        "139000000010",
        "prefix13900000001suffix",
    ],
)
async def test_invalid_cn_mobile_shapes_are_not_detected(value: str) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert "cn_mobile_phone" not in {detection.type for detection in detections}


@pytest.mark.asyncio
async def test_occurrence_fingerprint_is_context_bound_not_a_raw_value_hash() -> None:
    detector = PIIDetector()
    first = await detector.detect("customer@example.test", context=detection_context())
    second = await detector.detect(
        "customer@example.test",
        context=detection_context(event_id="event-2"),
    )

    assert first[0].fingerprint != second[0].fingerprint


@pytest.mark.asyncio
async def test_multiple_non_overlapping_entities_are_sorted_by_span() -> None:
    text = "Call (415) 555-2671 or email customer@example.test."

    detections = await PIIDetector().detect(text, context=detection_context())

    assert [detection.type for detection in detections] == [
        "phone_number",
        "email_address",
    ]
    assert [detection.start for detection in detections] == sorted(
        detection.start for detection in detections if detection.start is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "entity_type"),
    [
        ("GB82 WEST 1234 5698 7654 32", "iban_code"),
        ("192.0.2.25", "ip_address"),
        ("2001:db8::25", "ip_address"),
        ("900-70-0000", "us_itin"),
        ("routing number 123456780", "us_bank_number"),
        ("passport A12345678", "us_passport"),
        ("driver's license A12345678", "us_driver_license"),
        ("NHS 943 476 5919", "uk_nhs"),
        ("+44 20 7946 0958", "phone_number"),
    ],
)
async def test_high_value_presidio_style_local_entities_are_detected(
    value: str,
    entity_type: str,
) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    matching = next(item for item in detections if item.type == entity_type)
    assert matching.detector_version == "4"
    assert matching.masked_evidence.startswith(f"<pii:{entity_type}:")
    assert value not in matching.model_dump_json()


def _synthetic_base58check_address() -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = b"\x00" + bytes(range(1, 21))
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    encoded_value = int.from_bytes(payload + checksum, "big")
    encoded = ""
    while encoded_value:
        encoded_value, remainder = divmod(encoded_value, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * (len(payload + checksum) - len((payload + checksum).lstrip(b"\x00"))) + encoded


@pytest.mark.asyncio
async def test_checksum_valid_synthetic_crypto_address_is_detected() -> None:
    value = _synthetic_base58check_address()

    detections = await PIIDetector().detect(value, context=detection_context())

    assert [item.type for item in detections] == ["crypto_address"]
    assert value not in detections[0].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "GB82 WEST 1234 5698 7654 31",
        "999.0.2.25",
        "routing number 123456789",
        "NHS 9434765918",
        "A12345678",
        "123456780",
        "+12 34",
    ],
)
async def test_invalid_checksums_or_missing_identity_context_are_rejected(value: str) -> None:
    assert await PIIDetector().detect(value, context=detection_context()) == []


@pytest.mark.asyncio
async def test_pii_fingerprint_does_not_depend_on_same_length_payload() -> None:
    detector = PIIDetector()

    alice = await detector.detect("alice@example.test", context=detection_context())
    bobby = await detector.detect("bobby@example.test", context=detection_context())

    assert alice[0].fingerprint == bobby[0].fingerprint
    assert "alice@example.test" not in alice[0].model_dump_json()
    assert "bobby@example.test" not in bobby[0].model_dump_json()


@dataclass(frozen=True, slots=True)
class _RawPresidioResult:
    entity_type: str
    start: int
    end: int
    score: float


class _PreloadedAnalyzer:
    def __init__(self, results: list[_RawPresidioResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    def analyze(
        self,
        *,
        text: str,
        language: str,
        entities: list[str],
    ) -> list[_RawPresidioResult]:
        self.calls.append((text, language, tuple(entities)))
        return self.results


class _FixedPIIBackend:
    name = "reviewed-fixed-backend"
    version = "model-sha256-test"
    detection_types: frozenset[PIIEntityType] = frozenset(
        {"email_address", "person"}
    )

    def __init__(self, results: list[PIIBackendResult]) -> None:
        self._results = results

    async def analyze(self, text: str) -> list[PIIBackendResult]:
        del text
        return list(self._results)


@pytest.mark.asyncio
async def test_preconfigured_presidio_backend_maps_only_finite_public_types() -> None:
    analyzer = _PreloadedAnalyzer([_RawPresidioResult("PERSON", 0, 5, 0.91)])
    profile = PresidioPIIProfile(
        language="en",
        threshold=0.7,
        entity_mapping=(("PERSON", "person"),),
    )
    backend = PresidioAnalyzerBackend(
        analyzer,
        backend_name="reviewed-presidio",
        backend_version="model-sha256-test",
        profile=profile,
    )

    detections = await PIIDetector(backend).detect(
        "Alice visited",
        context=detection_context(),
    )

    assert analyzer.calls == [("Alice visited", "en", ("PERSON",))]
    assert [item.type for item in detections] == ["person"]
    assert detections[0].confidence == 0.91
    assert detections[0].detector_version.startswith("4+backend.")
    assert "Alice" not in detections[0].model_dump_json()


@pytest.mark.asyncio
async def test_pii_overlap_deduplication_is_scoped_to_detection_type() -> None:
    text = "alice@example.test"
    results = [
        PIIBackendResult("email_address", 0, len(text), 0.71),
        PIIBackendResult("person", 0, 5, 0.81),
        PIIBackendResult("person", 0, 5, 0.91),
    ]

    async def detect(
        backend_results: list[PIIBackendResult],
    ) -> list[tuple[str, int | None, int | None, float]]:
        backend = _FixedPIIBackend(backend_results)
        detections = await PIIDetector(backend).detect(
            text,
            context=detection_context(),
        )
        return [
            (item.type, item.start, item.end, item.confidence) for item in detections
        ]

    expected = [
        ("person", 0, 5, 0.91),
        ("email_address", 0, len(text), 0.95),
    ]
    assert await detect(results) == expected
    assert await detect(list(reversed(results))) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "expected_types"),
    [
        (
            "bank account 4532015112830366",
            {"credit_card", "us_bank_number"},
        ),
        (
            "+86 139-0000-0001",
            {"cn_mobile_phone", "phone_number"},
        ),
    ],
)
async def test_overlapping_local_pii_types_remain_policy_selectable(
    text: str,
    expected_types: set[str],
) -> None:
    detections = await PIIDetector().detect(text, context=detection_context())

    assert {item.type for item in detections}.issuperset(expected_types)


@pytest.mark.asyncio
async def test_presidio_backend_preserves_python_character_offsets_for_unicode() -> None:
    analyzer = _PreloadedAnalyzer([_RawPresidioResult("PERSON", 2, 7, 0.91)])
    backend = PresidioAnalyzerBackend(
        analyzer,
        backend_name="reviewed-presidio",
        backend_version="model-sha256-test",
        profile=PresidioPIIProfile(entity_mapping=(("PERSON", "person"),)),
    )

    detections = await PIIDetector(backend).detect(
        "你好Alice到访",
        context=detection_context(),
    )

    assert [(item.start, item.end) for item in detections] == [(2, 7)]


@pytest.mark.asyncio
async def test_presidio_backend_rejects_unmapped_label_without_echoing_it() -> None:
    raw_label = "UNREVIEWED_PRIVATE_LABEL"
    analyzer = _PreloadedAnalyzer([_RawPresidioResult(raw_label, 0, 5, 0.99)])
    backend = PresidioAnalyzerBackend(
        analyzer,
        backend_name="reviewed-presidio",
        backend_version="model-sha256-test",
        profile=PresidioPIIProfile(entity_mapping=(("PERSON", "person"),)),
    )

    with pytest.raises(TypeError) as raised:
        await PIIDetector(backend).detect("Alice", context=detection_context())

    assert raw_label not in str(raised.value)


@pytest.mark.asyncio
async def test_pii_detector_and_backend_results_are_hard_bounded() -> None:
    local_text = " ".join(f"person{index}@example.test" for index in range(65))
    with pytest.raises(ValueError, match="result limit"):
        await PIIDetector().detect(local_text, context=detection_context())

    analyzer = _PreloadedAnalyzer(
        [_RawPresidioResult("PERSON", 0, 1, 0.9) for _ in range(65)]
    )
    backend = PresidioAnalyzerBackend(
        analyzer,
        backend_name="reviewed-presidio",
        backend_version="model-sha256-test",
        profile=PresidioPIIProfile(entity_mapping=(("PERSON", "person"),)),
    )
    with pytest.raises(ValueError, match="result limit"):
        await PIIDetector(backend).detect("A", context=detection_context())

    combined_text = " ".join(
        f"person{index}@example.test" for index in range(MAX_COMBINED_LOCAL_ENTITIES)
    )
    combined_backend = _FixedPIIBackend(
        [PIIBackendResult("person", 0, 1, 0.9)]
    )
    with pytest.raises(ValueError, match="result limit"):
        await PIIDetector(combined_backend).detect(
            combined_text,
            context=detection_context(),
        )


@pytest.mark.asyncio
async def test_presidio_backend_does_not_iterate_sequence_subclasses() -> None:
    class _HostileList(list[object]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("untrusted collection must not be iterated")

    class _HostileAnalyzer:
        def analyze(self, **_kwargs: object) -> object:
            return _HostileList([_RawPresidioResult("PERSON", 0, 1, 0.9)])

    backend = PresidioAnalyzerBackend(
        _HostileAnalyzer(),
        backend_name="reviewed-presidio",
        backend_version="model-sha256-test",
        profile=PresidioPIIProfile(entity_mapping=(("PERSON", "person"),)),
    )

    with pytest.raises(TypeError, match="invalid result collection"):
        await backend.analyze("A")


@pytest.mark.asyncio
async def test_pii_detector_does_not_iterate_backend_sequence_subclasses() -> None:
    class _HostileList(list[object]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise AssertionError("untrusted collection must not be iterated")

    class _HostileBackend:
        name = "reviewed-backend"
        version = "model-sha256-test"
        detection_types = frozenset({"person"})

        async def analyze(self, _text: str) -> object:
            return _HostileList([])

    detector = PIIDetector(cast(PIIBackend, _HostileBackend()))

    with pytest.raises(TypeError, match="invalid result collection"):
        await detector.detect("A", context=detection_context())
