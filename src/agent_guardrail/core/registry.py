"""Explicit registries for trusted rule implementations and detectors."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agent_guardrail.core.match_plan import DetectorInputEncoding, ValueType
from agent_guardrail.core.protocols import Detector, Predicate, SimilarityDetector
from agent_guardrail.models import AnalysisErrorCode


class RegistryError(ValueError):
    """Base error for invalid or unknown registry entries."""


class UnknownDetectorError(RegistryError):
    """Raised when a rule references an unavailable detector."""


class UnknownPredicateError(RegistryError):
    """Raised when a policy references an unavailable Predicate."""


class CapabilityEvidencePolicy(StrEnum):
    """Closed redaction contracts for trusted MatchPlan capabilities."""

    STATIC_MASK_ONLY = "static_mask_only"
    MASKED_DETECTION_ONLY = "masked_detection_only"


@dataclass(frozen=True, slots=True)
class DetectorPolicyDescriptor:
    """The bounded detector surface that a structured policy may select."""

    name: str
    allowed_encodings: frozenset[str]
    detection_types: frozenset[str]
    max_input_bytes: int
    timeout_ms: int = 500
    max_detections: int = 64
    error_code: AnalysisErrorCode = AnalysisErrorCode.CAPABILITY_ERROR
    timeout_code: AnalysisErrorCode = AnalysisErrorCode.DETECTOR_TIMEOUT
    evidence_policy: CapabilityEvidencePolicy = (
        CapabilityEvidencePolicy.MASKED_DETECTION_ONLY
    )

    def __post_init__(self) -> None:
        _validate_capability_name(self.name, "detector policy descriptor")
        if not isinstance(self.allowed_encodings, frozenset):
            raise RegistryError("detector policy descriptor encodings must be a frozenset")
        if not self.allowed_encodings:
            raise RegistryError("detector policy descriptor must allow an encoding")
        supported_encodings = {encoding.value for encoding in DetectorInputEncoding}
        if not self.allowed_encodings.issubset(supported_encodings):
            raise RegistryError("detector policy descriptor has an unknown encoding")
        if not isinstance(self.detection_types, frozenset) or any(
            not isinstance(value, str) or not _is_evidence_type(value)
            for value in self.detection_types
        ):
            raise RegistryError("detector policy descriptor detection type is invalid")
        _validate_bound(self.max_input_bytes, 1, 8_388_608, "detector input bytes")
        _validate_bound(self.timeout_ms, 1, 60_000, "detector timeout")
        _validate_bound(self.max_detections, 1, 1_000, "detector result count")
        if self.error_code is not AnalysisErrorCode.CAPABILITY_ERROR:
            raise RegistryError("Detector execution errors must use capability_error")
        if self.timeout_code is not AnalysisErrorCode.DETECTOR_TIMEOUT:
            raise RegistryError("Detector timeouts must use detector_timeout")
        if self.evidence_policy is not CapabilityEvidencePolicy.MASKED_DETECTION_ONLY:
            raise RegistryError("Detector evidence must use masked Detection fields")


@dataclass(frozen=True, slots=True)
class PredicatePolicyDescriptor:
    """The finite contract published for one trusted Predicate implementation."""

    name: str
    argument_types: tuple[ValueType, ...]
    output_type: ValueType = ValueType.BOOLEAN
    pure: bool = True
    max_input_bytes: int = 16_384
    timeout_ms: int = 100
    error_code: AnalysisErrorCode = AnalysisErrorCode.CAPABILITY_ERROR
    timeout_code: AnalysisErrorCode = AnalysisErrorCode.CAPABILITY_ERROR
    evidence_policy: CapabilityEvidencePolicy = CapabilityEvidencePolicy.STATIC_MASK_ONLY

    def __post_init__(self) -> None:
        _validate_capability_name(self.name, "predicate policy descriptor")
        if not isinstance(self.argument_types, tuple) or any(
            not isinstance(value, ValueType) for value in self.argument_types
        ):
            raise RegistryError("predicate argument types must be a ValueType tuple")
        if len(self.argument_types) > 16:
            raise RegistryError("predicate policy descriptor has too many arguments")
        if self.output_type is not ValueType.BOOLEAN:
            raise RegistryError("structured-policy Predicates must return boolean")
        if self.pure is not True:
            raise RegistryError("structured-policy Predicates must be pure")
        _validate_bound(self.max_input_bytes, 1, 8_388_608, "predicate input bytes")
        _validate_bound(self.timeout_ms, 1, 60_000, "predicate timeout")
        if (
            self.error_code is not AnalysisErrorCode.CAPABILITY_ERROR
            or self.timeout_code is not AnalysisErrorCode.CAPABILITY_ERROR
        ):
            raise RegistryError("Predicate failures must use capability_error")
        if self.evidence_policy is not CapabilityEvidencePolicy.STATIC_MASK_ONLY:
            raise RegistryError("Predicate evidence must use a static Policy mask")


@dataclass(frozen=True, slots=True)
class SimilarityPolicyDescriptor:
    """Bounded surface for the specialized text-similarity Detector condition."""

    name: str
    detection_type: str
    max_input_bytes: int = 65_536
    max_texts: int = 128
    timeout_ms: int = 5_000
    error_code: AnalysisErrorCode = AnalysisErrorCode.CAPABILITY_ERROR
    timeout_code: AnalysisErrorCode = AnalysisErrorCode.DETECTOR_TIMEOUT
    evidence_policy: CapabilityEvidencePolicy = (
        CapabilityEvidencePolicy.MASKED_DETECTION_ONLY
    )

    def __post_init__(self) -> None:
        _validate_capability_name(self.name, "similarity policy descriptor")
        if not _is_evidence_type(self.detection_type):
            raise RegistryError("similarity policy descriptor detection type is invalid")
        _validate_bound(self.max_input_bytes, 1, 8_388_608, "similarity input bytes")
        _validate_bound(self.max_texts, 1, 128, "similarity text count")
        _validate_bound(self.timeout_ms, 1, 60_000, "similarity timeout")
        if self.error_code is not AnalysisErrorCode.CAPABILITY_ERROR:
            raise RegistryError("Similarity execution errors must use capability_error")
        if self.timeout_code is not AnalysisErrorCode.DETECTOR_TIMEOUT:
            raise RegistryError("Similarity timeouts must use detector_timeout")
        if self.evidence_policy is not CapabilityEvidencePolicy.MASKED_DETECTION_ONLY:
            raise RegistryError("Similarity evidence must use masked Detection fields")


class DetectorRegistry:
    """An injected collection of local detector implementations."""

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}
        self._policy_descriptors: dict[str, DetectorPolicyDescriptor] = {}
        self._similarity_detectors: dict[str, SimilarityDetector] = {}
        self._similarity_policy_descriptors: dict[str, SimilarityPolicyDescriptor] = {}

    def register(
        self,
        detector: Detector,
        *,
        policy_descriptor: DetectorPolicyDescriptor | None = None,
    ) -> None:
        if detector.name in self._detectors or detector.name in self._similarity_detectors:
            raise RegistryError(f"detector is already registered: {detector.name}")
        if policy_descriptor is not None and policy_descriptor.name != detector.name:
            raise RegistryError("detector policy descriptor must name its detector")
        self._detectors[detector.name] = detector
        if policy_descriptor is not None:
            self._policy_descriptors[detector.name] = policy_descriptor

    def get(self, name: str) -> Detector:
        try:
            return self._detectors[name]
        except KeyError as exc:
            raise UnknownDetectorError(f"unknown detector: {name}") from exc

    def policy_descriptor(self, name: str) -> DetectorPolicyDescriptor:
        """Return the explicitly published structured-policy capability."""

        self.get(name)
        try:
            return self._policy_descriptors[name]
        except KeyError as exc:
            raise RegistryError(f"detector is not available to structured policy: {name}") from exc

    def register_similarity(
        self,
        detector: SimilarityDetector,
        *,
        policy_descriptor: SimilarityPolicyDescriptor,
    ) -> None:
        """Publish one specialized semantic-similarity implementation."""

        if detector.name in self._detectors or detector.name in self._similarity_detectors:
            raise RegistryError(f"detector is already registered: {detector.name}")
        if policy_descriptor.name != detector.name:
            raise RegistryError("similarity policy descriptor must name its detector")
        self._similarity_detectors[detector.name] = detector
        self._similarity_policy_descriptors[detector.name] = policy_descriptor

    def get_similarity(self, name: str) -> SimilarityDetector:
        try:
            return self._similarity_detectors[name]
        except KeyError as exc:
            raise UnknownDetectorError(f"unknown similarity detector: {name}") from exc

    def similarity_policy_descriptor(self, name: str) -> SimilarityPolicyDescriptor:
        self.get_similarity(name)
        try:
            return self._similarity_policy_descriptors[name]
        except KeyError as exc:
            raise RegistryError(
                f"similarity detector is not available to structured policy: {name}"
            ) from exc


class PredicateRegistry:
    """Explicit trusted Predicate implementations published to structured policy."""

    def __init__(self) -> None:
        self._predicates: dict[str, Predicate] = {}
        self._policy_descriptors: dict[str, PredicatePolicyDescriptor] = {}

    def register(
        self,
        predicate: Predicate,
        *,
        policy_descriptor: PredicatePolicyDescriptor,
    ) -> None:
        if predicate.name in self._predicates:
            raise RegistryError(f"predicate is already registered: {predicate.name}")
        if policy_descriptor.name != predicate.name:
            raise RegistryError("predicate policy descriptor must name its Predicate")
        self._predicates[predicate.name] = predicate
        self._policy_descriptors[predicate.name] = policy_descriptor

    def get(self, name: str) -> Predicate:
        try:
            return self._predicates[name]
        except KeyError as exc:
            raise UnknownPredicateError(f"unknown Predicate: {name}") from exc

    def policy_descriptor(self, name: str) -> PredicatePolicyDescriptor:
        """Return the explicitly published structured-policy capability."""

        self.get(name)
        return self._policy_descriptors[name]


def _validate_capability_name(name: str, subject: str) -> None:
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 128
        or not name[0].islower()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in name)
    ):
        raise RegistryError(f"{subject} name is invalid")


def _validate_bound(value: int, minimum: int, maximum: int, subject: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RegistryError(f"{subject} must be an integer")
    if not minimum <= value <= maximum:
        raise RegistryError(f"{subject} is outside its hard bounds")


def _is_evidence_type(value: str) -> bool:
    if not value or len(value) > 128 or not value[0].isalpha():
        return False
    return all(
        character.isascii()
        and (character.isalnum() or character in "_.:-")
        for character in value
    )
