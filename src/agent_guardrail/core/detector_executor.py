"""One bounded execution boundary shared by MatchPlan and the direct Detector SDK."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from agent_guardrail.core.capabilities import CompiledDetectorCapability
from agent_guardrail.core.match_plan import DetectorInputEncoding
from agent_guardrail.core.registry import DetectorPolicyDescriptor
from agent_guardrail.models import AnalysisErrorCode, Detection, DetectionContext

_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 65_536
_SAFE_FINGERPRINT_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)


class DetectorExecutionError(RuntimeError):
    """A stable, input-redacted failure from the shared Detector boundary."""

    def __init__(
        self,
        *,
        code: AnalysisErrorCode,
        message: str,
        capability: str | None,
        retryable: bool = False,
    ) -> None:
        self.code = code
        self.capability = capability
        self.retryable = retryable
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PreparedDetectorInput:
    """A descriptor-checked Detector input with its exact encoded byte cost."""

    capability: str
    encoding: DetectorInputEncoding
    text: str
    input_bytes: int


class DetectorExecutor:
    """Resolve, prepare, invoke, and validate explicitly published Detectors."""

    def __init__(self, capabilities: tuple[CompiledDetectorCapability, ...]) -> None:
        resolved: dict[str, CompiledDetectorCapability] = {}
        for capability in capabilities:
            name = capability.descriptor.name
            implementation = capability.implementation
            if name in resolved:
                raise ValueError("Detector capabilities must have unique names")
            if implementation.name != name:
                raise ValueError("registered Detector identity is inconsistent")
            version = implementation.version
            if (
                not isinstance(version, str)
                or not version
                or version != version.strip()
                or len(version) > 128
            ):
                raise ValueError("registered Detector version is invalid")
            resolved[name] = capability
        self._capabilities = resolved

    def descriptor(self, capability: str) -> DetectorPolicyDescriptor:
        """Return the trusted descriptor without exposing its implementation."""

        return self._resolve(capability).descriptor

    def implementation_version(self, capability: str) -> str:
        return self._resolve(capability).implementation.version

    def prepare_text(
        self,
        capability: str,
        text: str,
        *,
        encoding: DetectorInputEncoding = DetectorInputEncoding.TEXT,
    ) -> PreparedDetectorInput:
        """Validate an already textual representation against its descriptor."""

        compiled = self._resolve(capability)
        descriptor = compiled.descriptor
        if not isinstance(encoding, DetectorInputEncoding):
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector input encoding is invalid",
                capability=descriptor.name,
            )
        if encoding.value not in descriptor.allowed_encodings:
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector input encoding is not published",
                capability=descriptor.name,
            )
        if type(text) is not str:
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector text input is invalid",
                capability=descriptor.name,
            )
        if len(text) > descriptor.max_input_bytes:
            self._raise_input_limit(descriptor.name)
        encoded_size = _utf8_size(text, capability=descriptor.name)
        if encoded_size > descriptor.max_input_bytes:
            self._raise_input_limit(descriptor.name)
        return PreparedDetectorInput(
            capability=descriptor.name,
            encoding=encoding,
            text=text,
            input_bytes=max(1, encoded_size),
        )

    def prepare_json(self, capability: str, value: object) -> PreparedDetectorInput:
        """Validate and canonically encode one bounded JSON value."""

        descriptor = self._resolve(capability).descriptor
        if DetectorInputEncoding.CANONICAL_JSON.value not in descriptor.allowed_encodings:
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector input encoding is not published",
                capability=descriptor.name,
            )
        _validate_json_value(
            value,
            capability=descriptor.name,
            max_input_bytes=descriptor.max_input_bytes,
        )
        try:
            text = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
        except (OverflowError, RecursionError, TypeError, ValueError):
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector JSON input is invalid",
                capability=descriptor.name,
            ) from None
        return self.prepare_text(
            capability,
            text,
            encoding=DetectorInputEncoding.CANONICAL_JSON,
        )

    async def execute(
        self,
        prepared: PreparedDetectorInput,
        *,
        context: DetectionContext,
    ) -> tuple[Detection, ...]:
        """Invoke one prepared Detector with timeout and strict result validation."""

        checked = self.prepare_text(
            prepared.capability,
            prepared.text,
            encoding=prepared.encoding,
        )
        compiled = self._resolve(checked.capability)
        descriptor = compiled.descriptor
        implementation = compiled.implementation
        execution_context = context.model_copy(deep=True)
        try:
            async with asyncio.timeout(descriptor.timeout_ms / 1_000):
                raw = await implementation.detect(checked.text, context=execution_context)
        except TimeoutError:
            raise DetectorExecutionError(
                code=descriptor.timeout_code,
                message="Detector capability timed out",
                capability=descriptor.name,
                retryable=True,
            ) from None
        except Exception:
            raise DetectorExecutionError(
                code=descriptor.error_code,
                message="Detector capability execution failed",
                capability=descriptor.name,
            ) from None
        if not isinstance(raw, (list, tuple)) or len(raw) > descriptor.max_detections:
            self._raise_invalid_result(descriptor.name)
        result: list[Detection] = []
        for detection in raw:
            if not isinstance(detection, Detection) or not self._valid_detection(
                detection,
                capability=descriptor.name,
                implementation_version=implementation.version,
                detection_types=descriptor.detection_types,
                text_length=len(checked.text),
            ):
                self._raise_invalid_result(descriptor.name)
            result.append(detection.model_copy(deep=True, update={"path": None}))
        return tuple(result)

    def _resolve(self, capability: str) -> CompiledDetectorCapability:
        if not _is_safe_capability_name(capability):
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector capability is unavailable",
                capability=None,
            )
        try:
            return self._capabilities[capability]
        except KeyError:
            raise DetectorExecutionError(
                code=AnalysisErrorCode.CAPABILITY_ERROR,
                message="Detector capability is unavailable",
                capability=capability,
            ) from None

    @staticmethod
    def _valid_detection(
        detection: Detection,
        *,
        capability: str,
        implementation_version: str,
        detection_types: frozenset[str],
        text_length: int,
    ) -> bool:
        return not (
            detection.detector != capability
            or detection.detector_version != implementation_version
            or detection.type not in detection_types
            or len(detection.masked_evidence) > 256
            or detection.masked_evidence != detection.masked_evidence.strip()
            or len(detection.fingerprint) > 128
            or any(
                character not in _SAFE_FINGERPRINT_CHARACTERS
                for character in detection.fingerprint
            )
            or (detection.path is not None and len(detection.path) > 256)
            or (detection.path is not None and detection.path != detection.path.strip())
            or (detection.end is not None and detection.end > text_length)
        )

    @staticmethod
    def _raise_input_limit(capability: str) -> None:
        raise DetectorExecutionError(
            code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
            message="Detector input exceeds its published byte limit",
            capability=capability,
        )

    @staticmethod
    def _raise_invalid_result(capability: str) -> None:
        raise DetectorExecutionError(
            code=AnalysisErrorCode.CAPABILITY_ERROR,
            message="Detector capability returned an invalid result",
            capability=capability,
        )


def _validate_json_value(
    value: object,
    *,
    capability: str,
    max_input_bytes: int,
) -> None:
    """Bound JSON traversal before the canonical encoder allocates output."""

    remaining_nodes = _MAX_JSON_NODES
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        remaining_nodes -= 1
        if remaining_nodes < 0 or depth > _MAX_JSON_DEPTH:
            raise DetectorExecutionError(
                code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
                message="Detector JSON input exceeds its structural limit",
                capability=capability,
            )
        if item is None or type(item) in {bool, int}:
            continue
        if type(item) is float:
            if item != item or item in {float("inf"), float("-inf")}:
                _raise_invalid_json(capability)
            continue
        if type(item) is str:
            if len(item) > max_input_bytes or _utf8_size(
                item,
                capability=capability,
            ) > max_input_bytes:
                DetectorExecutor._raise_input_limit(capability)
            continue
        if type(item) is list:
            if len(item) > remaining_nodes:
                _raise_json_structure_limit(capability)
            stack.extend((child, depth + 1) for child in item)
            continue
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                _raise_invalid_json(capability)
            if len(item) > remaining_nodes:
                _raise_json_structure_limit(capability)
            for key in item:
                if len(key) > max_input_bytes or _utf8_size(
                    key,
                    capability=capability,
                ) > max_input_bytes:
                    DetectorExecutor._raise_input_limit(capability)
            stack.extend((child, depth + 1) for child in item.values())
            continue
        _raise_invalid_json(capability)


def _raise_invalid_json(capability: str) -> None:
    raise DetectorExecutionError(
        code=AnalysisErrorCode.CAPABILITY_ERROR,
        message="Detector JSON input is invalid",
        capability=capability,
    )


def _raise_json_structure_limit(capability: str) -> None:
    raise DetectorExecutionError(
        code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
        message="Detector JSON input exceeds its structural limit",
        capability=capability,
    )


def _utf8_size(value: str, *, capability: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise DetectorExecutionError(
            code=AnalysisErrorCode.CAPABILITY_ERROR,
            message="Detector input is not valid UTF-8",
            capability=capability,
        ) from None


def _is_safe_capability_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].islower()
        and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789_"
            for character in value
        )
    )
