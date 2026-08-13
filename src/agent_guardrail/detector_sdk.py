"""Framework-neutral direct Detector SDK without Policy or lifecycle orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4

from pydantic import JsonValue

from agent_guardrail.config.defaults import create_default_detector_registry
from agent_guardrail.config.deployment import (
    DetectorDeploymentProfile,
    PromptModelDevice,
    create_deployment_detector_registry,
)
from agent_guardrail.core.capabilities import CompiledDetectorCapability
from agent_guardrail.core.detector_executor import DetectorExecutor
from agent_guardrail.core.match_plan import DetectorInputEncoding
from agent_guardrail.core.registry import DetectorRegistry
from agent_guardrail.models import Detection, DetectionContext

_MAX_DETECT_MANY_CAPABILITIES = 64


@dataclass(frozen=True, slots=True)
class DetectorCapability:
    """The bounded, implementation-backed surface published by one Detector."""

    name: str
    version: str
    encodings: tuple[DetectorInputEncoding, ...]
    detection_types: tuple[str, ...]
    max_input_bytes: int
    timeout_ms: int
    max_detections: int


@dataclass(frozen=True, slots=True)
class DetectorResult:
    """Safe facts from one Detector invocation; this is not an enforcement Decision."""

    capability: str
    encoding: DetectorInputEncoding
    context: DetectionContext
    detections: tuple[Detection, ...]

    @property
    def detected(self) -> bool:
        return bool(self.detections)


class DetectorRunner:
    """Run reviewed Detectors directly at arbitrary application insertion points."""

    def __init__(self, registry: DetectorRegistry | None = None) -> None:
        selected = registry or create_default_detector_registry()
        descriptors = selected.published_detector_descriptors()
        compiled = tuple(
            CompiledDetectorCapability(
                descriptor=descriptor,
                implementation=selected.get(descriptor.name),
            )
            for descriptor in descriptors
        )
        self._executor = DetectorExecutor(compiled)
        self._capabilities = tuple(
            DetectorCapability(
                name=descriptor.name,
                version=self._executor.implementation_version(descriptor.name),
                encodings=tuple(
                    encoding
                    for encoding in DetectorInputEncoding
                    if encoding.value in descriptor.allowed_encodings
                ),
                detection_types=tuple(sorted(descriptor.detection_types)),
                max_input_bytes=descriptor.max_input_bytes,
                timeout_ms=descriptor.timeout_ms,
                max_detections=descriptor.max_detections,
            )
            for descriptor in descriptors
        )

    @classmethod
    def from_profile(
        cls,
        profile: DetectorDeploymentProfile | str = DetectorDeploymentProfile.LOCAL,
        *,
        prompt_model_device: PromptModelDevice | str = PromptModelDevice.CPU,
        detector_assets_dir: Path | None = None,
    ) -> DetectorRunner:
        """Construct a deployment-owned fixed profile; Policy cannot select it."""

        return cls(
            create_deployment_detector_registry(
                profile,
                prompt_model_device=prompt_model_device,
                detector_assets_dir=detector_assets_dir,
            )
        )

    @classmethod
    def from_registry(cls, registry: DetectorRegistry) -> DetectorRunner:
        """Construct from an explicitly trusted, descriptor-published Registry."""

        return cls(registry)

    @property
    def capabilities(self) -> tuple[DetectorCapability, ...]:
        """Enumerate only Detectors callable through this direct SDK."""

        return self._capabilities

    async def detect(
        self,
        capability: str,
        text: str,
        *,
        context: DetectionContext | None = None,
    ) -> DetectorResult:
        """Alias for detect_text for concise application hooks."""

        return await self.detect_text(capability, text, context=context)

    async def detect_text(
        self,
        capability: str,
        text: str,
        *,
        context: DetectionContext | None = None,
    ) -> DetectorResult:
        """Run one Detector over bounded UTF-8 text."""

        return (
            await self.detect_many(
                (capability,),
                text,
                encoding=DetectorInputEncoding.TEXT,
                context=context,
            )
        )[0]

    async def detect_json(
        self,
        capability: str,
        value: JsonValue,
        *,
        context: DetectionContext | None = None,
    ) -> DetectorResult:
        """Run one Detector over deterministic canonical JSON."""

        return (
            await self.detect_many(
                (capability,),
                value,
                encoding=DetectorInputEncoding.CANONICAL_JSON,
                context=context,
            )
        )[0]

    async def detect_many(
        self,
        capabilities: Sequence[str],
        value: str | JsonValue,
        *,
        encoding: DetectorInputEncoding | str = DetectorInputEncoding.TEXT,
        context: DetectionContext | None = None,
    ) -> tuple[DetectorResult, ...]:
        """Run a bounded ordered Detector set over one value and fail on any error."""

        names = self._validate_capabilities(capabilities)
        selected_encoding = self._validate_encoding(encoding)
        selected_context = self._validate_context(context)
        if selected_encoding is DetectorInputEncoding.TEXT:
            text = cast(str, value)
            prepared = tuple(
                self._executor.prepare_text(name, text, encoding=selected_encoding)
                for name in names
            )
        else:
            prepared = tuple(
                self._executor.prepare_json(name, value)
                for name in names
            )

        results: list[DetectorResult] = []
        for item in prepared:
            detections = await self._executor.execute(item, context=selected_context)
            results.append(
                DetectorResult(
                    capability=item.capability,
                    encoding=item.encoding,
                    context=selected_context.model_copy(deep=True),
                    detections=detections,
                )
            )
        return tuple(results)

    @staticmethod
    def _validate_capabilities(capabilities: Sequence[str]) -> tuple[str, ...]:
        if isinstance(capabilities, (str, bytes)) or not isinstance(capabilities, Sequence):
            raise TypeError("capabilities must be a sequence of Detector names")
        names = tuple(capabilities)
        if not names:
            raise ValueError("detect_many requires at least one Detector")
        if len(names) > _MAX_DETECT_MANY_CAPABILITIES:
            raise ValueError("detect_many has too many Detectors")
        if any(not isinstance(name, str) for name in names):
            raise TypeError("capabilities must contain only Detector names")
        if len(names) != len(set(names)):
            raise ValueError("detect_many Detector names must be unique")
        return names

    @staticmethod
    def _validate_encoding(
        encoding: DetectorInputEncoding | str,
    ) -> DetectorInputEncoding:
        try:
            return DetectorInputEncoding(encoding)
        except (TypeError, ValueError):
            raise ValueError("unknown Detector input encoding") from None

    @staticmethod
    def _validate_context(context: DetectionContext | None) -> DetectionContext:
        selected = context or DetectionContext(
            trace_id=f"scan_{uuid4().hex}",
            event_id="input",
        )
        if not isinstance(selected, DetectionContext):
            raise TypeError("context must be a DetectionContext")
        copied = selected.model_copy(deep=True)
        if any(
            not value.strip() or value != value.strip() or len(value) > 256
            for value in (copied.trace_id, copied.event_id)
        ):
            raise ValueError("Detector context identifiers are invalid")
        return copied
