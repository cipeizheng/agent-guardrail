"""Controlled services made available to rule implementations."""

from __future__ import annotations

import asyncio
from hashlib import sha256

from agent_guardrail.core.registry import DetectorRegistry
from agent_guardrail.models import Detection, DetectionContext, GuardrailContext


class DetectorTimeoutError(TimeoutError):
    """A detector exceeded its configured execution deadline."""


class RuleServices:
    """Detector access with per-evaluation caching and explicit deadlines."""

    def __init__(
        self,
        *,
        detectors: DetectorRegistry,
        policy_hash: str,
        detector_timeout_ms: int,
    ) -> None:
        self._detectors = detectors
        self._policy_hash = policy_hash
        self._detector_timeout_seconds = detector_timeout_ms / 1_000
        self._cache: dict[tuple[str, str, str, str], tuple[Detection, ...]] = {}

    @property
    def detector_cache_size(self) -> int:
        """Expose cache size for metrics and deterministic tests."""

        return len(self._cache)

    async def detect(
        self,
        detector_name: str,
        text: str,
        *,
        context: GuardrailContext,
        path: str | None = None,
    ) -> tuple[Detection, ...]:
        """Detect text once per policy, detector version and content hash."""

        detector = self._detectors.get(detector_name)
        content_hash = sha256(text.encode("utf-8")).hexdigest()
        cache_key = (self._policy_hash, detector.name, detector.version, content_hash)
        detections = self._cache.get(cache_key)
        if detections is None:
            detection_context = DetectionContext(
                trace_id=context.trace.id,
                event_id=context.event.id,
                phase=context.event.phase,
            )
            try:
                async with asyncio.timeout(self._detector_timeout_seconds):
                    detected = await detector.detect(text, context=detection_context)
            except TimeoutError as exc:
                raise DetectorTimeoutError(
                    f"detector {detector.name!r} exceeded its deadline"
                ) from exc
            detections = tuple(detected)
            self._cache[cache_key] = detections

        if path is None:
            return detections
        return tuple(detection.model_copy(update={"path": path}) for detection in detections)
