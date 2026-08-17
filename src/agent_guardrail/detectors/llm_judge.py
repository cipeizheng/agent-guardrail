"""Deployment-injected LLM judge scoring for prompt-injection detection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, runtime_checkable

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

MAX_LLM_JUDGE_BYTES = 16_384
LLM_JUDGE_DETECTION_TYPE = "llm_judge_prompt_injection"


@dataclass(frozen=True, slots=True)
class JudgeVerdict:
    """One normalized judge verdict with no model-generated prose."""

    score: float

    def __post_init__(self) -> None:
        if not isinstance(self.score, float) or not 0.0 <= self.score <= 1.0:
            raise ValueError("judge verdict score must be a float in [0, 1]")


@runtime_checkable
class LLMJudgeBackend(Protocol):
    """A deployment-owned, preconfigured judge endpoint.

    The deployment constructs the client, model, prompt template, credentials,
    and timeouts. The detector never selects them and Policy never sees them.
    """

    name: str
    version: str

    async def judge(self, text: str) -> JudgeVerdict: ...


@dataclass(frozen=True, slots=True)
class LLMJudgeProfile:
    """Deployment-owned identity for one pinned judge configuration."""

    profile_id: str
    profile_version: str
    prompt_sha256: str

    def __post_init__(self) -> None:
        _validate_identity(self.profile_id, "judge profile id")
        _validate_identity(self.profile_version, "judge profile version")
        if (
            not isinstance(self.prompt_sha256, str)
            or len(self.prompt_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.prompt_sha256)
        ):
            raise ValueError("judge profile prompt_sha256 must be 64 lowercase hex characters")


class LLMJudgeDetector:
    """Turn a bounded judge verdict into an audit-safe Detector fact."""

    name = "prompt_injection_judge"
    adapter_version = "1"

    def __init__(
        self,
        backend: LLMJudgeBackend,
        *,
        profile: LLMJudgeProfile,
        threshold: float = 0.5,
    ) -> None:
        if not isinstance(backend, LLMJudgeBackend):
            raise TypeError("backend must implement LLMJudgeBackend")
        if not isinstance(profile, LLMJudgeProfile):
            raise TypeError("profile must be an LLMJudgeProfile")
        if not isinstance(threshold, float) or not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be a float in (0, 1]")
        _validate_identity(backend.name, "judge backend name")
        _validate_identity(backend.version, "judge backend version")
        self._backend = backend
        self._profile = profile
        self._threshold = threshold
        identity = sha256(
            json.dumps(
                (
                    backend.name,
                    backend.version,
                    profile.profile_id,
                    profile.profile_version,
                    profile.prompt_sha256,
                    threshold,
                ),
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        if len(text.encode("utf-8")) > MAX_LLM_JUDGE_BYTES:
            raise ValueError("LLM judge input exceeds its hard byte bound")
        verdict = await self._backend.judge(text)
        if not isinstance(verdict, JudgeVerdict):
            raise TypeError("judge backend returned an invalid verdict")
        if verdict.score <= self._threshold:
            return []
        detection_type = LLM_JUDGE_DETECTION_TYPE
        span = (0, len(text)) if text else None
        fingerprint = occurrence_fingerprint(
            context=context,
            detector=self.name,
            detector_version=self.version,
            detection_type=detection_type,
            start=span[0] if span is not None else 0,
            end=span[1] if span is not None else 0,
        )
        common = {
            "type": detection_type,
            "detector": self.name,
            "detector_version": self.version,
            "confidence": verdict.score,
            "masked_evidence": f"<{self.name}:{detection_type}:{fingerprint}>",
            "fingerprint": fingerprint,
        }
        if span is not None:
            return [Detection(**common, start=span[0], end=span[1])]
        return [Detection(**common)]


def _validate_identity(value: object, subject: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError(f"{subject} is invalid")
