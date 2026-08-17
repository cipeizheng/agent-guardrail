from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_guardrail.config import (
    DetectorDeploymentProfile,
    DetectorProfileError,
    create_deployment_detector_registry,
    create_llm_judge_detector_registry,
)
from agent_guardrail.detectors import (
    JudgeVerdict,
    LLMJudgeDetector,
    LLMJudgeProfile,
)
from agent_guardrail.models import DetectionContext

_PROMPT_SHA = "a" * 64


def _context(*, event_id: str = "event-1") -> DetectionContext:
    return DetectionContext(trace_id="trace-1", event_id=event_id)


def _profile(*, prompt_sha256: str = _PROMPT_SHA) -> LLMJudgeProfile:
    return LLMJudgeProfile(
        profile_id="release-judge",
        profile_version="1",
        prompt_sha256=prompt_sha256,
    )


@dataclass(slots=True)
class _Backend:
    verdict: JudgeVerdict
    calls: int = 0
    name: str = "test-judge"
    version: str = "2026-08-16"

    async def judge(self, text: str) -> JudgeVerdict:
        del text
        self.calls += 1
        return self.verdict


def test_judge_verdict_rejects_out_of_range_scores() -> None:
    JudgeVerdict(score=0.0)
    JudgeVerdict(score=1.0)
    with pytest.raises(ValueError, match="float in \\[0, 1\\]"):
        JudgeVerdict(score=1.5)
    with pytest.raises(ValueError, match="float in \\[0, 1\\]"):
        JudgeVerdict(score=True)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_digest", ["", "a" * 63, "A" * 64, "z" * 64, 42])
def test_judge_profile_requires_sha256_hex_digest(bad_digest: object) -> None:
    with pytest.raises(ValueError, match="64 lowercase hex"):
        LLMJudgeProfile(
            profile_id="release-judge",
            profile_version="1",
            prompt_sha256=bad_digest,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_llm_judge_detector_applies_deployment_threshold() -> None:
    attack = _Backend(JudgeVerdict(score=0.91))
    benign = _Backend(JudgeVerdict(score=0.49))

    hit = await LLMJudgeDetector(
        attack, profile=_profile(), threshold=0.5
    ).detect("novel goal-hijack payload", context=_context())
    miss = await LLMJudgeDetector(
        benign, profile=_profile(), threshold=0.5
    ).detect("ordinary tool output", context=_context())

    assert [item.type for item in hit] == ["llm_judge_prompt_injection"]
    assert hit[0].detector == "prompt_injection_judge"
    assert hit[0].confidence == 0.91
    assert hit[0].masked_evidence.startswith("<prompt_injection_judge:llm_judge_prompt_injection:")
    assert "novel goal-hijack payload" not in hit[0].model_dump_json()
    assert miss == []
    assert attack.calls == benign.calls == 1


@pytest.mark.asyncio
async def test_llm_judge_detector_rejects_unstructured_verdicts() -> None:
    from typing import cast

    invalid = cast(JudgeVerdict, {"injection": True})
    detector = LLMJudgeDetector(_Backend(invalid), profile=_profile())

    with pytest.raises(TypeError, match="invalid verdict"):
        await detector.detect("classify me", context=_context())


@pytest.mark.asyncio
async def test_llm_judge_detector_enforces_hard_byte_bound() -> None:
    detector = LLMJudgeDetector(_Backend(JudgeVerdict(score=0.9)), profile=_profile())

    with pytest.raises(ValueError, match="hard byte bound"):
        await detector.detect("x" * 16_385, context=_context())


def test_llm_judge_version_identity_binds_threshold_and_prompt() -> None:
    backend = _Backend(JudgeVerdict(score=0.9))
    base = LLMJudgeDetector(backend, profile=_profile())
    other_threshold = LLMJudgeDetector(backend, profile=_profile(), threshold=0.9)
    other_prompt = LLMJudgeDetector(
        backend,
        profile=_profile(prompt_sha256="b" * 64),
    )

    assert base.version != other_threshold.version
    assert base.version != other_prompt.version
    assert base.version.startswith("1-")


def test_llm_judge_constructor_rejects_invalid_injection() -> None:
    backend = _Backend(JudgeVerdict(score=0.9))
    with pytest.raises(TypeError, match="implement LLMJudgeBackend"):
        LLMJudgeDetector(object(), profile=_profile())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="LLMJudgeProfile"):
        LLMJudgeDetector(backend, profile=object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="threshold must be a float"):
        LLMJudgeDetector(backend, profile=_profile(), threshold=0.0)


def test_llm_judge_descriptor_is_bounded_and_release_scoped() -> None:
    detector = LLMJudgeDetector(_Backend(JudgeVerdict(score=0.9)), profile=_profile())
    registry = create_llm_judge_detector_registry(detector)

    descriptor = registry.policy_descriptor("prompt_injection_judge")
    assert descriptor.timeout_ms == 10_000
    assert descriptor.max_detections == 1
    assert descriptor.max_input_bytes == 16_384
    assert descriptor.allowed_encodings == frozenset({"text", "canonical_json"})
    assert set(descriptor.detection_types) == {"llm_judge_prompt_injection"}


def test_deployment_registry_accepts_paired_judge_configuration() -> None:
    registry = create_deployment_detector_registry(
        DetectorDeploymentProfile.LOCAL,
        llm_judge_backend=_Backend(JudgeVerdict(score=0.9)),
        llm_judge_profile=_profile(),
        llm_judge_threshold=0.75,
    )
    descriptor = registry.policy_descriptor("prompt_injection_judge")
    assert descriptor is not None
    # the threshold is folded into the registered detector's version identity
    registered = registry.get("prompt_injection_judge")
    unconfigured = LLMJudgeDetector(_Backend(JudgeVerdict(score=0.9)), profile=_profile())
    assert registered.version != unconfigured.version


def test_deployment_registry_rejects_half_configured_judge() -> None:
    backend = _Backend(JudgeVerdict(score=0.9))
    with pytest.raises(DetectorProfileError, match="configured together"):
        create_deployment_detector_registry(
            DetectorDeploymentProfile.LOCAL,
            llm_judge_backend=backend,
        )
    with pytest.raises(DetectorProfileError, match="configured together"):
        create_deployment_detector_registry(
            DetectorDeploymentProfile.LOCAL,
            llm_judge_profile=_profile(),
        )


@pytest.mark.parametrize("bad_threshold", [0.0, -0.1, 1.5, 1, True])
def test_deployment_registry_rejects_invalid_judge_threshold(bad_threshold: float) -> None:
    with pytest.raises(DetectorProfileError, match="LLM judge threshold"):
        create_deployment_detector_registry(
            DetectorDeploymentProfile.LOCAL,
            llm_judge_backend=_Backend(JudgeVerdict(score=0.9)),
            llm_judge_profile=_profile(),
            llm_judge_threshold=bad_threshold,
        )


def test_deployment_registry_judge_threshold_requires_backend() -> None:
    with pytest.raises(DetectorProfileError, match="requires an LLM judge backend"):
        create_deployment_detector_registry(
            DetectorDeploymentProfile.LOCAL,
            llm_judge_threshold=0.9,
        )


def test_default_registry_has_no_judge_capability() -> None:
    from agent_guardrail.config import create_default_detector_registry
    from agent_guardrail.core.registry import UnknownDetectorError

    registry = create_default_detector_registry()
    with pytest.raises(UnknownDetectorError):
        registry.get("prompt_injection_judge")
    with pytest.raises(UnknownDetectorError):
        registry.policy_descriptor("prompt_injection_judge")
