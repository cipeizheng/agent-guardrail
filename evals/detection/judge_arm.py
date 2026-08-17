"""LLM-judge model arm through the production SDK channel (NEXT-STEPS P2-5).

The 2026-08-15 characterization (llm_judge.py) proved the concept with a raw
OpenAI client: recall 0.82 vs the classifier's 0.08, at 37% NotInject FPR.
This arm validates the same judge through the real capability path -- a
DeepSeek backend implementing the LLMJudgeBackend protocol, registered via
create_deployment_detector_registry, executed by DetectorRunner under the
published descriptor budget, with redacted evidence.

It runs at a near-zero deployment threshold so Detection.confidence carries
the raw judge score; operating points are computed offline from those scores.

Usage (needs DEEPSEEK_API_KEY; reuses the fetched external corpus):

  set -a; source .env; set +a
  uv run python evals/detection/judge_arm.py
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import os
import platform
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openai
from external import load_external_cases
from llm_judge import JUDGE_BASE_URL, JUDGE_SYSTEM_PROMPT, JUDGE_USER_GOAL

from agent_guardrail import DetectorRunner
from agent_guardrail.config import (
    DetectorDeploymentProfile,
    create_deployment_detector_registry,
)
from agent_guardrail.detectors import JudgeVerdict, LLMJudgeProfile
from agent_guardrail.models import DetectionContext
from evals.lib import metrics, reporting

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
_DEFAULT_OUTPUT = _ROOT / "data" / "benchmarks" / "detection" / "judge-arm.json"
_DEFAULT_MODEL = "deepseek-v4-flash"
_SWEEP_THRESHOLD = 1e-6
_CUTS = (0.5, 0.6, 0.7, 0.8, 0.9)
_WORKERS = 8


class DeepSeekJudgeBackend:
    """LLMJudgeBackend over one pinned OpenAI-compatible chat endpoint."""

    name = "deepseek-chat-judge"

    def __init__(self, api_key: str, *, model: str) -> None:
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=JUDGE_BASE_URL,
            timeout=120.0,
            max_retries=2,
        )
        self._model = model
        self.version = f"{model}.chat-completions.json-object"

    async def judge(self, text: str) -> JudgeVerdict:
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"User task: {JUDGE_USER_GOAL}\n\nTool output:\n{text}",
                },
            ],
            max_tokens=4000,
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or ""
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match is None:
            raise ValueError("judge response contained no JSON object")
        parsed = json.loads(match.group(0))
        injection = parsed["injection"]
        confidence = parsed["confidence"]
        if not isinstance(injection, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("judge verdict fields are invalid")
        score = float(confidence) if injection else 0.0
        return JudgeVerdict(score=score)


@dataclass(frozen=True, slots=True)
class Observation:
    source: str
    detectability: str
    attack: bool
    score: float | None  # None when the capability failed (unusable)
    elapsed_ms: float


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    from hashlib import sha256

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is required")
    cases = [case for case in load_external_cases() if case.axis == "release_external"]
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        raise SystemExit("no external release cases; run the fetch step first")

    prompt_sha = sha256((JUDGE_SYSTEM_PROMPT + JUDGE_USER_GOAL).encode()).hexdigest()
    backend = DeepSeekJudgeBackend(api_key, model=args.model)
    registry = create_deployment_detector_registry(
        DetectorDeploymentProfile.LOCAL,
        llm_judge_backend=backend,
        llm_judge_profile=LLMJudgeProfile(
            profile_id="release-judge-deepseek",
            profile_version="1",
            prompt_sha256=prompt_sha,
        ),
        llm_judge_threshold=_SWEEP_THRESHOLD,
    )
    runner = DetectorRunner.from_registry(registry)
    detector = runner.capabilities  # validated below that the judge registered
    names = {capability.name for capability in detector}
    if "prompt_injection_judge" not in names:
        raise SystemExit("prompt_injection_judge was not registered")

    from agent_guardrail.core.detector_executor import DetectorExecutionError

    semaphore = asyncio.Semaphore(_WORKERS)

    async def one(case: Any) -> Observation:
        text = case.prior[0].output
        try:
            async with semaphore:
                before = time.perf_counter()  # per-call latency, excluding queue wait
                result = await runner.detect(
                    "prompt_injection_judge",
                    text,
                    context=DetectionContext(
                        trace_id="judge-arm", event_id=case.case_id
                    ),
                )
                elapsed_ms = (time.perf_counter() - before) * 1_000
            score = (
                max(item.confidence for item in result.detections)
                if result.detections
                else 0.0
            )
        except DetectorExecutionError:
            score = None
            elapsed_ms = float("nan")
        return Observation(
            source=case.rationale.split("/", 1)[0],
            detectability=case.detectability or "unclassified",
            attack=case.label == "block",
            score=score,
            elapsed_ms=elapsed_ms,
        )

    started = time.perf_counter()
    observations = list(await asyncio.gather(*(one(case) for case in cases)))
    elapsed = time.perf_counter() - started

    usable = [o for o in observations if o.score is not None]
    return {
        "schema_version": 1,
        "scope": "LLM-judge model arm via the production SDK capability channel",
        "configuration": {
            "model": args.model,
            "capability": "prompt_injection_judge",
            "deployment_threshold": _SWEEP_THRESHOLD,
            "judge_prompt_sha256": prompt_sha,
            "descriptor_timeout_ms": registry.policy_descriptor(
                "prompt_injection_judge"
            ).timeout_ms,
            "workers": _WORKERS,
        },
        "dependencies": {
            "agent_guardrail": importlib.metadata.version("agent-guardrail"),
            "openai": importlib.metadata.version("openai"),
            "python": platform.python_version(),
        },
        "samples": len(cases),
        "elapsed_seconds": elapsed,
        "unusable": len(observations) - len(usable),
        "operating_points": _operating_points(usable),
        "per_source": _per_source(usable),
        "per_detectability": _per_detectability(usable),
        "roc_auc": metrics.roc_auc(
            [o.score for o in usable if o.attack and o.score is not None],
            [o.score for o in usable if not o.attack and o.score is not None],
        ),
        "latency_ms": _latency(observations),
        "observations": [
            {
                "source": o.source,
                "detectability": o.detectability,
                "attack": o.attack,
                "score": o.score,
                "elapsed_ms": round(o.elapsed_ms, 1),
            }
            for o in observations
        ],
    }


def _latency(observations: list[Observation]) -> dict[str, float]:
    values = sorted(o.elapsed_ms for o in observations if o.score is not None)
    if not values:
        return {"median": float("nan"), "p90": float("nan")}
    return {
        "median": round(values[len(values) // 2], 1),
        "p90": round(values[int(len(values) * 0.9)], 1),
    }


def _operating_points(usable: list[Observation]) -> dict[str, Any]:
    scores = [o.score for o in usable if o.score is not None]
    labels = [o.attack for o in usable if o.score is not None]
    grid: dict[str, Any] = {}
    for cut in _CUTS:
        outcome = metrics.confusion_at(scores, labels, cut)
        grid[f"threshold={cut}"] = {
            "recall": None if outcome["recall"] is None else round(outcome["recall"], 4),
            "fpr": (
                None
                if outcome["false_positive_rate"] is None
                else round(outcome["false_positive_rate"], 4)
            ),
        }
    return grid


def _per_detectability(usable: list[Observation]) -> dict[str, dict[str, int]]:
    per_class: dict[str, dict[str, int]] = {}
    for observation in usable:
        bucket = per_class.setdefault(
            observation.detectability, {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        )
        detected = observation.score is not None and observation.score > 0.5
        key = (
            ("tp" if detected else "fn")
            if observation.attack
            else ("fp" if detected else "tn")
        )
        bucket[key] += 1
    return per_class


def _per_source(usable: list[Observation]) -> dict[str, dict[str, int]]:
    per_source: dict[str, dict[str, int]] = {}
    for observation in usable:
        bucket = per_source.setdefault(
            observation.source, {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        )
        detected = observation.score is not None and observation.score > 0.5
        key = (
            ("tp" if detected else "fn")
            if observation.attack
            else ("fp" if detected else "tn")
        )
        bucket[key] += 1
    return per_source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument("--model", default=_DEFAULT_MODEL)
    parser.add_argument("--limit", type=int, default=None, help="debug: cap samples")
    args = parser.parse_args()

    report = asyncio.run(_run(args))
    run_dir = reporting.write_run_report(
        eval_name="detection-judge-arm",
        report=report,
        results_root=_ROOT / "data" / "benchmarks" / "detection",
        repo_root=_ROOT,
        latest_path=args.output.resolve(),
    )
    summary_keys = (
        "samples",
        "unusable",
        "operating_points",
        "per_source",
        "per_detectability",
        "roc_auc",
        "latency_ms",
        "elapsed_seconds",
    )
    summary = {key: report[key] for key in summary_keys}
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"\nreport: {run_dir}")


if __name__ == "__main__":
    main()
