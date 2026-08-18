#!/usr/bin/env python3
"""DeBERTa on AgentDojo injection payloads (the missing corpus cell).

PromptGuard 2 reports AUC 0.942 for injection detection on AgentDojo
(LlamaFirewall paper, Table 4.3); our prompt_injection_model (Protect AI
DeBERTa v2) showed AUC 0.365 on BIPIA/NotInject. Those corpora are not
comparable: BIPIA text attacks are content_undetectable by construction and
NotInject are trigger-word benign hard negatives, while AgentDojo injections
use the "important instructions" template that detectability.py classifies
as style_detectable. This probe scores the pinned DeBERTa on the AgentDojo
release payloads (35 attacks) against the NotInject hard negatives (339
benign) - the cell our fact-layer eval never measured - so the
classifier-gap question and the corpus-choice question separate.

No gate: a characterization probe recorded via evals.lib reporting.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_guardrail.config.deployment import PromptModelDevice, create_prompt_classifier
from evals.lib import metrics, reporting

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
_DEFAULT_DATA = _ROOT / "data" / "benchmarks"
_DEFAULT_ASSETS = _ROOT / "data" / "detector-assets"
_THRESHOLD = 0.85  # deployment operating point


@dataclass(frozen=True, slots=True)
class Scored:
    label: bool
    score: float
    elapsed_ms: float


async def _load_texts() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """AgentDojo attack payloads from the release corpus + NotInject negatives."""
    import json

    sys.path.insert(0, str(_HERE))
    from run import Sample, _load_manifest, _load_samples  # reuse the pinned loader

    release = json.loads((_DEFAULT_DATA / "detection" / "agentdojo-release.json").read_text())
    attacks = [
        {
            "sample_id": f"aj-{case['suite']}-{case['task_id']}",
            "text": case["attack_text"],
            "attack": True,
        }
        for case in release["cases"]
    ]
    manifest, files = _load_manifest(_HERE / "manifest.json", _DEFAULT_DATA / "prompt-injection")
    samples: list[Sample] = _load_samples(files)
    negatives = [
        {
            "sample_id": f"ni-{sample.sample_id}",
            "text": sample.text,
            "attack": False,
        }
        for sample in samples
        if sample.benchmark_id == "notinject"
    ]
    return attacks, negatives


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    attacks, negatives = await _load_texts()
    if len(attacks) != 35:
        raise SystemExit(f"expected 35 AgentDojo attack payloads, got {len(attacks)}")
    if not negatives:
        raise SystemExit("no NotInject negatives loaded")

    classifier = create_prompt_classifier(
        device=PromptModelDevice.CPU,
        assets_dir=args.detector_assets_dir.resolve(),
    )

    scored: list[Scored] = []
    for item in (*attacks, *negatives):
        before = time.perf_counter()
        result = await classifier.classify(item["text"])
        elapsed_ms = (time.perf_counter() - before) * 1_000
        scored.append(Scored(label=item["attack"], score=result.score, elapsed_ms=elapsed_ms))

    attack_scores = [item.score for item in scored if item.label]
    benign_scores = [item.score for item in scored if not item.label]
    labels = [item.label for item in scored]
    scores = [item.score for item in scored]
    return {
        "scope": "DeBERTa on AgentDojo payloads vs NotInject negatives (corpus cell probe)",
        "configuration": {
            "capability": "prompt_injection_model",
            "deployment_threshold": _THRESHOLD,
            "n_attack": len(attack_scores),
            "n_benign": len(benign_scores),
        },
        "operating_point": metrics.confusion_at(scores, labels, _THRESHOLD),
        "roc_auc": metrics.roc_auc(attack_scores, benign_scores),
        "attack_score_distribution": _distribution(attack_scores),
        "benign_score_distribution": _distribution(benign_scores),
        "elapsed_ms_median_attack": _median([item.elapsed_ms for item in scored if item.label]),
    }


def _distribution(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)

    def quantile(q: float) -> float:
        index = min(len(ordered) - 1, round(q * (len(ordered) - 1)))
        return ordered[index]

    return {
        "min": ordered[0],
        "p10": quantile(0.1),
        "median": quantile(0.5),
        "p90": quantile(0.9),
        "max": ordered[-1],
    }


def _median(values: list[float]) -> float:
    return _distribution(values)["median"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--detector-assets-dir",
        type=Path,
        default=_DEFAULT_ASSETS,
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=_DEFAULT_DATA / "prompt-injection",
    )
    args = parser.parse_args()

    report = asyncio.run(_run(args))
    run_dir = reporting.write_run_report(
        eval_name="prompt-injection-agentdojo-payloads",
        report=report,
        results_root=args.results_root,
        repo_root=_ROOT,
        latest_path=args.results_root / "results" / "agentdojo-payloads-latest.json",
        summary={
            "roc_auc": report["roc_auc"],
            "recall_at_threshold": report["operating_point"]["recall"],
            "fpr_at_threshold": report["operating_point"]["false_positive_rate"],
        },
    )
    print(f"roc_auc={report['roc_auc']}")
    print(f"recall@{_THRESHOLD}={report['operating_point']['recall']} "
          f"fpr={report['operating_point']['false_positive_rate']}")
    print(f"attack score median={report['attack_score_distribution']['median']}")
    print(f"report: {run_dir}")


if __name__ == "__main__":
    main()
