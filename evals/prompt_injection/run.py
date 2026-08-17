#!/usr/bin/env python3
"""Run pinned prompt-injection datasets through the public Detector SDK."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import math
import platform
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from agent_guardrail import DetectorRunner
from agent_guardrail.config.deployment import create_deployment_detector_registry
from agent_guardrail.models import DetectionContext
from evals.lib import detectability, metrics, reporting

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")
_DEFAULT_DATA = _ROOT / "data" / "benchmarks" / "prompt-injection"
_DEFAULT_OUTPUT = _DEFAULT_DATA / "results" / "latest.json"
_DIGEST_HEX_LENGTH = 64
_MAX_REPORT_FAILURE_IDS = 1000


@dataclass(frozen=True, slots=True)
class DatasetFile:
    benchmark_id: str
    dataset_id: str
    attack: bool
    path: Path
    revision: str
    sha256: str
    size_bytes: int
    expected_samples: int


@dataclass(frozen=True, slots=True)
class Sample:
    sample_id: str
    benchmark_id: str
    dataset_id: str
    category: str
    attack: bool
    text: str
    detectability: str


@dataclass(frozen=True, slots=True)
class Observation:
    sample: Sample
    detected: bool
    detection_types: tuple[str, ...]
    elapsed_ms: float
    score: float | None = None


_SWEEP_THRESHOLD_LIMIT = 0.01
_SWEEP_GRID = (0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95)
_PRECISION_AT_RECALL = (0.80, 0.90, 0.95)
_RECALL_AT_FPR = (0.01,)
_SCORED_CAPABILITY = "prompt_injection_model"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate prompt-injection Detectors without an LLM or Agent."
    )
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--data-dir", type=Path, default=_DEFAULT_DATA)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument(
        "--profile",
        choices=("local", "full_local_v1"),
        default="full_local_v1",
    )
    parser.add_argument(
        "--detectors",
        nargs="+",
        default=("prompt_injection", "prompt_injection_model"),
    )
    parser.add_argument("--detector-assets-dir", type=Path)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument(
        "--prompt-model-threshold",
        type=float,
        default=None,
        help=(
            "deployment threshold for prompt_injection_model (default: profile 0.85). "
            "Pass a value <= 0.01 to surface raw scores and enable operating-point "
            "metrics; Detector version identity records the value."
        ),
    )
    return parser.parse_args()


def _load_manifest(path: Path, data_dir: Path) -> tuple[dict[str, Any], list[DatasetFile]]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read benchmark manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise SystemExit("unsupported benchmark manifest")
    benchmarks = manifest.get("benchmarks")
    if not isinstance(benchmarks, list) or not benchmarks:
        raise SystemExit("benchmark manifest has no datasets")

    files: list[DatasetFile] = []
    for benchmark in benchmarks:
        if not isinstance(benchmark, dict):
            raise SystemExit("benchmark manifest entry is invalid")
        benchmark_id = benchmark.get("id")
        label = benchmark.get("label")
        revision = benchmark.get("revision")
        entries = benchmark.get("files")
        if (
            not isinstance(benchmark_id, str)
            or label not in {"attack", "benign"}
            or not isinstance(revision, str)
            or not isinstance(entries, list)
        ):
            raise SystemExit("benchmark manifest metadata is invalid")
        for entry in entries:
            if not isinstance(entry, dict):
                raise SystemExit("benchmark file entry is invalid")
            relative = entry.get("path")
            dataset_id = entry.get("id")
            digest = entry.get("sha256")
            size = entry.get("size_bytes")
            count = entry.get("expected_samples")
            if not isinstance(relative, str):
                raise SystemExit("benchmark file path is invalid")
            parsed = PurePosixPath(relative)
            if parsed.is_absolute() or ".." in parsed.parts:
                raise SystemExit("benchmark file path escapes the data directory")
            if (
                not isinstance(dataset_id, str)
                or not isinstance(digest, str)
                or len(digest) != _DIGEST_HEX_LENGTH
                or not isinstance(size, int)
                or size <= 0
                or not isinstance(count, int)
                or count <= 0
            ):
                raise SystemExit("benchmark file metadata is invalid")
            files.append(
                DatasetFile(
                    benchmark_id=benchmark_id,
                    dataset_id=dataset_id,
                    attack=label == "attack",
                    path=data_dir.joinpath(*parsed.parts),
                    revision=revision,
                    sha256=digest,
                    size_bytes=size,
                    expected_samples=count,
                )
            )
    return manifest, files


def _verified_json(source: DatasetFile) -> Any:
    if (
        source.path.is_symlink()
        or not source.path.is_file()
        or source.path.stat().st_size != source.size_bytes
    ):
        raise SystemExit(f"benchmark input is missing or has the wrong size: {source.path}")
    raw = source.path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source.sha256:
        raise SystemExit(f"benchmark input digest mismatch: {source.path}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"benchmark input is not valid JSON: {source.path}") from exc


def _sample_id(source: DatasetFile, category: str, index: int) -> str:
    material = f"{source.benchmark_id}\0{source.dataset_id}\0{category}\0{index}"
    return f"sample-{hashlib.sha256(material.encode()).hexdigest()[:16]}"


def _load_samples(files: list[DatasetFile]) -> list[Sample]:
    samples: list[Sample] = []
    for source in files:
        raw = _verified_json(source)
        before = len(samples)
        if source.benchmark_id == "notinject":
            if not isinstance(raw, list):
                raise SystemExit(f"NotInject input has an invalid shape: {source.path}")
            for index, item in enumerate(raw):
                if not isinstance(item, dict):
                    raise SystemExit(f"NotInject sample is invalid: {source.path}")
                text = item.get("prompt")
                category = item.get("category")
                if not isinstance(text, str) or not text or not isinstance(category, str):
                    raise SystemExit(f"NotInject sample fields are invalid: {source.path}")
                samples.append(
                    Sample(
                        sample_id=_sample_id(source, category, index),
                        benchmark_id=source.benchmark_id,
                        dataset_id=source.dataset_id,
                        category=category,
                        attack=source.attack,
                        text=text,
                        detectability=detectability.classify_corpus(
                            source.benchmark_id, source.dataset_id
                        ),
                    )
                )
        elif source.benchmark_id == "bipia":
            if not isinstance(raw, dict):
                raise SystemExit(f"BIPIA input has an invalid shape: {source.path}")
            for category, values in raw.items():
                if not isinstance(category, str) or not isinstance(values, list):
                    raise SystemExit(f"BIPIA category is invalid: {source.path}")
                for index, text in enumerate(values):
                    if not isinstance(text, str) or not text:
                        raise SystemExit(f"BIPIA sample is invalid: {source.path}")
                    samples.append(
                        Sample(
                            sample_id=_sample_id(source, category, index),
                            benchmark_id=source.benchmark_id,
                            dataset_id=source.dataset_id,
                            category=category,
                            attack=source.attack,
                            text=text,
                            detectability=detectability.classify_corpus(
                                source.benchmark_id, source.dataset_id
                            ),
                        )
                    )
        else:
            raise SystemExit(f"no parser for benchmark {source.benchmark_id}")
        actual_count = len(samples) - before
        if actual_count != source.expected_samples:
            raise SystemExit(
                f"benchmark sample count mismatch for {source.path}: "
                f"expected {source.expected_samples}, got {actual_count}"
            )
    ids = [sample.sample_id for sample in samples]
    if len(ids) != len(set(ids)):
        raise SystemExit("benchmark sample IDs are not unique")
    return samples


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _metrics(observations: list[Observation]) -> dict[str, Any]:
    true_positive = sum(item.sample.attack and item.detected for item in observations)
    false_negative = sum(item.sample.attack and not item.detected for item in observations)
    false_positive = sum(not item.sample.attack and item.detected for item in observations)
    true_negative = sum(not item.sample.attack and not item.detected for item in observations)
    attack_count = true_positive + false_negative
    benign_count = true_negative + false_positive
    total = attack_count + benign_count
    recall = _ratio(true_positive, attack_count)
    specificity = _ratio(true_negative, benign_count)
    precision = _ratio(true_positive, true_positive + false_positive)
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    balanced_accuracy = (
        round((recall + specificity) / 2, 6)
        if recall is not None and specificity is not None
        else None
    )
    failure_ids = [
        item.sample.sample_id
        for item in observations
        if item.sample.attack != item.detected
    ][:_MAX_REPORT_FAILURE_IDS]
    type_counts = Counter(
        detection_type
        for item in observations
        for detection_type in item.detection_types
    )
    durations = [item.elapsed_ms for item in observations]
    return {
        "samples": total,
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_negative": true_negative,
        },
        "recall": recall,
        "false_positive_rate": _ratio(false_positive, benign_count),
        "specificity": specificity,
        "precision": precision,
        "f1": f1,
        "accuracy": _ratio(true_positive + true_negative, total),
        "balanced_accuracy": balanced_accuracy,
        "detection_type_counts": dict(sorted(type_counts.items())),
        "misclassified_sample_ids": failure_ids,
        "latency_ms": {
            "mean": round(sum(durations) / len(durations), 3) if durations else 0.0,
            "p50": _percentile(durations, 0.50),
            "p95": _percentile(durations, 0.95),
            "p99": _percentile(durations, 0.99),
            "max": round(max(durations), 3) if durations else 0.0,
        },
    }


def _group_metrics(observations: list[Observation]) -> dict[str, Any]:
    grouped: dict[tuple[str, str, str], list[Observation]] = defaultdict(list)
    for item in observations:
        grouped[(item.sample.benchmark_id, item.sample.dataset_id, item.sample.category)].append(
            item
        )
    result: dict[str, Any] = {}
    for (benchmark_id, dataset_id, category), items in sorted(grouped.items()):
        key = f"{benchmark_id}/{dataset_id}/{category}"
        detected = sum(item.detected for item in items)
        result[key] = {
            "label": "attack" if items[0].sample.attack else "benign",
            "samples": len(items),
            "detected": detected,
            "detection_rate": _ratio(detected, len(items)),
        }
    return result


def _detectability_metrics(observations: list[Observation]) -> dict[str, Any]:
    """Full metrics per detectability class (evals/lib/detectability.py)."""

    grouped: dict[str, list[Observation]] = defaultdict(list)
    for item in observations:
        grouped[item.sample.detectability].append(item)
    if "unclassified" in grouped:
        raise SystemExit(
            "unclassified corpus in detectability map; classify it in "
            "evals/lib/detectability.py before reporting"
        )
    return {name: _metrics(items) for name, items in sorted(grouped.items())}


def _cut_outcome(
    observations: list[Observation],
    cut: float,
    *,
    inclusive: bool,
) -> dict[str, Any]:
    """Confusion counts at one score cut; inclusive matches `score >= cut`."""

    return metrics.confusion_at(
        [item.score or 0.0 for item in observations],
        [item.sample.attack for item in observations],
        cut,
        inclusive=inclusive,
    )


def _roc_auc(observations: list[Observation]) -> float | None:
    """Rank-based AUC (Mann-Whitney) with tie handling; None without both classes."""

    return metrics.roc_auc(
        [item.score or 0.0 for item in observations if item.sample.attack],
        [item.score or 0.0 for item in observations if not item.sample.attack],
    )


def _operating_points(
    observations: list[Observation],
    *,
    deployment_threshold: float,
) -> dict[str, Any]:
    """Operating-point metrics over the full score distribution of one Detector."""

    scores = [item.score or 0.0 for item in observations]
    labels = [item.sample.attack for item in observations]
    return {
        "deployment_threshold": deployment_threshold,
        "score_semantics": (
            "Detection confidence captured at the deployment threshold above; "
            "samples without a Detection count as score 0.0; threshold_grid rows "
            "use the Detector semantics `detected iff score > threshold`"
        ),
        "roc_auc": _roc_auc(observations),
        "precision_at_recall": metrics.precision_at_recall(scores, labels, _PRECISION_AT_RECALL),
        "recall_at_fpr": metrics.recall_at_fpr(scores, labels, _RECALL_AT_FPR),
        "threshold_grid": {
            str(threshold): _cut_outcome(observations, threshold, inclusive=False)
            for threshold in _SWEEP_GRID
        },
    }


def _git_revision() -> str | None:
    return reporting.git_revision(_ROOT)["revision"]


def _package_versions() -> dict[str, str]:
    names = ("agent-guardrail", "torch", "transformers")
    versions: dict[str, str] = {}
    for name in names:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return versions


async def _run(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    manifest_path = args.manifest.resolve()
    data_dir = args.data_dir.resolve()
    manifest, files = _load_manifest(manifest_path, data_dir)
    samples = _load_samples(files)
    if args.profile == "full_local_v1" and args.detector_assets_dir is None:
        raise SystemExit("--detector-assets-dir is required for full_local_v1")
    if args.prompt_model_threshold is not None and not (
        0.0 < args.prompt_model_threshold <= 1.0
    ):
        raise SystemExit("--prompt-model-threshold must be a float in (0, 1]")
    sweep_enabled = (
        args.prompt_model_threshold is not None
        and args.prompt_model_threshold <= _SWEEP_THRESHOLD_LIMIT
        and _SCORED_CAPABILITY in args.detectors
    )
    runner = DetectorRunner.from_registry(
        create_deployment_detector_registry(
            args.profile,
            prompt_model_device=args.device,
            detector_assets_dir=(
                args.detector_assets_dir.resolve() if args.detector_assets_dir is not None else None
            ),
            **(
                {"prompt_model_threshold": args.prompt_model_threshold}
                if args.prompt_model_threshold is not None
                else {}
            ),
        )
    )
    capabilities = {capability.name: capability for capability in runner.capabilities}
    selected = tuple(args.detectors)
    if len(selected) != len(set(selected)):
        raise SystemExit("--detectors must not contain duplicates")
    missing = [name for name in selected if name not in capabilities]
    if missing:
        raise SystemExit(
            f"selected Detector is unavailable in {args.profile}: {', '.join(missing)}"
        )
    for sample in samples:
        size = len(sample.text.encode("utf-8"))
        for name in selected:
            if size > capabilities[name].max_input_bytes:
                raise SystemExit(
                    f"{sample.sample_id} exceeds {name}'s published input-byte limit"
                )

    started = time.perf_counter()
    detector_observations: dict[str, list[Observation]] = {name: [] for name in selected}
    ensemble_observations: list[Observation] = []
    for index, sample in enumerate(samples, start=1):
        sample_detections: list[str] = []
        sample_elapsed = 0.0
        for name in selected:
            before = time.perf_counter()
            result = await runner.detect(
                name,
                sample.text,
                context=DetectionContext(
                    trace_id="prompt-injection-benchmark",
                    event_id=sample.sample_id,
                ),
            )
            elapsed_ms = (time.perf_counter() - before) * 1000
            detection_types = tuple(sorted({item.type for item in result.detections}))
            score: float | None = None
            if sweep_enabled and name == _SCORED_CAPABILITY:
                score = (
                    max(item.confidence for item in result.detections)
                    if result.detections
                    else 0.0
                )
            detector_observations[name].append(
                Observation(
                    sample=sample,
                    detected=result.detected,
                    detection_types=detection_types,
                    elapsed_ms=elapsed_ms,
                    score=score,
                )
            )
            sample_elapsed += elapsed_ms
            sample_detections.extend(detection_types)
        ensemble_observations.append(
            Observation(
                sample=sample,
                detected=bool(sample_detections),
                detection_types=tuple(sorted(set(sample_detections))),
                elapsed_ms=sample_elapsed,
            )
        )
        if index % 50 == 0 or index == len(samples):
            print(f"evaluated {index}/{len(samples)} samples", file=sys.stderr)

    results: dict[str, Any] = {}
    for name, observations in detector_observations.items():
        results[name] = {
            "capability": {
                "name": capabilities[name].name,
                "version": capabilities[name].version,
                "max_input_bytes": capabilities[name].max_input_bytes,
                "timeout_ms": capabilities[name].timeout_ms,
            },
            "overall": _metrics(observations),
            "categories": _group_metrics(observations),
            "detectability": _detectability_metrics(observations),
        }
        if sweep_enabled and name == _SCORED_CAPABILITY:
            assert args.prompt_model_threshold is not None
            results[name]["operating_points"] = _operating_points(
                observations,
                deployment_threshold=args.prompt_model_threshold,
            )
    if len(selected) > 1:
        results["ensemble_any"] = {
            "members": list(selected),
            "overall": _metrics(ensemble_observations),
            "categories": _group_metrics(ensemble_observations),
            "detectability": _detectability_metrics(ensemble_observations),
        }

    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "prompt-injection Detector classification; no Agent, LLM, or tool execution",
        "configuration": {
            "profile": args.profile,
            "device": args.device,
            "detectors": list(selected),
            "prompt_model_threshold": args.prompt_model_threshold,
            "operating_points_enabled": sweep_enabled,
            "manifest_sha256": manifest_digest,
        },
        "environment": {
            "guardrail_revision": _git_revision(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "packages": _package_versions(),
        },
        "datasets": [
            {
                "id": benchmark["id"],
                "label": benchmark["label"],
                "repository": benchmark["repository"],
                "revision": benchmark["revision"],
                "license": benchmark["license"],
                "samples": sum(
                    source.expected_samples
                    for source in files
                    if source.benchmark_id == benchmark["id"]
                ),
            }
            for benchmark in manifest["benchmarks"]
        ],
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "results": results,
    }
    summary = {
        name: {
            "recall": result["overall"]["recall"],
            "false_positive_rate": result["overall"]["false_positive_rate"],
            "balanced_accuracy": result["overall"]["balanced_accuracy"],
        }
        for name, result in results.items()
    }
    run_dir = reporting.write_run_report(
        eval_name="prompt-injection",
        report=report,
        results_root=data_dir,
        repo_root=_ROOT,
        latest_path=args.output.resolve(),
        summary=summary,
    )
    return report, run_dir


def main() -> None:
    args = _parse_args()
    report, output = asyncio.run(_run(args))
    print(f"report: {output}")
    for name, result in report["results"].items():
        metrics = result["overall"]
        print(
            f"{name}: recall={metrics['recall']} "
            f"false_positive_rate={metrics['false_positive_rate']} "
            f"balanced_accuracy={metrics['balanced_accuracy']}"
        )
        points = result.get("operating_points")
        if points is not None:
            grid = points["threshold_grid"]
            print(
                f"{name} operating points: roc_auc={points['roc_auc']} "
                f"prec@recall0.95={points['precision_at_recall'].get('0.95')} "
                f"recall@fpr0.01={points['recall_at_fpr'].get('0.01')}"
            )
            print(
                f"{name} threshold grid: "
                + " | ".join(
                    f"{threshold}: R={row['recall']} FPR={row['false_positive_rate']}"
                    for threshold, row in sorted(
                        grid.items(), key=lambda item: float(item[0])
                    )
                )
            )


if __name__ == "__main__":
    main()
