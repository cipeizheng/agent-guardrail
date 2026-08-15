"""Run the per-decision-point detection eval and print per-axis confusion matrices.

Usage:
  uv run python evals/detection/run.py                          # local profile
  uv run --project evals/agentdojo python evals/detection/run.py \\
      --profile full_local_v1                                   # model PI detector

Two channels over the same corpus: the GuardrailRun decision layer (policy
ALLOW/BLOCK per decision point) and the DetectorRunner fact layer (detector
facts per probed text), so decision-layer mismatches can be attributed to
either a detector gap or a rule composition gap.

The default `local` profile needs no model credentials or external assets.
`full_local_v1` additionally publishes the fixed DeBERTa prompt-injection
classifier (plus semgrep/yara/presidio backends) and runs the model-based
release policy as a second ablation arm.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

from corpus import ALL_CASES, Case, FactProbe
from replay import replay_case

from agent_guardrail import DetectorRunner
from agent_guardrail.config import (
    DetectorDeploymentProfile,
    PromptModelDevice,
    create_default_detector_registry,
    create_default_predicate_registry,
    create_deployment_detector_registry,
    load_policy_file,
)
from agent_guardrail.core import MatchPolicyAnalyzer

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
_DEFAULT_OUTPUT = _ROOT / "data" / "benchmarks" / "detection" / "latest.json"
_DEFAULT_ASSETS = _ROOT / "data" / "detector-assets"


def _policy_matrix(registry_capabilities: frozenset[str]) -> dict[str, tuple[str, ...]]:
    """axis -> policies under test; extra arms appear only when published."""

    matrix: dict[str, tuple[str, ...]] = {
        "constraint": ("constraint.yaml",),
        "content": ("content.yaml",),
        "flow": ("flow-call-level.yaml", "flow-field-level.yaml"),
        "release": ("release-injection.yaml",),
        "code": ("code-execution.yaml",),
    }
    if "prompt_injection_model" in registry_capabilities:
        matrix["release"] = ("release-injection.yaml", "release-injection-model.yaml")
    return matrix


# Axes whose cases carry fact probes for the DetectorRunner channel.
FACT_AXES = ("content", "release")


@dataclass(frozen=True, slots=True)
class Outcome:
    case: Case
    predicted_block: bool


@dataclass(frozen=True, slots=True)
class Matrix:
    policy: str
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def benign_fpr(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def attack_fnr(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.false_negatives / denominator if denominator else 0.0

    @property
    def precision(self) -> float | None:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else None

    def as_dict(self) -> dict[str, object]:
        return {
            "policy": self.policy,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "benign_fpr": round(self.benign_fpr, 4),
            "attack_fnr": round(self.attack_fnr, 4),
            "precision": None if self.precision is None else round(self.precision, 4),
            "recall": None if self.recall is None else round(self.recall, 4),
        }


def _build_analyzer(policy_name: str, registry) -> MatchPolicyAnalyzer:
    return MatchPolicyAnalyzer(
        load_policy_file(
            _HERE / "policies" / policy_name,
            detectors=registry,
            predicates=create_default_predicate_registry(),
        )
    )


def _run_policy(
    policy_name: str, registry, cases: Sequence[Case]
) -> tuple[Matrix, tuple[Outcome, ...]]:
    analyzer = _build_analyzer(policy_name, registry)
    outcomes = tuple(Outcome(case, replay_case(analyzer, case)) for case in cases)
    matrix = Matrix(
        policy=policy_name,
        true_positives=sum(
            1 for o in outcomes if o.case.label == "block" and o.predicted_block
        ),
        false_positives=sum(
            1 for o in outcomes if o.case.label == "allow" and o.predicted_block
        ),
        true_negatives=sum(
            1 for o in outcomes if o.case.label == "allow" and not o.predicted_block
        ),
        false_negatives=sum(
            1 for o in outcomes if o.case.label == "block" and not o.predicted_block
        ),
    )
    return matrix, outcomes


def _print_matrix(axis: str, matrix: Matrix) -> None:
    print(f"[{axis}] policy={matrix.policy}")
    print(
        f"  TP={matrix.true_positives}  FP={matrix.false_positives}  "
        f"TN={matrix.true_negatives}  FN={matrix.false_negatives}  "
        f"benign_fpr={matrix.benign_fpr:.2f}  attack_fnr={matrix.attack_fnr:.2f}"
    )


def _print_outcomes(outcomes: Sequence[Outcome]) -> None:
    for outcome in outcomes:
        predicted = "BLOCK" if outcome.predicted_block else "ALLOW"
        if outcome.case.label == "dual_use":
            print(f"  ?? {outcome.case.case_id}: label=DUAL_USE predicted={predicted}")
            continue
        label = outcome.case.label.upper()
        marker = "ok " if predicted == label else "XX "
        print(f"  {marker}{outcome.case.case_id}: label={label} predicted={predicted}")
    print()


@dataclass(frozen=True, slots=True)
class FactMatrix:
    capability: str
    hits: int
    misses: int
    false_alarms: int
    clean: int

    @property
    def recall(self) -> float | None:
        denominator = self.hits + self.misses
        return self.hits / denominator if denominator else None

    @property
    def fpr(self) -> float | None:
        denominator = self.false_alarms + self.clean
        return self.false_alarms / denominator if denominator else None

    def as_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "expected_fact_hit": self.hits,
            "expected_fact_missed": self.misses,
            "unexpected_fact": self.false_alarms,
            "expected_clean": self.clean,
            "fact_recall": None if self.recall is None else round(self.recall, 4),
            "fact_fpr": None if self.fpr is None else round(self.fpr, 4),
        }


async def _run_fact_channel(
    runner: DetectorRunner,
    probes: Sequence[tuple[str, FactProbe]],
) -> tuple[dict[str, FactMatrix], dict[tuple[str, str], bool]]:
    """Detector facts for every probe; returns per-capability matrices and per-probe hits."""

    hits: dict[tuple[str, str], bool] = {}
    for case_id, probe in probes:
        result = await runner.detect_text(probe.capability, probe.text)
        hits[(case_id, probe.capability)] = result.detected
    matrices: dict[str, FactMatrix] = {}
    capabilities = sorted({probe.capability for _, probe in probes})
    for capability in capabilities:
        selected = [(c, p) for c, p in probes if p.capability == capability]
        matrices[capability] = FactMatrix(
            capability=capability,
            hits=sum(
                1
                for case_id, probe in selected
                if probe.expect_fact and hits[(case_id, capability)]
            ),
            misses=sum(
                1
                for case_id, probe in selected
                if probe.expect_fact and not hits[(case_id, capability)]
            ),
            false_alarms=sum(
                1
                for case_id, probe in selected
                if not probe.expect_fact and hits[(case_id, capability)]
            ),
            clean=sum(
                1
                for case_id, probe in selected
                if not probe.expect_fact and not hits[(case_id, capability)]
            ),
        )
    return matrices, hits


def _attribute_mismatch(
    case: Case,
    fact_hits: dict[tuple[str, str], bool],
) -> str:
    """Attribute a decision-layer miss to a detector gap or a rule composition gap."""

    if not case.fact_probes:
        return "no fact probes on this case"
    if case.label == "block":
        any_fact = any(fact_hits.get((case.case_id, p.capability)) for p in case.fact_probes)
        return "detector gap" if not any_fact else "rule composition gap"
    return "detector false alarm"


def _build_registry(args: argparse.Namespace):
    """Build the detector registry for the requested deployment profile."""

    if args.profile == DetectorDeploymentProfile.LOCAL.value:
        return create_default_detector_registry()
    return create_deployment_detector_registry(
        args.profile,
        prompt_model_device=args.device,
        detector_assets_dir=args.detector_assets_dir,
    )


def _fact_probes(registry) -> tuple[tuple[str, FactProbe], ...]:
    """Collect probes; the model PI arm reuses the heuristic probe texts."""

    probes = [
        (case.case_id, probe)
        for case in ALL_CASES
        if case.axis in FACT_AXES
        for probe in case.fact_probes
    ]
    capabilities = frozenset(
        descriptor.name for descriptor in registry.published_detector_descriptors()
    )
    if "prompt_injection_model" in capabilities:
        probes.extend(
            (case_id, FactProbe("prompt_injection_model", probe.text, probe.expect_fact))
            for case_id, probe in probes
            if probe.capability == "prompt_injection"
        )
    return tuple(probes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument(
        "--profile",
        choices=[profile.value for profile in DetectorDeploymentProfile],
        default=DetectorDeploymentProfile.LOCAL.value,
        help="detector deployment profile (full_local_v1 adds the PI model)",
    )
    parser.add_argument(
        "--detector-assets-dir",
        type=Path,
        default=_DEFAULT_ASSETS,
        help="model/runtime assets root for full_local_v1",
    )
    parser.add_argument(
        "--device",
        choices=[device.value for device in PromptModelDevice],
        default=PromptModelDevice.CPU.value,
        help="execution device for the prompt-injection model",
    )
    args = parser.parse_args()

    registry = _build_registry(args)
    policy_matrix = _policy_matrix(
        frozenset(
            descriptor.name for descriptor in registry.published_detector_descriptors()
        )
    )

    report: dict[str, object] = {
        "schema_version": 1,
        "scope": "per-decision-point policy detection, per-axis confusion matrix",
        "agent_guardrail": version("agent-guardrail"),
        "profile": args.profile,
        "axes": {},
        "limitations": [
            "BLOCK samples are author-scripted and carry author-imagination bias.",
            "ALLOW samples are scripted; real-model benign trace harvesting is planned.",
            "dual_use cases are reported separately and excluded from the matrices.",
        ],
    }

    fact_matrices, fact_hits = asyncio.run(
        _run_fact_channel(DetectorRunner.from_registry(registry), _fact_probes(registry))
    )
    print(f"[fact layer] DetectorRunner channel over the same corpus (profile={args.profile})")
    for matrix in fact_matrices.values():
        print(
            f"  {matrix.capability}: expected_hit={matrix.hits}  "
            f"missed={matrix.misses}  false_alarm={matrix.false_alarms}  "
            f"clean={matrix.clean}  recall={matrix.recall}  fpr={matrix.fpr}"
        )
    print()
    report["fact_layer"] = {
        name: matrix.as_dict() for name, matrix in fact_matrices.items()
    }

    failures = 0
    for axis, policy_names in policy_matrix.items():
        cases = tuple(case for case in ALL_CASES if case.axis == axis)
        axis_report: dict[str, object] = {"cases": len(cases)}
        for policy_name in policy_names:
            matrix, outcomes = _run_policy(policy_name, registry, cases)
            _print_matrix(axis, matrix)
            _print_outcomes(outcomes)
            judged = tuple(o for o in outcomes if o.case.label != "dual_use")
            failures += sum(
                1 for o in judged if (o.case.label == "block") != o.predicted_block
            )
            mismatches = []
            for outcome in judged:
                if (outcome.case.label == "block") == outcome.predicted_block:
                    continue
                attribution = _attribute_mismatch(outcome.case, fact_hits)
                print(
                    f"    attribution[{outcome.case.case_id}]: {attribution}"
                )
                mismatches.append(
                    {
                        "case": outcome.case.case_id,
                        "label": outcome.case.label,
                        "predicted": "block" if outcome.predicted_block else "allow",
                        "rationale": outcome.case.rationale,
                        "attribution": attribution,
                    }
                )
            axis_report[policy_name] = {
                **matrix.as_dict(),
                "mismatches": mismatches,
                "dual_use": [
                    {
                        "case": o.case.case_id,
                        "predicted": "block" if o.predicted_block else "allow",
                        "rationale": o.case.rationale,
                    }
                    for o in outcomes
                    if o.case.label == "dual_use"
                ],
            }
        report["axes"][axis] = axis_report  # type: ignore[index]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"report written to {args.output}")
    print(f"mismatched decisions: {failures}")


if __name__ == "__main__":
    main()
