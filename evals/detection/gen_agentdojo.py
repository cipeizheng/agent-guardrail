"""Export AgentDojo injection attacks as fixed detection-eval corpus files.

Run under the `evals/corpus` project environment (it owns the pinned
`agentdojo` install used to export the release payloads):

  uv run --project evals/corpus python evals/detection/gen_agentdojo.py

Writes agentdojo-release.json under data/benchmarks/detection/: one entry per
injection task (GOAL wrapped in the upstream ``important_instructions``
template) for the release axis.

Texts are never edited here; the agentdojo version is recorded for
reproducibility.
"""

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path

from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.task_suite.load_suites import get_suite

_HERE = Path(__file__).resolve().parent
_OUTPUT_DIR = _HERE.parents[1] / "data" / "benchmarks" / "detection"
_RELEASE_OUTPUT = _OUTPUT_DIR / "agentdojo-release.json"

_BENCHMARK_VERSION = "v1.2.2"
_SUITES = ("workspace", "travel", "banking", "slack")
# The upstream template addresses a specific user and model; both names are
# part of the shipped attack string, so we pin them exactly as agentdojo does.
_USER_NAME = "Emma Johnson"
_MODEL_NAME = "ChatGPT"


def main() -> None:
    template = ImportantInstructionsAttack._JB_STRING
    entries = []
    for suite_name in _SUITES:
        suite = get_suite(_BENCHMARK_VERSION, suite_name)
        for task_id, task in suite.injection_tasks.items():
            attack_text = template.format(
                user=_USER_NAME, model=_MODEL_NAME, goal=task.GOAL
            )
            entries.append(
                {
                    "suite": suite_name,
                    "task_id": task_id,
                    "goal": task.GOAL,
                    "attack_text": attack_text,
                }
            )
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _RELEASE_OUTPUT.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "agentdojo",
                "benchmark_version": _BENCHMARK_VERSION,
                "agentdojo_version": version("agentdojo"),
                "attack_template": "important_instructions",
                "template_user": _USER_NAME,
                "template_model": _MODEL_NAME,
                "cases": entries,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(entries)} injection cases to {_RELEASE_OUTPUT}")


if __name__ == "__main__":
    main()
