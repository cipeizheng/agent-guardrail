"""Export AgentDojo injection attacks as a fixed release-axis corpus file.

Run under the agentdojo project environment (it owns the agentdojo install):

  uv run --project evals/agentdojo python evals/detection/gen_agentdojo.py

Writes data/benchmarks/detection/agentdojo-release.json: one entry per
injection task across the v1.2.2 suites, each carrying the task's own GOAL
and the GOAL wrapped in the upstream ``important_instructions`` template.
The corpus file records the agentdojo version so the export is reproducible;
texts are never edited here.
"""

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path

from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.task_suite.load_suites import get_suite

_HERE = Path(__file__).resolve().parent
_OUTPUT = _HERE.parents[1] / "data" / "benchmarks" / "detection" / "agentdojo-release.json"

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
    _OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    _OUTPUT.write_text(
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
    print(f"wrote {len(entries)} injection cases to {_OUTPUT}")


if __name__ == "__main__":
    main()
