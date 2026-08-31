#!/usr/bin/env python3
"""Export the pinned AgentDojo injection payload corpus for Detector evaluation.

Run under the isolated ``evals/corpus`` environment:

    uv run --project evals/corpus python evals/prompt_injection/gen_agentdojo.py

The output contains attack payloads only. It does not run an Agent and cannot
produce an attack-success rate.
"""

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path

from agentdojo.attacks.important_instructions_attacks import (  # pyright: ignore[reportMissingImports]
    ImportantInstructionsAttack,
)
from agentdojo.task_suite.load_suites import get_suite  # pyright: ignore[reportMissingImports]

_ROOT = Path(__file__).resolve().parents[2]
_OUTPUT_DIR = _ROOT / "data" / "benchmarks" / "prompt-injection"
_RELEASE_OUTPUT = _OUTPUT_DIR / "agentdojo-release.json"
_BENCHMARK_VERSION = "v1.2.2"
_SUITES = ("workspace", "travel", "banking", "slack")
_USER_NAME = "Emma Johnson"
_MODEL_NAME = "ChatGPT"


def main() -> None:
    template = ImportantInstructionsAttack._JB_STRING
    entries = []
    for suite_name in _SUITES:
        suite = get_suite(_BENCHMARK_VERSION, suite_name)
        for task_id, task in suite.injection_tasks.items():
            entries.append(
                {
                    "suite": suite_name,
                    "task_id": task_id,
                    "goal": task.GOAL,
                    "attack_text": template.format(
                        user=_USER_NAME,
                        model=_MODEL_NAME,
                        goal=task.GOAL,
                    ),
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
    print(f"wrote {len(entries)} injection payloads to {_RELEASE_OUTPUT}")


if __name__ == "__main__":
    main()
