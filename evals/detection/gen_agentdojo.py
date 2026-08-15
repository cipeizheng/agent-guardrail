"""Export AgentDojo injection attacks as fixed detection-eval corpus files.

Run under the agentdojo project environment (it owns the agentdojo install):

  uv run --project evals/agentdojo python evals/detection/gen_agentdojo.py

Writes two files under data/benchmarks/detection/:

- agentdojo-release.json: one entry per injection task (GOAL wrapped in the
  upstream ``important_instructions`` template) for the release axis.
- agentdojo-flow.json: the flow axis. Attack side = the malicious sink call
  each injection task's ground_truth prescribes, replayed with the attack text
  in one untrusted read output. Benign side = every user task with a sink
  write call, split by whether the destination value appears literally in the
  task's PROMPT (named vs delegated; see preregistration.md).

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
_FLOW_OUTPUT = _OUTPUT_DIR / "agentdojo-flow.json"

_BENCHMARK_VERSION = "v1.2.2"
_SUITES = ("workspace", "travel", "banking", "slack")
# The upstream template addresses a specific user and model; both names are
# part of the shipped attack string, so we pin them exactly as agentdojo does.
_USER_NAME = "Emma Johnson"
_MODEL_NAME = "ChatGPT"

# Destination-like sink arguments (coverage knowledge, disclosed in the prereg).
_DEST_ARGS = (
    "recipient",
    "recipients",
    "to",
    "channel",
    "file_path",
    "file_id",
    "email_id",
    "user",
    "user_id",
    "username",
    "password",
    "hotel",
)
_SINK_TOOLS = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "send_email",
    "send_channel_message",
    "send_direct_message",
    "invite_user_to_slack",
    "remove_user_from_slack",
    "add_user_to_channel",
    "delete_file",
    "create_file",
    "append_to_file",
    "share_file",
    "delete_email",
    "reserve_hotel",
    "update_password",
}
# One plausible read tool per suite; used as the untrusted prior step whose
# output carries the injection (attack) or the looked-up value (benign).
_READ_TOOL = {
    "workspace": ("search_emails", {"query": "bill"}),
    "banking": ("get_most_recent_transactions", {}),
    "slack": ("read_channel_messages", {"channel": "general"}),
    "travel": ("get_all_restaurants_in_city", {"city": "Paris"}),
}


def _dest_calls(calls) -> list[dict]:
    """Sink calls with a destination-like argument; lists flattened to text."""

    found = []
    for call in calls:
        if call.function not in _SINK_TOOLS:
            continue
        for key, value in call.args.items():
            if key not in _DEST_ARGS:
                continue
            if isinstance(value, list):
                value = ",".join(str(item) for item in value)
            if not isinstance(value, str) or not value:
                continue
            arguments = {
                name: (",".join(str(v) for v in arg) if isinstance(arg, list) else arg)
                for name, arg in call.args.items()
            }
            found.append(
                {
                    "function": call.function,
                    "dest_arg": key,
                    "dest_value": value,
                    "arguments": arguments,
                }
            )
            break
    return found


def _flow_export() -> dict:
    attack_cases = []
    benign_cases = []
    for suite_name in _SUITES:
        suite = get_suite(_BENCHMARK_VERSION, suite_name)
        environment = suite.load_and_inject_default_environment({})
        user_tasks = list(suite.user_tasks.values())
        for task_id, task in suite.injection_tasks.items():
            dests = _dest_calls(task.ground_truth(environment))
            if not dests:
                continue
            attack_text = ImportantInstructionsAttack._JB_STRING.format(
                user=_USER_NAME, model=_MODEL_NAME, goal=task.GOAL
            )
            # Pair with the first benign prompt that does not name the
            # attacker's destination, so the pending call cannot be excused.
            user_prompt = next(
                user_task.PROMPT
                for user_task in user_tasks
                if dests[0]["dest_value"].lower() not in user_task.PROMPT.lower()
            )
            attack_cases.append(
                {
                    "suite": suite_name,
                    "task_id": task_id,
                    "goal": task.GOAL,
                    "attack_text": attack_text,
                    "user_prompt": user_prompt,
                    "sink_call": dests[0],
                }
            )
        for user_task in user_tasks:
            dests = _dest_calls(user_task.ground_truth(environment))
            if not dests:
                continue
            named = dests[0]["dest_value"].lower() in user_task.PROMPT.lower()
            benign_cases.append(
                {
                    "suite": suite_name,
                    "task_id": user_task.ID,
                    "prompt": user_task.PROMPT,
                    "named": named,
                    "sink_call": dests[0],
                }
            )
    return {
        "schema_version": 1,
        "source": "agentdojo",
        "benchmark_version": _BENCHMARK_VERSION,
        "agentdojo_version": version("agentdojo"),
        "read_tools": _READ_TOOL,
        "attack_cases": attack_cases,
        "benign_cases": benign_cases,
    }


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

    flow = _flow_export()
    _FLOW_OUTPUT.write_text(json.dumps(flow, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    named = sum(1 for case in flow["benign_cases"] if case["named"])
    print(
        f"wrote {len(flow['attack_cases'])} attack / {len(flow['benign_cases'])} benign "
        f"({named} named, {len(flow['benign_cases']) - named} delegated) to {_FLOW_OUTPUT}"
    )


if __name__ == "__main__":
    main()
