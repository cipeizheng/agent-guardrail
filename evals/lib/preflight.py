"""Measurement-power preflight for comparative evals.

A comparative eval only measures something when its control arm shows signal:
a baseline attack-success rate of 0 makes every guarded-arm number
indistinguishable from "the attack never fired" (the AgentDojo floor-effect
finding in evals/NEXT-STEPS.md). This module centralizes that check so each
comparative entry point aborts before spending the treatment arm.
"""

from __future__ import annotations

from typing import Any


def measurement_power(successes: int, trials: int) -> dict[str, Any]:
    """Describe the control arm's signal; ``ok`` is False when it shows none."""

    rate = successes / trials if trials else None
    return {
        "successes": successes,
        "trials": trials,
        "success_rate": None if rate is None else round(rate, 4),
        "has_measurement_power": bool(trials) and successes > 0,
    }


def require_measurement_power(
    check: dict[str, Any],
    *,
    arm: str,
    remedy: str,
    allow_none: bool = False,
) -> None:
    """Abort with an actionable message when the control arm shows no signal.

    ``allow_none`` records the zero-signal run instead of aborting (for
    deliberate floor-effect documentation runs).
    """

    if check["has_measurement_power"] or allow_none:
        return
    raise SystemExit(
        f"no measurement power: {arm} shows {check['successes']} successes over "
        f"{check['trials']} trials; every treatment-arm number would be "
        f"indistinguishable from 'the attack never fired'. {remedy} "
        f"Pass --allow-floor to record this floor-effect run anyway."
    )
