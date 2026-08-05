"""The side-effect-free guardrail decision engine."""

from __future__ import annotations

import asyncio

from pydantic import JsonValue

from agent_guardrail.core.policy import PolicySet, RuleBinding
from agent_guardrail.core.registry import DetectorRegistry
from agent_guardrail.core.services import DetectorTimeoutError, RuleServices
from agent_guardrail.models import (
    ACTION_PRIORITY,
    Action,
    Decision,
    GuardrailContext,
    PendingTrace,
    Violation,
)


class GuardrailEngine:
    """Evaluate trusted rules and aggregate their configured actions."""

    def __init__(self, *, policy: PolicySet, detectors: DetectorRegistry) -> None:
        self.policy = policy
        self.detectors = detectors

    async def evaluate(self, context: GuardrailContext) -> Decision:
        """Adapt the v0.1 single-event context to the pending analyzer."""

        return await self.analyze_pending(PendingTrace.from_context(context))

    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        """Analyze an atomic pending batch without performing external side effects."""

        pending_snapshot = pending.model_dump(mode="json")
        services = RuleServices(
            detectors=self.detectors,
            policy_hash=self.policy.content_hash,
            detector_timeout_ms=self.policy.engine.detector_timeout_ms,
        )
        violations: list[Violation] = []

        for event in pending.events:
            context = pending.context_for(event)
            for binding in self.policy.rules:
                if context.event.phase not in binding.rule.phases:
                    continue
                rule_violations = await self._evaluate_rule(binding, context, services)
                violations.extend(rule_violations)
                if len(violations) >= self.policy.engine.max_violations:
                    violations = violations[: self.policy.engine.max_violations]
                    break
            if len(violations) >= self.policy.engine.max_violations:
                break

        if pending.model_dump(mode="json") != pending_snapshot:
            raise RuntimeError("a policy rule mutated the pending trace")

        configured_actions = [
            action for violation in violations if (action := violation.action) is not None
        ]
        final_action = max(
            configured_actions,
            key=lambda action: ACTION_PRIORITY[action],
            default=Action.ALLOW,
        )
        primary = pending.primary_event
        return Decision(
            action=final_action,
            trace_id=pending.trace.id,
            event_id=primary.id,
            pending_event_ids=pending.event_ids,
            phase=primary.phase,
            policy_version=self.policy.version,
            policy_hash=self.policy.content_hash,
            violations=tuple(violations),
        )

    async def _evaluate_rule(
        self,
        binding: RuleBinding,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        try:
            timeout_seconds = self.policy.engine.default_timeout_ms / 1_000
            async with asyncio.timeout(timeout_seconds):
                matches = await binding.rule.evaluate(context, services)
        except DetectorTimeoutError:
            return [
                self._system_violation(
                    binding,
                    context,
                    code="detector_timeout",
                    message="A required detector did not complete before its deadline.",
                    action=self.policy.engine.on_detector_timeout,
                )
            ]
        except TimeoutError:
            return [
                self._system_violation(
                    binding,
                    context,
                    code="rule_timeout",
                    message="A policy rule did not complete before its deadline.",
                    action=self.policy.engine.on_rule_error,
                )
            ]
        except Exception as exc:  # A policy error must become an explicit decision.
            return [
                self._system_violation(
                    binding,
                    context,
                    code="rule_error",
                    message="A policy rule failed during evaluation.",
                    action=self.policy.engine.on_rule_error,
                    error_type=type(exc).__name__,
                )
            ]

        return [
            violation.model_copy(
                update={
                    "rule_id": binding.rule.id,
                    "phase": context.event.phase,
                    "action": binding.action,
                    "event_ids": tuple(dict.fromkeys((*violation.event_ids, context.event.id))),
                }
            )
            for violation in matches
        ]

    @staticmethod
    def _system_violation(
        binding: RuleBinding,
        context: GuardrailContext,
        *,
        code: str,
        message: str,
        action: Action,
        error_type: str | None = None,
    ) -> Violation:
        metadata: dict[str, JsonValue] = {"system": True}
        if error_type is not None:
            metadata["error_type"] = error_type
        return Violation(
            rule_id=binding.rule.id,
            code=code,
            phase=context.event.phase,
            message=message,
            action=action,
            event_ids=(context.event.id,),
            metadata=metadata,
        )
