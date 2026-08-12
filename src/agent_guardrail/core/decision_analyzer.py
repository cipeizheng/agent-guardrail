"""Fail-safe Enforcement projection over the anchor-free MatchPlan matcher."""

from __future__ import annotations

from pydantic import JsonValue

from agent_guardrail.core.matcher import SnapshotMatcher
from agent_guardrail.core.policy import CompiledPolicy
from agent_guardrail.models import (
    ACTION_PRIORITY,
    SECURITY_CONTEXT_PARAMETER_NAMES,
    Action,
    AnalysisError,
    AnalysisErrorCode,
    Decision,
    Detection,
    EvidenceSource,
    Finding,
    FindingEvidence,
    PendingTrace,
    Violation,
)


class MatchPolicyAnalyzer:
    """Map MatchPlan Findings and safe analysis failures to one atomic Decision."""

    __slots__ = ("_actions", "_detector_versions", "_matcher", "policy")

    def __init__(self, policy: CompiledPolicy) -> None:
        self.policy = policy
        self._actions = {binding.rule_id: binding.action for binding in policy.actions}
        self._detector_versions = {
            capability.descriptor.name: capability.implementation.version
            for capability in (*policy.match_plan.detectors, *policy.match_plan.similarities)
        }
        self._matcher = SnapshotMatcher(
            policy.match_plan,
            policy_version=policy.version,
            policy_hash=policy.content_hash,
        )

    @property
    def policy_version(self) -> int:
        return self.policy.version

    @property
    def policy_hash(self) -> str:
        return self.policy.content_hash

    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        """Analyze the whole pending snapshot before any Event is committed."""

        declared_parameters = {
            declaration.name for declaration in self.policy.match_plan.plan.parameters
        }
        security_parameters = {
            name: value
            for name, value in pending.security_context.policy_parameters().items()
            if name in declared_parameters and name in SECURITY_CONTEXT_PARAMETER_NAMES
        }
        report = await self._matcher.analyze_pending(
            pending,
            parameters=security_parameters or None,
        )
        violations = [
            self._finding_violation(finding, pending)
            for finding in report.findings
        ]
        violations.extend(self._error_violation(error, pending) for error in report.errors)
        retained = _retain_violations(violations, self.policy.engine.max_violations)
        final_action = max(
            (violation.action for violation in retained if violation.action is not None),
            key=lambda action: ACTION_PRIORITY[action],
            default=Action.ALLOW,
        )
        return Decision(
            action=final_action,
            trace_id=pending.trace.id,
            event_id=pending.primary_event_id,
            pending_event_ids=pending.event_ids,
            phase=pending.primary_event.phase,
            policy_version=self.policy.version,
            policy_hash=self.policy.content_hash,
            violations=retained,
        )

    def _finding_violation(self, finding: Finding, pending: PendingTrace) -> Violation:
        pending_subjects = tuple(
            event_id
            for event_id in pending.event_ids
            if event_id in finding.subject_event_ids
        )
        metadata: dict[str, JsonValue] = {
            "finding_id": finding.id,
            "subject_event_ids": list(finding.subject_event_ids),
        }
        bound_event_ids = tuple(
            dict.fromkeys(
                binding.event_id
                for binding in finding.bindings
                if binding.event_id is not None
            )
        )
        if bound_event_ids:
            metadata["bound_event_ids"] = list(bound_event_ids)
        return Violation(
            rule_id=finding.rule_id,
            code=finding.code,
            phase=pending.primary_event.phase,
            message=finding.message,
            action=self._actions[finding.rule_id],
            event_ids=pending_subjects,
            evidence=tuple(
                detection
                for item in finding.evidence
                if (detection := self._detector_evidence(item)) is not None
            ),
            metadata=metadata,
        )

    def _error_violation(self, error: AnalysisError, pending: PendingTrace) -> Violation:
        action = (
            self.policy.engine.on_detector_timeout
            if error.code is AnalysisErrorCode.DETECTOR_TIMEOUT
            else self.policy.engine.on_analysis_error
        )
        event_ids = tuple(
            event_id for event_id in pending.event_ids if event_id in error.event_ids
        ) or pending.event_ids
        metadata: dict[str, JsonValue] = {"system": True}
        if error.capability is not None:
            metadata["capability"] = error.capability
        if error.retryable:
            metadata["retryable"] = True
        return Violation(
            rule_id=error.rule_id or "policy_analysis",
            code=error.code.value,
            phase=pending.primary_event.phase,
            message=error.message,
            action=action,
            event_ids=event_ids,
            metadata=metadata,
        )

    def _detector_evidence(self, evidence: FindingEvidence) -> Detection | None:
        if evidence.source is not EvidenceSource.DETECTOR or evidence.capability is None:
            return None
        if (
            evidence.masked_evidence is None
            or evidence.fingerprint is None
            or evidence.confidence is None
        ):
            return None
        location = evidence.location
        return Detection(
            type=evidence.type,
            detector=evidence.capability,
            detector_version=self._detector_versions[evidence.capability],
            confidence=evidence.confidence,
            start=location.start if location is not None else None,
            end=location.end if location is not None else None,
            path=_location_path(location.path) if location is not None else None,
            masked_evidence=evidence.masked_evidence,
            fingerprint=evidence.fingerprint,
        )


def _retain_violations(
    violations: list[Violation],
    maximum: int,
) -> tuple[Violation, ...]:
    """Keep the highest-priority violations without changing their stable order."""

    ranked = sorted(
        enumerate(violations),
        key=lambda item: (
            -ACTION_PRIORITY[item[1].action or Action.ALLOW],
            item[0],
        ),
    )[:maximum]
    retained_indexes = {index for index, _violation in ranked}
    return tuple(
        violation
        for index, violation in enumerate(violations)
        if index in retained_indexes
    )


def _location_path(path: tuple[str | int, ...]) -> str:
    rendered = "$"
    for segment in path:
        rendered += f"[{segment}]" if isinstance(segment, int) else f".{segment}"
    return rendered
