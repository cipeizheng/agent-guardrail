"""Bounded incremental Finding deduplication over the MatchPlan matcher."""

from __future__ import annotations

from collections.abc import Mapping

from agent_guardrail.core.capabilities import CompiledMatchPlan
from agent_guardrail.core.match_plan import MatchPlan
from agent_guardrail.core.matcher import SnapshotMatcher
from agent_guardrail.models import (
    AnalysisError,
    AnalysisErrorCode,
    AnalysisReport,
    Finding,
    FindingEmission,
    PendingTrace,
    Trace,
)

DEFAULT_MONITOR_FINDING_IDENTITIES = 100_000
MAX_MONITOR_FINDING_IDENTITIES = 1_000_000


class MatchMonitor:
    """Emit new Findings while keeping tentative pending analysis retry-safe."""

    __slots__ = ("_matcher", "_max_finding_identities", "_seen")

    def __init__(
        self,
        plan: MatchPlan | CompiledMatchPlan,
        *,
        policy_version: int,
        policy_hash: str,
        max_finding_identities: int = DEFAULT_MONITOR_FINDING_IDENTITIES,
    ) -> None:
        if (
            isinstance(max_finding_identities, bool)
            or not isinstance(max_finding_identities, int)
        ):
            raise TypeError("max_finding_identities must be an integer")
        if not 1 <= max_finding_identities <= MAX_MONITOR_FINDING_IDENTITIES:
            raise ValueError("max_finding_identities is outside its hard bounds")
        self._matcher = SnapshotMatcher(
            plan,
            policy_version=policy_version,
            policy_hash=policy_hash,
        )
        self._max_finding_identities = max_finding_identities
        self._seen: set[tuple[str, str]] = set()

    @property
    def seen_count(self) -> int:
        """Return the number of committed trace-local Finding identities."""

        return len(self._seen)

    async def analyze(
        self,
        trace: Trace,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> AnalysisReport:
        """Analyze a committed snapshot and atomically remember successful Findings."""

        report = await self._matcher.analyze(trace, parameters=parameters)
        return self._emit_new(report, commit=True)

    async def analyze_pending(
        self,
        pending_trace: PendingTrace,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> AnalysisReport:
        """Analyze whole pending input without acknowledging tentative Findings."""

        report = await self._matcher.analyze_pending(
            pending_trace,
            parameters=parameters,
        )
        return self._emit_new(report, commit=False)

    def reset(self, trace_id: str | None = None) -> None:
        """Clear all dedupe state, or only state belonging to one Trace."""

        if trace_id is None:
            self._seen.clear()
            return
        if not isinstance(trace_id, str):
            raise TypeError("trace_id must be a string")
        if not trace_id.strip() or trace_id != trace_id.strip():
            raise ValueError("trace_id must be a non-blank trimmed string")
        self._seen = {key for key in self._seen if key[0] != trace_id}

    def _emit_new(self, report: AnalysisReport, *, commit: bool) -> AnalysisReport:
        new_findings = tuple(
            finding
            for finding in report.findings
            if _finding_key(report.trace_id, finding) not in self._seen
        )
        if report.errors or not commit:
            return _replace_report(report, findings=new_findings)

        new_keys = {
            _finding_key(report.trace_id, finding) for finding in new_findings
        }
        if len(self._seen) + len(new_keys) > self._max_finding_identities:
            return _replace_report(
                report,
                findings=(),
                errors=(
                    AnalysisError(
                        code=AnalysisErrorCode.RESOURCE_EXHAUSTED,
                        message="MatchMonitor identity state budget exhausted",
                    ),
                ),
            )
        self._seen.update(new_keys)
        return _replace_report(report, findings=new_findings)


def _finding_key(trace_id: str, finding: Finding) -> tuple[str, str]:
    return trace_id, finding.id


def _replace_report(
    report: AnalysisReport,
    *,
    findings: tuple[Finding, ...],
    errors: tuple[AnalysisError, ...] | None = None,
) -> AnalysisReport:
    values = report.model_dump(mode="python")
    values["emission"] = FindingEmission.NEW
    values["findings"] = findings
    if errors is not None:
        values["errors"] = errors
    return AnalysisReport.model_validate(values)
