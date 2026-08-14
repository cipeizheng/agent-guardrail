"""Public guardrail core APIs."""

from agent_guardrail.core.authoring import (
    AuthorPolicy,
    AuthorPolicyCompilationError,
    compile_author_policy,
)
from agent_guardrail.core.capabilities import (
    CapabilityCompilationError,
    CompiledDetectorCapability,
    CompiledMatchPlan,
    CompiledPredicateCapability,
    CompiledSimilarityCapability,
    compile_match_plan_capabilities,
)
from agent_guardrail.core.decision_analyzer import MatchPolicyAnalyzer
from agent_guardrail.core.detector_executor import DetectorExecutionError
from agent_guardrail.core.match_plan import (
    CostDimension,
    MatchBudgetExceeded,
    MatchCostLedger,
    MatchCostSnapshot,
    MatchLimitOverrides,
    MatchLimits,
    MatchPlan,
    MatchRulePlan,
)
from agent_guardrail.core.matcher import SnapshotMatcher
from agent_guardrail.core.policy import (
    CompiledPolicy,
    EnforcementConfig,
    PolicyDocument,
    RuleAction,
)
from agent_guardrail.core.protocols import (
    Detector,
    Predicate,
    PredicateContext,
    SimilarityDetector,
)
from agent_guardrail.core.registry import (
    CapabilityEvidencePolicy,
    DetectorPolicyDescriptor,
    DetectorRegistry,
    PredicatePolicyDescriptor,
    PredicateRegistry,
    SimilarityPolicyDescriptor,
)

__all__ = [
    "Detector",
    "DetectorExecutionError",
    "Predicate",
    "PredicateContext",
    "SimilarityDetector",
    "DetectorPolicyDescriptor",
    "DetectorRegistry",
    "PredicatePolicyDescriptor",
    "PredicateRegistry",
    "SimilarityPolicyDescriptor",
    "CompiledPolicy",
    "EnforcementConfig",
    "MatchPolicyAnalyzer",
    "CostDimension",
    "MatchBudgetExceeded",
    "MatchCostLedger",
    "MatchCostSnapshot",
    "MatchLimitOverrides",
    "MatchLimits",
    "MatchPlan",
    "MatchRulePlan",
    "PolicyDocument",
    "RuleAction",
    "SnapshotMatcher",
    "AuthorPolicy",
    "AuthorPolicyCompilationError",
    "compile_author_policy",
    "CapabilityCompilationError",
    "CapabilityEvidencePolicy",
    "CompiledDetectorCapability",
    "CompiledMatchPlan",
    "CompiledPredicateCapability",
    "CompiledSimilarityCapability",
    "compile_match_plan_capabilities",
]
