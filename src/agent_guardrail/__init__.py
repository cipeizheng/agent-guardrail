"""A small, explainable guardrail runtime for AI agents."""

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.enforcement import (
    EnforcementSession,
    GuardedLLMClient,
    GuardedToolExecutor,
    GuardrailBlocked,
    GuardrailUnavailable,
)
from agent_guardrail.models import (
    Action,
    CandidateEvent,
    CandidateRelation,
    Decision,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    PendingTrace,
    Phase,
    RelationKind,
    Trace,
)
from agent_guardrail.runtime import GuardrailRuntime, PolicyAnalyzer

__version__ = "0.1.0"

__all__ = [
    "Action",
    "CandidateEvent",
    "CandidateRelation",
    "Decision",
    "EnforcementSession",
    "Event",
    "EventKind",
    "EventOrigin",
    "EventRelation",
    "MatchPolicyAnalyzer",
    "GuardedLLMClient",
    "GuardedToolExecutor",
    "GuardrailBlocked",
    "GuardrailRuntime",
    "GuardrailUnavailable",
    "Phase",
    "PendingTrace",
    "PolicyAnalyzer",
    "RelationKind",
    "Trace",
    "create_default_detector_registry",
    "create_default_predicate_registry",
    "load_policy_file",
    "load_policy_yaml",
]
