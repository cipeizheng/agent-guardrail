"""A small, explainable guardrail runtime for AI agents."""

from agent_guardrail.adapters.protocols import (
    ModelProviderAdapter,
    ProviderAdapterError,
    ProviderStreamDecoder,
)
from agent_guardrail.adapters.streaming import (
    ProviderStreamUpdate,
    ServerSentEvent,
    StreamRelease,
)
from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
    create_detector_registry,
    create_model_detector_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.core.detector_executor import DetectorExecutionError
from agent_guardrail.core.match_plan import DetectorInputEncoding
from agent_guardrail.detector_sdk import (
    DetectorCapability,
    DetectorResult,
    DetectorRunner,
)
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
    ContentTrustClass,
    DataSensitivity,
    Decision,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    FlowAuthorization,
    FlowSecurityContext,
    OwnerScope,
    PendingTrace,
    RelationKind,
    SecurityDestination,
    SecurityFactAuthorities,
    SecurityFactAuthority,
    Trace,
)
from agent_guardrail.runtime import GuardrailRuntime, PolicyAnalyzer
from agent_guardrail.sdk import EventRef, GuardrailRun, SubmissionResult

__version__ = "0.1.0"

__all__ = [
    "Action",
    "CandidateEvent",
    "CandidateRelation",
    "ContentTrustClass",
    "DataSensitivity",
    "Decision",
    "DetectorCapability",
    "DetectorExecutionError",
    "DetectorInputEncoding",
    "DetectorResult",
    "DetectorRunner",
    "EnforcementSession",
    "Event",
    "EventKind",
    "EventOrigin",
    "EventRelation",
    "FlowAuthorization",
    "FlowSecurityContext",
    "ModelProviderAdapter",
    "MatchPolicyAnalyzer",
    "GuardedLLMClient",
    "GuardedToolExecutor",
    "GuardrailBlocked",
    "GuardrailRuntime",
    "GuardrailRun",
    "GuardrailUnavailable",
    "OwnerScope",
    "PendingTrace",
    "PolicyAnalyzer",
    "ProviderAdapterError",
    "ProviderStreamDecoder",
    "ProviderStreamUpdate",
    "EventRef",
    "SubmissionResult",
    "RelationKind",
    "SecurityDestination",
    "SecurityFactAuthorities",
    "SecurityFactAuthority",
    "ServerSentEvent",
    "StreamRelease",
    "Trace",
    "create_default_detector_registry",
    "create_default_predicate_registry",
    "create_detector_registry",
    "create_model_detector_registry",
    "load_policy_file",
    "load_policy_yaml",
]
