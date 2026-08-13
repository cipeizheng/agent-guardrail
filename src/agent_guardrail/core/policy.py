"""The only production policy schema: strict YAML compiled to MatchPlan."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Self

from pydantic import ConfigDict, Field, StrictInt, model_validator

from agent_guardrail.core.authoring import (
    MAX_AUTHOR_PARAMETERS,
    MAX_AUTHOR_PREDICATES,
    MAX_AUTHOR_RULES,
    AuthorModel,
    AuthorParameterSpec,
    AuthorPolicy,
    AuthorPredicateDefinition,
    AuthorRule,
)
from agent_guardrail.core.capabilities import CompiledMatchPlan
from agent_guardrail.core.match_plan import MatchLimits, ParameterType
from agent_guardrail.models import (
    SECURITY_CONTEXT_PARAMETER_NAMES,
    Action,
    AnalysisScope,
)


class EnforcementConfig(AuthorModel):
    """Bounded Finding-to-Decision behavior owned by Enforcement."""

    max_violations: StrictInt = Field(default=100, ge=1, le=1_000)
    on_analysis_error: Action = Action.BLOCK
    on_detector_timeout: Action = Action.BLOCK


class PolicyRule(AuthorRule):
    """One readable MatchPlan rule plus its deployment action."""

    action: Action = Action.BLOCK


class PolicyDocument(AuthorModel):
    """Breaking v3 production document; legacy Rule and anchor forms are invalid."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    version: Literal[3]
    engine: EnforcementConfig = Field(default_factory=EnforcementConfig)
    scopes: tuple[AnalysisScope, ...] = (AnalysisScope.PENDING,)
    limits: MatchLimits = Field(default_factory=MatchLimits)
    parameters: dict[str, AuthorParameterSpec] = Field(
        default_factory=dict,
        max_length=MAX_AUTHOR_PARAMETERS,
    )
    predicates: dict[str, AuthorPredicateDefinition] = Field(
        default_factory=dict,
        max_length=MAX_AUTHOR_PREDICATES,
    )
    rules: tuple[PolicyRule, ...] = Field(max_length=MAX_AUTHOR_RULES)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if len(self.scopes) != len(set(self.scopes)):
            raise ValueError("policy scopes must be unique")
        if AnalysisScope.PENDING not in self.scopes:
            raise ValueError("production policy must support pending analysis")
        rule_ids = tuple(rule.id for rule in self.rules)
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("policy Rule IDs must be unique")
        if any(
            parameter.required and parameter.default is None
            for parameter in self.parameters.values()
        ):
            raise ValueError("production policy parameters must define defaults")
        for name, parameter in self.parameters.items():
            if name.startswith("security_") and name not in SECURITY_CONTEXT_PARAMETER_NAMES:
                raise ValueError(f"unsupported security context parameter: {name}")
            if name not in SECURITY_CONTEXT_PARAMETER_NAMES:
                continue
            if (
                parameter.type is not ParameterType.STRING
                or parameter.required
                or parameter.default != "unknown"
            ):
                raise ValueError(
                    "reserved security context parameters must be optional strings "
                    "with the default 'unknown'"
                )
        return self

    def analysis_policy(self) -> AuthorPolicy:
        """Project the action-free author policy consumed by the MatchPlan compiler."""

        return AuthorPolicy(
            version=1,
            scopes=self.scopes,
            limits=self.limits,
            parameters=self.parameters,
            predicates=self.predicates,
            rules=self.rules,
        )


@dataclass(frozen=True, slots=True)
class RuleAction:
    """Deployment-only action for one action-free MatchPlan rule."""

    rule_id: str
    action: Action


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Atomically validated production policy and trusted capabilities."""

    version: int
    content_hash: str
    engine: EnforcementConfig
    match_plan: CompiledMatchPlan
    actions: tuple[RuleAction, ...]
