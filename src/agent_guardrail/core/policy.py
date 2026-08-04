"""Strict policy configuration and immutable runtime policy objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    model_validator,
)

from agent_guardrail.core.protocols import Rule
from agent_guardrail.models import Action, Phase


class PolicyConfigModel(BaseModel):
    """Base for closed policy schemas."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EngineConfig(PolicyConfigModel):
    """Bounded execution and failure behavior for the engine."""

    default_timeout_ms: StrictInt = Field(default=1_000, ge=1, le=60_000)
    detector_timeout_ms: StrictInt = Field(default=500, ge=1, le=60_000)
    on_rule_error: Action = Action.BLOCK
    on_detector_timeout: Action = Action.BLOCK
    max_violations: StrictInt = Field(default=100, ge=1, le=1_000)


class RuleEntry(PolicyConfigModel):
    """A YAML rule reference; it cannot name a Python module or class."""

    id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    type: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_]*$")
    enabled: StrictBool = True
    action: Action = Action.BLOCK
    phases: tuple[Phase, ...] = Field(min_length=1)
    config: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_phases(self) -> Self:
        if len(self.phases) != len(set(self.phases)):
            raise ValueError("rule phases must be unique")
        return self


class PolicyDocument(PolicyConfigModel):
    """The versioned top-level YAML schema."""

    version: Literal[1]
    engine: EngineConfig = Field(default_factory=EngineConfig)
    rules: tuple[RuleEntry, ...]

    @model_validator(mode="after")
    def validate_rule_ids(self) -> Self:
        rule_ids = [rule.id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule IDs must be unique")
        return self


@dataclass(frozen=True, slots=True)
class RuleBinding:
    """A trusted rule instance plus its deployment action."""

    rule: Rule
    action: Action


@dataclass(frozen=True, slots=True)
class PolicySet:
    """An immutable policy activated only after complete validation."""

    version: int
    content_hash: str
    engine: EngineConfig
    rules: tuple[RuleBinding, ...]
