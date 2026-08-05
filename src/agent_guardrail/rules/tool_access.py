"""Allow or deny named tools at model-response and execution boundaries."""

from __future__ import annotations

from hashlib import sha256
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from agent_guardrail.core.services import RuleServices
from agent_guardrail.models import (
    EventKind,
    GuardrailContext,
    ModelResponse,
    Phase,
    ToolCall,
    Violation,
)

ToolAccessMode = Literal["allowlist", "denylist"]


class ToolAccessConfig(BaseModel):
    """Strict configuration for a named tool allowlist or denylist."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ToolAccessMode
    tools: tuple[str, ...] = Field(min_length=1)

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, tools: tuple[str, ...]) -> tuple[str, ...]:
        if len(tools) != len(set(tools)):
            raise ValueError("tool names must be unique")
        if any(not tool.strip() for tool in tools):
            raise ValueError("tool names cannot be blank")
        if any(tool != tool.strip() for tool in tools):
            raise ValueError("tool names cannot contain surrounding whitespace")
        return tools


class ToolAccessRule:
    """Reject tool calls according to one explicit allowlist or denylist."""

    def __init__(
        self,
        *,
        rule_id: str,
        phases: frozenset[Phase],
        config: ToolAccessConfig,
    ) -> None:
        self.id = rule_id
        self.phases = phases
        self.config = config
        self._tools = frozenset(config.tools)

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        violations: list[Violation] = []
        for call in self._extract_calls(context):
            listed = call.name in self._tools
            denied = listed if self.config.mode == "denylist" else not listed
            if not denied:
                continue
            violations.append(
                Violation(
                    rule_id=self.id,
                    code="tool_access_denied",
                    phase=context.event.phase,
                    message="The requested tool is not allowed by policy.",
                    metadata=cast(
                        dict[str, JsonValue],
                        {
                            "mode": self.config.mode,
                            "tool_name_fingerprint": sha256(call.name.encode("utf-8")).hexdigest()[
                                :16
                            ],
                        },
                    ),
                )
            )
        return violations

    @staticmethod
    def _extract_calls(context: GuardrailContext) -> tuple[ToolCall, ...]:
        try:
            if context.event.phase is Phase.PRE_TOOL and context.event.kind is EventKind.TOOL_CALL:
                return (ToolCall.model_validate(context.event.payload),)
            if (
                context.event.phase is Phase.POST_LLM
                and context.event.kind is EventKind.MODEL_RESPONSE
            ):
                return ModelResponse.model_validate(context.event.payload).tool_calls
        except ValueError:
            return ()
        return ()
