"""Block configured outbound tools when selected arguments contain secrets."""

from __future__ import annotations

import json
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from agent_guardrail.core.services import RuleServices
from agent_guardrail.models import (
    Detection,
    EventKind,
    GuardrailContext,
    ModelResponse,
    Phase,
    ToolCall,
    Violation,
)


class SecretExfiltrationConfig(BaseModel):
    """Configuration accepted by the registered secret exfiltration rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: tuple[str, ...] = Field(min_length=1)
    text_arguments: tuple[str, ...] = Field(min_length=1)

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, tools: tuple[str, ...]) -> tuple[str, ...]:
        if len(tools) != len(set(tools)):
            raise ValueError("tool names must be unique")
        if any(not tool.strip() for tool in tools):
            raise ValueError("tool names cannot be blank")
        return tools

    @field_validator("text_arguments")
    @classmethod
    def validate_arguments(cls, arguments: tuple[str, ...]) -> tuple[str, ...]:
        if len(arguments) != len(set(arguments)):
            raise ValueError("text arguments must be unique")
        if any(not argument.strip() for argument in arguments):
            raise ValueError("text argument names cannot be blank")
        return arguments


class SecretExfiltrationRule:
    """Use the secret detector only for configured outbound tool arguments."""

    def __init__(
        self,
        *,
        rule_id: str,
        phases: frozenset[Phase],
        config: SecretExfiltrationConfig,
    ) -> None:
        self.id = rule_id
        self.phases = phases
        self.config = config

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        calls = self._extract_calls(context)
        violations: list[Violation] = []
        for call_index, call in enumerate(calls):
            if call.name not in self.config.tools:
                continue

            detections: list[Detection] = []
            matched_arguments: list[str] = []
            for argument_name in self.config.text_arguments:
                if argument_name not in call.arguments:
                    continue
                text = self._to_text(call.arguments[argument_name])
                argument_detections = await services.detect(
                    "secrets",
                    text,
                    context=context,
                    path=self._argument_path(context.event.phase, call_index, argument_name),
                )
                if argument_detections:
                    matched_arguments.append(argument_name)
                    detections.extend(argument_detections)

            if detections:
                violations.append(
                    Violation(
                        rule_id=self.id,
                        code="secret_exfiltration",
                        phase=context.event.phase,
                        message="A protected tool argument contains credential-like data.",
                        evidence=tuple(detections),
                        metadata={
                            "tool_name": call.name,
                            "argument_names": cast(JsonValue, matched_arguments),
                            "secret_types": cast(
                                JsonValue,
                                sorted({detection.type for detection in detections}),
                            ),
                            "fingerprints": cast(
                                JsonValue,
                                sorted({detection.fingerprint for detection in detections}),
                            ),
                        },
                    )
                )
        return violations

    @staticmethod
    def _extract_calls(context: GuardrailContext) -> tuple[ToolCall, ...]:
        try:
            if (
                context.event.phase is Phase.PRE_TOOL
                and context.event.kind is EventKind.TOOL_CALL
            ):
                return (ToolCall.model_validate(context.event.payload),)
            if (
                context.event.phase is Phase.POST_LLM
                and context.event.kind is EventKind.MODEL_RESPONSE
            ):
                return ModelResponse.model_validate(context.event.payload).tool_calls
        except ValueError:
            return ()
        return ()

    @staticmethod
    def _argument_path(phase: Phase, call_index: int, argument_name: str) -> str:
        if phase is Phase.POST_LLM:
            return f"$.tool_calls[{call_index}].arguments.{argument_name}"
        return f"$.arguments.{argument_name}"

    @staticmethod
    def _to_text(value: JsonValue) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
