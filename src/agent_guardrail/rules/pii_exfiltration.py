"""Block configured outbound tools when selected arguments contain PII."""

from __future__ import annotations

import json
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from agent_guardrail.core.services import RuleServices
from agent_guardrail.detectors.pii import PIIEntityType
from agent_guardrail.models import (
    Detection,
    EventKind,
    GuardrailContext,
    ModelResponse,
    Phase,
    ToolCall,
    Violation,
)


class PIIExfiltrationConfig(BaseModel):
    """Strict configuration for selected outbound PII checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: tuple[str, ...] = Field(min_length=1)
    text_arguments: tuple[str, ...] = Field(min_length=1)
    entities: tuple[PIIEntityType, ...] = Field(min_length=1)

    @field_validator("tools", "text_arguments", "entities")
    @classmethod
    def validate_unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("configured values must be unique")
        if any(not value.strip() for value in values):
            raise ValueError("configured values cannot be blank")
        if any(value != value.strip() for value in values):
            raise ValueError("configured values cannot contain surrounding whitespace")
        return values


class PIIExfiltrationRule:
    """Use the PII detector only for configured outbound tool arguments."""

    def __init__(
        self,
        *,
        rule_id: str,
        phases: frozenset[Phase],
        config: PIIExfiltrationConfig,
    ) -> None:
        self.id = rule_id
        self.phases = phases
        self.config = config
        self._entities = frozenset(config.entities)

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        violations: list[Violation] = []
        for call_index, call in enumerate(self._extract_calls(context)):
            if call.name not in self.config.tools:
                continue

            detections: list[Detection] = []
            matched_arguments: list[str] = []
            for argument_name in self.config.text_arguments:
                if argument_name not in call.arguments:
                    continue
                detected = await services.detect(
                    "pii",
                    self._to_text(call.arguments[argument_name]),
                    context=context,
                    path=self._argument_path(context.event.phase, call_index, argument_name),
                )
                selected = [detection for detection in detected if detection.type in self._entities]
                if selected:
                    matched_arguments.append(argument_name)
                    detections.extend(selected)

            if detections:
                violations.append(
                    Violation(
                        rule_id=self.id,
                        code="pii_exfiltration",
                        phase=context.event.phase,
                        message="A protected tool argument contains selected personal data.",
                        evidence=tuple(detections),
                        metadata={
                            "tool_name": call.name,
                            "argument_names": cast(JsonValue, matched_arguments),
                            "pii_types": cast(
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
