"""Block configured tool-to-tool flows using explicit provenance edges."""

from __future__ import annotations

from hashlib import sha256
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from agent_guardrail.core.services import RuleServices
from agent_guardrail.models import (
    EventKind,
    GuardrailContext,
    Phase,
    ToolCall,
    ToolResult,
    Violation,
)


class ToolResultFlowConfig(BaseModel):
    """Strict source-tool and destination-tool sets for one denied flow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_tools: tuple[str, ...] = Field(min_length=1)
    destination_tools: tuple[str, ...] = Field(min_length=1)

    @field_validator("source_tools", "destination_tools")
    @classmethod
    def validate_tool_names(cls, tools: tuple[str, ...]) -> tuple[str, ...]:
        if len(tools) != len(set(tools)):
            raise ValueError("tool names must be unique")
        if any(not tool.strip() for tool in tools):
            raise ValueError("tool names cannot be blank")
        if any(tool != tool.strip() for tool in tools):
            raise ValueError("tool names cannot contain surrounding whitespace")
        return tools


class ToolResultFlowRule:
    """Reject a destination call descended from configured tool results."""

    def __init__(
        self,
        *,
        rule_id: str,
        phases: frozenset[Phase],
        config: ToolResultFlowConfig,
    ) -> None:
        self.id = rule_id
        self.phases = phases
        self.config = config
        self._source_tools = frozenset(config.source_tools)
        self._destination_tools = frozenset(config.destination_tools)

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        if (
            context.event.phase is not Phase.PRE_TOOL
            or context.event.kind is not EventKind.TOOL_CALL
        ):
            return []

        call = ToolCall.model_validate(context.event.payload)
        if call.name not in self._destination_tools:
            return []

        matched_sources: list[tuple[str, ToolCall]] = []
        for result_event in context.trace.ancestors_of(
            context.event,
            kind=EventKind.TOOL_RESULT,
        ):
            result = ToolResult.model_validate(result_event.payload)
            for source_event in context.trace.sources_of(result_event):
                if source_event.kind is not EventKind.TOOL_CALL:
                    continue
                source_call = ToolCall.model_validate(source_event.payload)
                if (
                    source_call.call_id == result.call_id
                    and source_call.name == result.name
                    and source_call.name in self._source_tools
                ):
                    matched_sources.append((result_event.id, source_call))
                    break
        if not matched_sources:
            return []

        return [
            Violation(
                rule_id=self.id,
                code="tool_result_flow_denied",
                phase=context.event.phase,
                message="The requested tool flow is not allowed by policy.",
                metadata=cast(
                    dict[str, JsonValue],
                    {
                        "matched_source_event_ids": [
                            source_event_id for source_event_id, _result in matched_sources
                        ],
                        "source_tool_name_fingerprints": sorted(
                            {
                                _tool_name_fingerprint(source_call.name)
                                for _source_event_id, source_call in matched_sources
                            }
                        ),
                        "destination_tool_name_fingerprint": _tool_name_fingerprint(call.name),
                    },
                ),
            )
        ]


def _tool_name_fingerprint(tool_name: str) -> str:
    return sha256(tool_name.encode("utf-8")).hexdigest()[:16]
