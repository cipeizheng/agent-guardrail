"""AgentDojo pipeline elements that exercise the public agent-guardrail runtime."""

from __future__ import annotations

import asyncio
import json
from ast import literal_eval
from collections import Counter
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Any, cast

from agent_guardrail import GuardrailRun
from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.models import (
    ContentTrustClass,
    EventSecurityFacts,
    MessageRole,
    SecurityFactAuthority,
    ToolCall,
    ToolResult,
)
from agent_guardrail.sdk import EventRef
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import (
    ToolsExecutionLoop,
    ToolsExecutor,
    is_string_list,
    tool_result_to_str,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.models import MODEL_PROVIDERS, ModelsEnum
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)
from pydantic import BaseModel, JsonValue

_STATE_KEY = "agent_guardrail_agentdojo_state"
_BLOCK_MESSAGE = "The guardrail blocked an external tool result before model release."


def _run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Bridge AgentDojo's synchronous pipeline to the asynchronous SDK."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    raise RuntimeError("the synchronous AgentDojo adapter cannot run inside an event loop")


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    raise TypeError("AgentDojo produced a tool value outside the canonical JSON boundary")


@dataclass(slots=True)
class GuardrailStats:
    """Aggregate counters only; raw prompts and tool results are never retained."""

    model_calls: int = 0
    tool_call_proposals: int = 0
    tool_calls_executed: int = 0
    tool_results_scanned: int = 0
    tool_results_allowed: int = 0
    blocked_before_model_call: int = 0
    blocked_before_tool_call: int = 0
    blocked_before_tool_result_release: int = 0
    adapter_failures: int = 0
    violation_codes: Counter[str] = field(default_factory=Counter)

    def record_block(self, codes: Sequence[str], *, checkpoint: str) -> None:
        if checkpoint == "model_call":
            self.blocked_before_model_call += 1
        elif checkpoint == "tool_call":
            self.blocked_before_tool_call += 1
        elif checkpoint == "tool_result_release":
            self.blocked_before_tool_result_release += 1
        else:
            raise ValueError("unknown guardrail checkpoint")
        self.violation_codes.update(codes or ("guardrail_blocked_without_violation",))

    def as_dict(self) -> dict[str, JsonValue]:
        scanned = self.tool_results_scanned
        return {
            "model_calls": self.model_calls,
            "tool_call_proposals": self.tool_call_proposals,
            "tool_calls_executed": self.tool_calls_executed,
            "tool_results_scanned": scanned,
            "tool_results_allowed": self.tool_results_allowed,
            "blocked_before_model_call": self.blocked_before_model_call,
            "blocked_before_tool_call": self.blocked_before_tool_call,
            "blocked_before_tool_result_release": self.blocked_before_tool_result_release,
            "tool_result_block_rate": (
                self.blocked_before_tool_result_release / scanned if scanned else None
            ),
            "adapter_failures": self.adapter_failures,
            "violation_codes": dict(sorted(self.violation_codes.items())),
        }


@dataclass(slots=True)
class _TaskState:
    run: GuardrailRun
    inputs: tuple[EventRef, ...]
    proposals: dict[int, EventRef] = field(default_factory=dict)
    call_ids: dict[int, str] = field(default_factory=dict)


def _state(extra_args: dict) -> _TaskState:
    state = extra_args.get(_STATE_KEY)
    if not isinstance(state, _TaskState):
        raise RuntimeError("AgentDojo guardrail state is missing")
    return state


def _abort(
    message: str,
    messages: Sequence[ChatMessage],
    env: Env,
) -> AbortAgentError:
    return AbortAgentError(message, list(messages), env)


class InitGuardrailRun(BasePipelineElement):
    def __init__(self, analyzer: MatchPolicyAnalyzer, stats: GuardrailStats) -> None:
        self._analyzer = analyzer
        self._stats = stats

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        selected_env = env or cast(Env, EmptyEnv())
        selected_args = dict(extra_args or {})
        run = GuardrailRun(analyzer=self._analyzer)
        try:
            result = _run(
                run.message(
                    role=MessageRole.USER,
                    text=query,
                    security_facts=EventSecurityFacts(
                        trust_class=ContentTrustClass.USER_CONTENT,
                        trust_authority=SecurityFactAuthority.ENFORCEMENT,
                    ),
                )
            )
        except Exception as exc:
            self._stats.adapter_failures += 1
            raise _abort(
                "The guardrail failed closed before the model call.", messages, selected_env
            ) from exc
        if result.decision.blocked or result.primary is None:
            self._stats.record_block(
                [violation.code for violation in result.decision.violations],
                checkpoint="model_call",
            )
            raise _abort(_BLOCK_MESSAGE, messages, selected_env)
        selected_args[_STATE_KEY] = _TaskState(run=run, inputs=(result.primary,))
        return query, runtime, selected_env, messages, selected_args


class GuardedLLM(BasePipelineElement):
    def __init__(self, inner: BasePipelineElement, stats: GuardrailStats) -> None:
        self._inner = inner
        self._stats = stats
        self.name = inner.name

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        selected_env = env or cast(Env, EmptyEnv())
        selected_args = extra_args or {}
        state = _state(selected_args)
        try:
            model_result = _run(state.run.model_call(model=self.name, inputs=state.inputs))
        except Exception as exc:
            self._stats.adapter_failures += 1
            raise _abort(
                "The guardrail failed closed before the model call.", messages, selected_env
            ) from exc
        if model_result.decision.blocked or model_result.primary is None:
            self._stats.record_block(
                [violation.code for violation in model_result.decision.violations],
                checkpoint="model_call",
            )
            raise _abort(_BLOCK_MESSAGE, messages, selected_env)

        self._stats.model_calls += 1
        query, runtime, selected_env, updated_messages, selected_args = self._inner.query(
            query, runtime, selected_env, messages, selected_args
        )
        if not updated_messages or updated_messages[-1]["role"] != "assistant":
            return query, runtime, selected_env, updated_messages, selected_args

        for tool_call in updated_messages[-1]["tool_calls"] or ():
            call_id = tool_call.id or f"agentdojo-call-{self._stats.tool_call_proposals + 1}"
            state.call_ids[id(tool_call)] = call_id
            canonical_call = ToolCall(
                call_id=call_id,
                name=tool_call.function,
                arguments=cast(dict[str, JsonValue], _json_value(tool_call.args)),
            )
            try:
                proposal = _run(
                    state.run.tool_call_proposal(
                        canonical_call,
                        model_call=model_result.primary,
                    )
                )
            except Exception as exc:
                self._stats.adapter_failures += 1
                raise _abort(
                    "The guardrail failed closed while recording a tool proposal.",
                    updated_messages,
                    selected_env,
                ) from exc
            if proposal.decision.blocked or proposal.primary is None:
                self._stats.record_block(
                    [violation.code for violation in proposal.decision.violations],
                    checkpoint="tool_call",
                )
                raise _abort(_BLOCK_MESSAGE, updated_messages, selected_env)
            state.proposals[id(tool_call)] = proposal.primary
            self._stats.tool_call_proposals += 1
        return query, runtime, selected_env, updated_messages, selected_args


class GuardedToolsExecutor(BasePipelineElement):
    def __init__(self, stats: GuardrailStats) -> None:
        self._stats = stats
        self.output_formatter = partial(tool_result_to_str, dump_fn=json.dumps)

    @staticmethod
    def _error_message(tool_call: FunctionCall, message: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string("")],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=message,
        )

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        selected_env = env or cast(Env, EmptyEnv())
        selected_args = extra_args or {}
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, selected_env, messages, selected_args
        tool_calls = messages[-1]["tool_calls"] or ()
        if not tool_calls:
            return query, runtime, selected_env, messages, selected_args

        state = _state(selected_args)
        tool_call_results: list[ChatToolResultMessage] = []
        result_refs: list[EventRef] = []
        for tool_call in tool_calls:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    self._error_message(tool_call, "Empty function name provided.")
                )
                continue
            if tool_call.function not in runtime.functions:
                tool_call_results.append(
                    self._error_message(tool_call, f"Invalid tool {tool_call.function} provided.")
                )
                continue

            for key, value in tool_call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    tool_call.args[key] = literal_eval(value)

            call_id = state.call_ids.get(id(tool_call)) or tool_call.id
            proposal = state.proposals.get(id(tool_call))
            if call_id is None or proposal is None:
                self._stats.adapter_failures += 1
                raise _abort(
                    "The guardrail failed closed before a tool call.", messages, selected_env
                )
            canonical_call = ToolCall(
                call_id=call_id,
                name=tool_call.function,
                arguments=cast(dict[str, JsonValue], _json_value(tool_call.args)),
            )
            try:
                call = _run(state.run.tool_call(canonical_call, proposal=proposal))
            except Exception as exc:
                self._stats.adapter_failures += 1
                raise _abort(
                    "The guardrail failed closed before a tool call.", messages, selected_env
                ) from exc
            if call.decision.blocked or call.primary is None:
                self._stats.record_block(
                    [violation.code for violation in call.decision.violations],
                    checkpoint="tool_call",
                )
                raise _abort(_BLOCK_MESSAGE, messages, selected_env)

            raw_result, error = runtime.run_function(
                selected_env, tool_call.function, tool_call.args
            )
            self._stats.tool_calls_executed += 1
            formatted_result = self.output_formatter(raw_result)
            self._stats.tool_results_scanned += 1
            try:
                result = _run(
                    state.run.tool_result(
                        ToolResult(
                            call_id=call_id,
                            name=tool_call.function,
                            output=formatted_result,
                        ),
                        call=call.primary,
                        security_facts=EventSecurityFacts(
                            trust_class=ContentTrustClass.EXTERNAL_UNTRUSTED,
                            trust_authority=SecurityFactAuthority.ENFORCEMENT,
                        ),
                    )
                )
            except Exception as exc:
                self._stats.adapter_failures += 1
                raise _abort(
                    "The guardrail failed closed before releasing a tool result.",
                    messages,
                    selected_env,
                ) from exc
            if result.decision.blocked or result.primary is None:
                self._stats.record_block(
                    [violation.code for violation in result.decision.violations],
                    checkpoint="tool_result_release",
                )
                raise _abort(_BLOCK_MESSAGE, messages, selected_env)

            self._stats.tool_results_allowed += 1
            result_refs.append(result.primary)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted_result)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )

        state.inputs = tuple(result_refs)
        return query, runtime, selected_env, [*messages, *tool_call_results], selected_args


def build_baseline_pipeline(model: str, *, model_id: str | None = None) -> AgentPipeline:
    selected = ModelsEnum(model)
    inner = get_llm(MODEL_PROVIDERS[selected], selected, model_id, "tool")
    tools_loop = ToolsExecutionLoop(
        [
            ToolsExecutor(partial(tool_result_to_str, dump_fn=json.dumps)),
            inner,
        ]
    )
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), inner, tools_loop]
    )
    pipeline.name = str(selected)
    return pipeline


def build_guarded_pipeline(
    model: str,
    analyzer: MatchPolicyAnalyzer,
    stats: GuardrailStats,
    *,
    model_id: str | None = None,
) -> AgentPipeline:
    selected = ModelsEnum(model)
    inner = get_llm(MODEL_PROVIDERS[selected], selected, model_id, "tool")
    return build_guarded_pipeline_from_element(
        inner,
        analyzer,
        stats,
        pipeline_name=f"{selected}-agent-guardrail",
    )


def build_guarded_pipeline_from_element(
    inner: BasePipelineElement,
    analyzer: MatchPolicyAnalyzer,
    stats: GuardrailStats,
    *,
    pipeline_name: str,
) -> AgentPipeline:
    """Build the guarded composition around a deployment-selected AgentDojo LLM element."""

    guarded_llm = GuardedLLM(inner, stats)
    tools_loop = ToolsExecutionLoop([GuardedToolsExecutor(stats), guarded_llm])
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            InitGuardrailRun(analyzer, stats),
            guarded_llm,
            tools_loop,
        ]
    )
    pipeline.name = pipeline_name
    return pipeline
