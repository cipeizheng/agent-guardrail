"""AgentDojo pipeline elements that exercise the public agent-guardrail runtime."""

from __future__ import annotations

import asyncio
import json
import os
from ast import literal_eval
from collections import Counter
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Any, cast

import openai
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
from agentdojo.models import MODEL_NAMES, MODEL_PROVIDERS, ModelsEnum
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)
from pydantic import BaseModel, JsonValue

_STATE_KEY = "agent_guardrail_agentdojo_state"
_BLOCK_MESSAGE = "The guardrail blocked an external tool result before model release."

AGENTDOJO_PROVIDER = "agentdojo"
DEEPSEEK_RESPONSES_PROVIDER = "deepseek-responses"
DEFAULT_AGENTDOJO_MODEL = "gpt-4o-mini-2024-07-18"
DEFAULT_DEEPSEEK_RESPONSES_MODEL = "deepseek-v4-flash"
DEEPSEEK_RESPONSES_MODELS = frozenset({DEFAULT_DEEPSEEK_RESPONSES_MODEL, "deepseek-v4-pro"})
DEEPSEEK_RESPONSES_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_RESPONSES_TIMEOUT_SECONDS = 120.0


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


def _json_dump(value: object) -> str:
    """Serialize an AgentDojo tool result as JSON.

    The workspace suite returns BaseModels whose fields include ``datetime``/``date``;
    ``model_dump()`` keeps those as native objects, so plain ``json.dumps`` raises.
    ``default=str`` only affects scalars JSON cannot already encode.
    """
    return json.dumps(value, default=str)


def _message_text(message: ChatMessage) -> str:
    content = message.get("content")
    if not content:
        return ""
    return "\n".join(
        block["content"]
        for block in content
        if block.get("type") == "text" and block.get("content") is not None
    )


def _responses_input(messages: Sequence[ChatMessage]) -> list[dict[str, Any]]:
    """Convert complete AgentDojo history to DeepSeek's stateless Responses input."""

    items: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        if role == "tool":
            call_id = message["tool_call_id"] or message["tool_call"].id
            if not call_id:
                raise ValueError("DeepSeek Responses requires a tool call ID")
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": message["error"] or _message_text(message),
                }
            )
            continue

        text = _message_text(message)
        if role != "assistant" or text:
            items.append({"type": "message", "role": role, "content": text})
        if role != "assistant":
            continue

        for tool_call in message["tool_calls"] or ():
            if not tool_call.id:
                raise ValueError("DeepSeek Responses requires a tool call ID")
            items.append(
                {
                    "type": "function_call",
                    "call_id": tool_call.id,
                    "name": tool_call.function,
                    "arguments": json.dumps(
                        tool_call.args,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )
    return items


def _responses_tools(runtime: FunctionsRuntime) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": function.name,
            "description": function.description,
            "parameters": function.parameters.model_json_schema(),
        }
        for function in runtime.functions.values()
    ]


def _field(value: object, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _deepseek_response_message(response: object) -> ChatMessage:
    if _field(response, "status") != "completed":
        raise ValueError("DeepSeek Responses did not complete successfully")
    content: list = []
    tool_calls: list[FunctionCall] = []
    output = _field(response, "output")
    if not isinstance(output, Sequence) or isinstance(output, (str, bytes, bytearray)):
        raise ValueError("DeepSeek Responses returned an invalid output list")

    for item in output:
        item_type = _field(item, "type")
        if item_type == "message":
            parts = _field(item, "content")
            if not isinstance(parts, Sequence) or isinstance(parts, (str, bytes, bytearray)):
                raise ValueError("DeepSeek Responses returned invalid message content")
            for part in parts:
                if _field(part, "type") == "output_text":
                    text = _field(part, "text")
                    if not isinstance(text, str):
                        raise ValueError("DeepSeek Responses returned invalid output text")
                    content.append(text_content_block_from_string(text))
        elif item_type == "function_call":
            name = _field(item, "name")
            call_id = _field(item, "call_id")
            arguments = _field(item, "arguments")
            if not all(isinstance(value, str) and value for value in (name, call_id, arguments)):
                raise ValueError("DeepSeek Responses returned an invalid function call")
            try:
                parsed_arguments = json.loads(arguments)
            except json.JSONDecodeError as exc:
                raise ValueError("DeepSeek Responses returned non-JSON function arguments") from exc
            if not isinstance(parsed_arguments, dict):
                raise ValueError("DeepSeek Responses function arguments must be an object")
            tool_calls.append(FunctionCall(function=name, args=parsed_arguments, id=call_id))

    if not content and not tool_calls:
        raise ValueError("DeepSeek Responses returned no text or function call")
    return {
        "role": "assistant",
        "content": content or None,
        "tool_calls": tool_calls or None,
    }


class DeepSeekResponsesLLM(BasePipelineElement):
    """AgentDojo LLM element backed by DeepSeek's stateless Responses API."""

    def __init__(self, client: openai.OpenAI, model: str) -> None:
        self.client = client
        self.model = model
        self.name = model

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        selected_env = env or cast(Env, EmptyEnv())
        tools = _responses_tools(runtime)
        request: dict[str, Any] = {
            "model": self.model,
            "input": _responses_input(messages),
            "reasoning": {"effort": "none"},
            "temperature": 0.0,
        }
        if tools:
            request["tools"] = tools
            request["tool_choice"] = "auto"
        response = cast(Any, self.client.responses).create(**request)
        output = cast(ChatMessage, _deepseek_response_message(response))
        return (
            query,
            runtime,
            selected_env,
            [*messages, output],
            dict(extra_args or {}),
        )


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
        self.output_formatter = partial(tool_result_to_str, dump_fn=_json_dump)

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


def _build_llm(
    provider: str,
    model: str,
    *,
    model_id: str | None,
) -> BasePipelineElement:
    if provider == DEEPSEEK_RESPONSES_PROVIDER:
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise ValueError("DEEPSEEK_API_KEY is required for deepseek-responses")
        MODEL_NAMES.setdefault(model, "DeepSeek")
        return DeepSeekResponsesLLM(
            openai.OpenAI(
                api_key=api_key,
                base_url=DEEPSEEK_RESPONSES_BASE_URL,
                timeout=DEEPSEEK_RESPONSES_TIMEOUT_SECONDS,
                max_retries=2,
            ),
            model,
        )
    if provider != AGENTDOJO_PROVIDER:
        raise ValueError(f"unsupported AgentDojo evaluation provider: {provider}")
    selected = ModelsEnum(model)
    return get_llm(MODEL_PROVIDERS[selected], selected, model_id, "tool")


def build_baseline_pipeline(
    model: str,
    *,
    model_id: str | None = None,
    provider: str = AGENTDOJO_PROVIDER,
) -> AgentPipeline:
    inner = _build_llm(provider, model, model_id=model_id)
    tools_loop = ToolsExecutionLoop(
        [
            ToolsExecutor(partial(tool_result_to_str, dump_fn=_json_dump)),
            inner,
        ]
    )
    pipeline = AgentPipeline(
        [SystemMessage(load_system_message(None)), InitQuery(), inner, tools_loop]
    )
    pipeline.name = model
    return pipeline


def build_guarded_pipeline(
    model: str,
    analyzer: MatchPolicyAnalyzer,
    stats: GuardrailStats,
    *,
    model_id: str | None = None,
    provider: str = AGENTDOJO_PROVIDER,
) -> AgentPipeline:
    inner = _build_llm(provider, model, model_id=model_id)
    return build_guarded_pipeline_from_element(
        inner,
        analyzer,
        stats,
        pipeline_name=f"{model}-agent-guardrail",
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
