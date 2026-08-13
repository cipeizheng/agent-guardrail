# Agent 与 Enforcement 接入指南

> 适合谁：把 Runtime 接入应用、Agent、OpenAI Client 或 MCP Client 的开发者。
> 解决什么：Runtime/Session 生命周期、框架无关 SDK、接入选择和 Gateway 执行检查点。
> 不包含什么：HTTP 错误码和 MatchPlan 求值细节。

## 1. 组件职责

```text
GuardrailRuntime
  └─ MatchPolicyAnalyzer
       └─ SnapshotMatcher

EnforcementSession
  → PendingTrace
  → runtime.analyze_pending
  → Decision
  → atomic commit / sanitized block event
```

Runtime 管理一个已完整编译 Analyzer 的生命周期，不解析 Provider 协议、不执行 LLM/Tool，也不持有请求级
Trace。Session 管理 Trace、安全上下文、pending 原子提交和 Audit。

## 2. 无 YAML 的直接 Detector SDK

只需要在应用某个位置取得检测事实时，不必创建 Runtime 或 YAML：

```python
from agent_guardrail import DetectorExecutionError, DetectorRunner

detectors = DetectorRunner.from_profile("local")

try:
    result = await detectors.detect("prompt_injection", retrieved_text)
except DetectorExecutionError:
    return fail_closed_response()

if result.detected:
    return reject_untrusted_content()
```

`detect_text` 处理 UTF-8 text，`detect_json` 先产生确定性 canonical JSON，`detect_many` 对同一值按调用方顺序
运行多个 Detector。`capabilities` 枚举名称、版本、encoding、公开 detection type、输入/timeout/结果上限。
批量调用会在执行任何 Detector 前预校验全部 capability 与输入，但某个 backend 在执行期失败时整个调用仍以
`DetectorExecutionError` 失败，不返回容易被误解为安全的部分结果。

直接 SDK 与 MatchPlan 共享 Registry descriptor 和唯一 Detector 执行器，返回的 Detection 只有 type、
confidence、可选 span、mask 与 fingerprint，不包含原始命中内容。它不返回 `Decision`，不能自动阻止 LLM、
Tool、文件或网络副作用；应用必须根据 fact 明确采取动作。需要跨 Event/Relation 组合和统一失败动作时使用
`GuardrailRun` + YAML，需要可信中介执行时使用 Gateway/Inline。

backend 返回的自由形式 `Detection.path` 不进入直接结果；canonical JSON 的 span 只定位编码后的确定性文本，
不能当作原对象字段坐标。

默认会生成一次调用级 `DetectionContext`。需要把 fingerprint 稳定绑定到应用内已有对象时，可显式传入有界
`DetectionContext(trace_id=..., event_id=...)`。Detector profile 仍由部署选择，内容或 YAML 不能选择模型、
文件、进程、endpoint 或凭据。

## 3. Runtime

```python
runtime = GuardrailRuntime.from_policy_file(
    "policy.yaml",
    predicate_registry=predicates,
    detector_registry=detectors,
)

async with runtime:
    decision = await runtime.analyze_pending(pending)
```

未注入 Registry 时使用默认 capability。Loader 依次完成 v3 Schema、MatchPlan 编译和 capability linking；
任一步失败都不会创建 Runtime。生命周期是 `created → ready → closed`，closed 不能重启。

`analyze_pending(PendingTrace)` 是唯一 Analyzer 主路径；Runtime 不接受 Provider request/response，也不
决定调用应插在 Agent 的哪个生命周期位置。

## 4. Session 原子性

一次 `submit_candidates`：

1. 校验 batch 非空、有界、同 Trace 且 key 唯一；
2. 验证 Relation 只引用同 Trace 更早 Event 或更早 Candidate；
3. 分配连续 identity/sequence/time，构造 immutable PendingTrace；
4. 在 Session lock 内调用 Analyzer；
5. 验证 Analyzer 未修改输入，Decision 精确绑定 trace/pending；
6. allow/log 原子提交全部 Event；block 丢弃原始 Event，只提交脱敏 Decision Event；
7. 在锁外写脱敏 Audit。

Trace 容量、Analyzer 异常、输入修改或 Decision identity 错误都变成 `GuardrailUnavailable`，候选原文不
提交。锁不覆盖真实 LLM/Tool 副作用。

可信 `FlowSecurityContext` 只能经 Session 专用字段提交；普通 attributes 没有授权语义。Wrapper/Gateway
只覆盖它实际掌握的 destination，并在 sink 改变时清空旧 authorization。

## 5. 框架无关 Event/Policy SDK

`GuardrailRun` 不包装 Agent，也不要求 OpenAI Agents、LangGraph 或其他 Framework Adapter。应用在任何
有安全意义的位置提交 Event，读取 Decision，并把同一 run 返回的 `EventRef` 用于显式 Relation：

```python
from agent_guardrail import GuardrailRun
from agent_guardrail.models import MessageRole, ToolCall

run = GuardrailRun(analyzer=runtime, run_id="agent-task-1")
call = ToolCall(call_id="call-1", name="read_file", arguments={"path": "report"})

user = (await run.message(role=MessageRole.USER, text=user_text)).primary
assert user is not None
model = (await run.model_call(model="provider/model", inputs=(user,))).primary
assert model is not None
proposal = (await run.tool_call_proposal(call, model_call=model)).primary
assert proposal is not None
checked = await run.tool_call(call, proposal=proposal)
if checked.decision.blocked:
    return  # 必须在这里停止；不要执行真实 Tool

assert checked.primary is not None
result = await executor.execute(call)
committed_result = await run.tool_result(result, call=checked.primary)
```

如果该 ToolResult 被可信宿主确认为外部来源，首次提交时应改为把 `EventSecurityFacts` 绑定到这个确切
Candidate/Event。它不会从 `FlowSecurityContext`、EventOrigin 或时间顺序自动复制：

```python
from agent_guardrail.models import (
    ContentTrustClass,
    EventSecurityFacts,
    SecurityFactAuthority,
)

external_source = EventSecurityFacts(
    trust_class=ContentTrustClass.EXTERNAL_UNTRUSTED,
    trust_authority=SecurityFactAuthority.DATA_SOURCE,
)
result_ref = (
    await run.tool_result(result, call=checked.primary, security_facts=external_source)
).primary
```

随后把 `result_ref` 作为 `model_call(inputs=...)` 或 `tool_call(influenced_by=...)` 的来源；存储结构由目标
Event 向后引用 source，但关系语义始终是 source 影响 target。普通 HTTP/Provider payload 不能直接设置
该字段。

上述 helper 覆盖 `message/model_call/tool_call_proposal/tool_call/tool_result`。高级调用方也可用
`submit/submit_batch` 提交 `CandidateEvent`。SDK 只返回分析结果，不可能自动控制它未持有的副作用；因此
调用方必须把 `blocked` 检查放在实际模型、Tool、消息发送、文件写入等操作之前。

YAML 与 SDK 编排不重合：代码决定“何时产生哪些 Event、是否执行副作用”，YAML 决定“Event/Relation
满足什么安全条件时产生 Finding 与 Decision”。

## 6. 选择接入方式

| Agent 情况 | 接入 | 保证 |
| --- | --- | --- |
| 只需在任意位置取得检测 fact | `DetectorRunner` | 无 YAML；应用自行解释 fact 并控制副作用 |
| 能在任意代码位置提交语义 Event | `GuardrailRun` | 框架无关；由应用执行 Decision |
| 可注入 LLM 与 Tool 接口 | Inline Wrapper | 中介经过包装器的模型和工具调用 |
| 可配置 Model Provider Base URL | Provider Gateway | 中介模型请求与非流式/流式响应 |
| Tool 通过 MCP Server | MCP Gateway | 中介固定 Server 的 `tools/call` |
| LLM HTTP + MCP Tool | 两种 Gateway | 分别覆盖模型和工具边界 |
| 直接 Shell/函数/HTTP | 当前不能完整覆盖 | 需要 Hook/Sandbox/网络代理 |

LLM Gateway 阻止 ToolCall 返回 Agent，不等于阻止 Agent 经其他路径执行工具。

## 7. Inline

框架无关接口：

```python
class LLMClient(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse: ...

class ToolExecutor(Protocol):
    async def execute(self, call: ToolCall) -> ToolResult: ...
```

LLM 与 Tool Wrapper 必须共享任务级 Session：

```python
session = EnforcementSession(analyzer=runtime, trace=Trace(id="trace-1"))
llm = GuardedLLMClient(inner=provider, session=session)
tools = GuardedToolExecutor(inner=executor, session=session)
```

Inline LLM：

```text
new input Events + MODEL_CALL allow → inner.complete
→ observed output Events allow → return
```

Wrapper 维护请求历史 cursor，只接受上次历史的精确扩展，并把本轮新增历史与 `MODEL_CALL` 组成 batch。
observed response Event 显式 `derived_from` 该轮 `MODEL_CALL`。复杂 Framework 状态仍推荐直接使用
`GuardrailRun`，由调用方持有 EventRef，而不是依赖 Wrapper 猜测身份。

Inline Tool：

```text
observed TOOL_CALL allow → inner.execute
→ observed TOOL_RESULT allow → return
```

Wrapper 不按 payload 相等自动推断 proposal 来源；ToolResult 只引用实际 ToolCall。需要 proposal→实际调用
关系时应使用 `GuardrailRun.tool_call(..., proposal=...)` 显式提交。

- 调用前 block：底层调用次数为零；
- 输出释放前 block：底层副作用已发生，但原结果不返回、不提交。

## 8. Model Provider Gateway

Agent 不导入本项目，只修改 base URL：

```python
client = OpenAI(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080/v1/openai",
)
```

同一个 base URL 支持 `client.chat.completions.create(...)` 和 `client.responses.create(...)`；也可把 base
URL 设为 `/v1` 使用标准 `/v1/chat/completions`、`/v1/responses` alias。Responses 当前只支持可完整映射的
文本、instructions、custom function 与 function output。

每个请求创建独立 Session。规范化历史 Event 与 `MODEL_CALL` 在固定上游前于 `before_model_call` 检查；
非流式响应完整通过输出 Decision 后才释放。`stream=True` 时，Chat data-only SSE 和 Responses named SSE
都由 Adapter 转为累计 Canonical output：

- 文本 delta 对累计前缀做 tentative 检查，allow 后释放当前窗口；
- Tool arguments 在完整 JSON、声明、Schema 和 Policy 检查前不释放；
- terminal event 对完整输出再次检查并提交一个最终 Event；
- block/error 发送脱敏 SSE error，当前未通过窗口不释放；此前窗口已经发送，不能撤回。

响应头 `x-guardrail-streaming: prefix-guarded-non-retractable` 明示这一弱于完整缓冲的保证。需要完整输出
原子判断时使用 `stream=False`。当前仍不提供跨 HTTP 请求 Session。

非 OpenAI wire format 可由可信部署代码实现 `ModelProviderAdapter`，并在
`create_app(model_routes={"/v1/providers/name": adapter})` 注册。路由和相对上游路径在启动时固定；请求不能
携带动态 URL。仓内 Toy Adapter 用非流式与自定义 `token/done` SSE 证明扩展合同，不是发布的生产 Provider。

Adapter 合同分三组方法：`parse_request/request_to_canonical/request_payload`，
`parse_response/response_to_canonical/response_payload`，以及 `is_streaming/stream_decoder`；另有部署固定的
`upstream_path`。流 decoder 只能返回 `HOLD/GUARD/FINAL` 与累计 `ModelResponse`，不能执行 Policy 或创建
可信安全事实。公共类型从 `agent_guardrail` 导出，HTTP 组合仍由 gateway extra 的 `create_app` 完成。

## 9. MCP Gateway

```python
async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    result = await client.call_tool("send_email", arguments)
```

当前支持 MCP `2026-07-28` 的 `server/discover`、`ping`、`tools/list`、`tools/call`。只有 `tools/call`
创建 Session 并经过 `before_tool_call/before_tool_output_release`；其他方法不伪造 Tool Event。每次调用
独立，因此没有跨 ToolCall 计数或隐式审批。

## 10. Audit 与测试组件

AuditSink 只接收 Decision，不接收 Event payload。JSONL 摘要包含时间、trace、event、action、Rule/code、
Policy version/hash。

`agent_guardrail.testing` 的 ScriptedLLM、FakeToolExecutor 和 SimulatedAgent 用于确定性验证 allow/log/block
和副作用计数，不证明 Detector 算法准确率；生产模块不得导入 testing。真实 HTTP 黑盒测试还验证外部
OpenAI/MCP Agent 只改变 URL，调用前 block 时固定上游调用次数为零。

精确 HTTP/MCP 合同见[Gateway 协议参考](../reference/gateway-protocol.md)，进程配置见
[运行指南](operations.md)。
