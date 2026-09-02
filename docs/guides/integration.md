# 应用接入指南

> 本文说明如何把 Agent Guardrail 接入 Python 应用、模型客户端或 MCP 工具客户端，并说明每个代码对象负责什么。
> 相关参考：[Gateway 协议](../reference/gateway-protocol.md)、[分析引擎参考](../reference/analysis-engine.md)。

## 1. 接入流程与代码对象

```text
GuardrailRuntime
  └─ MatchPolicyAnalyzer
       └─ SnapshotMatcher

EnforcementSession
  → PendingTrace
  → runtime.analyze_pending
  → Decision
  → 原子提交 / 脱敏拦截事件
```

`GuardrailRuntime` 持有已校验的规则和分析器；`EnforcementSession` 保存一次任务的事件、提交前的事件批次和安全上下文，并在分析完成后提交结果。它们都只负责检查和记录，不负责解析模型协议，也不直接执行模型或工具。

| 代码对象 | 作用 |
| --- | --- |
| `DetectorRunner` | 对文本或 JSON 运行一个已注册的检测器，返回检测结果 |
| `GuardrailRuntime` | 加载规则并提供规则分析入口 |
| `GuardrailRun` | 让应用按顺序提交消息、模型调用和工具调用 |
| `EnforcementSession` | 在副作用前检查一批事件，并原子提交允许的事件 |

文中的 `Registry` 表示“已注册能力的清单”，`EventRef` 表示“已提交事件的引用”。这些名称会直接出现在代码接口中，使用时应按示例传递，不需要自行实现一套同名对象。

## 2. 在 Python 代码中调用检测器

`DetectorRunner` 直接运行部署配置中已经注册的检测器。下面的代码检查检索结果中是否包含提示注入特征：

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

`detect_text` 处理 UTF-8 文本，`detect_json` 先把值编码成确定性的 JSON（代码中的编码名是 `canonical_json`），`detect_many` 按调用方给出的顺序对同一个值运行多个检测器。`capabilities` 列出名称、版本、输入编码、公开检测类型、输入/timeout/结果上限。批量调用会在运行任何检测器前校验全部能力和输入；任一后端在执行期间失败，整个调用都会以 `DetectorExecutionError` 失败，不返回可能被误解为安全的部分结果。

直接接口与规则分析共享同一套检测器注册信息和执行器，返回的 `Detection` 只包含类型、置信度、可选位置、遮罩和指纹，不包含原始命中内容。应用根据检测结果决定是否继续模型、工具、文件或网络操作。多条事件及其关系通过 `GuardrailRun` 提交；模型服务和 MCP 工具也可以通过 Gateway 接入，由 Gateway 控制调用顺序。

检测器后端返回的自由格式 `Detection.path` 不进入直接结果；`canonical_json` 的 span 只定位编码后的文本，不能当作原对象的字段坐标。

默认会生成一次调用级 `DetectionContext`。需要把指纹稳定绑定到应用内已有对象时，可以显式传入有界的 `DetectionContext(trace_id=..., event_id=...)`。检测配置由部署方选择，内容或 YAML 不能选择模型、文件、进程、上游地址或凭据。

## 3. 加载规则并进行分析

```python
runtime = GuardrailRuntime.from_policy_file(
    "policy.yaml",
    predicate_registry=predicates,
    detector_registry=detectors,
)

async with runtime:
    decision = await runtime.analyze_pending(pending)
```

未提供自定义 Registry 时使用默认检测能力。加载器依次校验 version-3 YAML、编译检查计划并连接检测能力；任一步失败，Runtime 都不会创建。生命周期是 `created → ready → closed`，关闭后的 Runtime 不能重新启动。

`analyze_pending(PendingTrace)` 是 Runtime 交给分析器的唯一入口。Runtime 不解析模型服务请求或响应，也不替应用决定把检查放在 Agent 的哪个生命周期位置。

## 4. 一批事件的提交流程

一次 `submit_candidates` 会按以下顺序处理：

1. 校验批次非空、有大小限制、属于同一 Trace 且标识唯一；
2. 验证关系只引用同一 Trace 中更早的事件或候选事件；
3. 分配连续的标识、顺序号和时间，构造不可变的 `PendingTrace`；
4. 在 Session 锁内调用分析器；
5. 验证分析器没有修改输入，且 `Decision` 精确绑定到本次 Trace 和待提交事件；
6. `allow/log` 原子提交全部事件；`block` 丢弃原始事件，只提交脱敏的决定事件；
7. 在锁外写入脱敏审计记录。

Trace 容量、Analyzer 异常、输入修改或 Decision identity 错误都变成 `GuardrailUnavailable`，候选原文不提交。锁不覆盖真实 LLM/Tool 副作用。

可信 `FlowSecurityContext` 经 Session 专用字段提交；普通 attributes 没有授权语义。Gateway 只为自己掌握的调用目标建立 destination；应用接入通过 Session 或 SDK 的专用参数提供安全上下文，并在目标改变时使用与新目标对应的 authorization。

## 5. 在应用中提交事件

`GuardrailRun` 是应用内的事件提交接口，可用于 OpenAI Agents、LangGraph 或自定义 Agent。应用在模型和工具操作前提交事件、读取决定，并使用同一次运行返回的 `EventRef` 建立明确关系：

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
    return  # 拦截决定在真实 Tool 执行前结束本次操作

assert checked.primary is not None
result = await executor.execute(call)
committed_result = await run.tool_result(result, call=checked.primary)
```

如果应用侧工具执行代码确认结果来自外部数据源，首次提交时应把 `EventSecurityFacts` 绑定到这一个候选事件。这个来源信息不会从 `FlowSecurityContext`、`EventOrigin` 或时间顺序自动推断：

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

随后把 `result_ref` 作为 `model_call(inputs=...)` 或 `tool_call(influenced_by=...)` 的来源。关系存储在目标事件上，但语义是来源事件影响目标事件。普通 HTTP 或模型服务请求不能直接设置这个字段。

上述方法覆盖 `message/model_call/tool_call_proposal/tool_call/tool_result`。高级调用方也可以使用 `submit/submit_batch` 提交 `CandidateEvent`。SDK 返回分析结果；应用在实际模型、工具、消息发送或文件写入前读取 `blocked`。

YAML 与 SDK 编排不重合：代码决定“何时产生哪些 Event、是否执行副作用”，YAML 决定“Event/Relation 满足什么安全条件时产生 Finding 与 Decision”。

## 6. 接入位置

| 接入位置 | 使用方式 | Guardrail 检查范围 |
| --- | --- | --- |
| Python 业务代码中的单项内容检查 | `DetectorRunner` | 返回检测结果，由业务代码处理 |
| 模型或工具操作前的应用代码 | `GuardrailRun` | 检查应用提交的事件，由应用执行决定 |
| OpenAI 或 Anthropic 客户端的 base URL | Provider Gateway | 检查模型请求和模型响应 |
| MCP Client 的 Server URL | MCP Gateway | 检查固定 MCP Server 的 `tools/call` |
| 同时使用模型服务和 MCP 工具 | Provider Gateway + MCP Gateway | 两类请求分别检查，各自使用请求级 Trace |
| Agent 的 Shell、函数和直接 HTTP 能力 | 宿主 Hook、沙箱或网络代理 | 控制主机和网络操作 |

Gateway 只能控制经过它的模型和工具请求；如果 Agent 还可以通过其他路径执行工具，仍需由宿主 Hook、沙箱或网络策略控制那些路径。

## 7. 通过 Gateway 接入模型服务

应用无需在模型调用代码中导入本项目，只需将模型客户端的 base URL 指向 Gateway：

```python
client = OpenAI(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080/v1/openai",
)
```

同一个 base URL 支持 `client.chat.completions.create(...)` 和 `client.responses.create(...)`；也可把 base URL 设为 `/v1` 使用标准 `/v1/chat/completions`、`/v1/responses` alias。Responses 当前只支持可完整映射的文本、instructions、custom function 与 function output。

Responses 的 `previous_response_id` 需要可信部署显式注入 `ResponsesStateStore`：

```python
from agent_guardrail.gateway import InMemoryResponsesStateStore, create_app

app = create_app(settings, responses_state_store=InMemoryResponsesStateStore())
```

该实现验证状态恢复发生在 `before_model_call` 之前。它在进程内保存有界状态。外部接入采用 [Agentic API downstream fork](https://github.com/cipeizheng/agentic-api) → 当前 Gateway → Provider：Agentic API 在前端恢复并展开 history，当前 Gateway 接收完整 input 后执行 Guardrail。外部拓扑的单实例状态存储使用 SQLite；直接访问当前 Gateway 的 `previous_response_id` 使用显式注入的本地 state owner。Chat Completions 仍由调用方提交完整 history。

每个模型请求创建独立 Session。Gateway 将客户端提交的完整对话历史展开成内部 Event，并与本次 `MODEL_CALL` 一起在调用固定上游前检查。普通多轮对话继续使用模型客户端现有的 history/messages 参数。非流式响应完整通过输出 Decision 后才释放。`stream=True` 时，Chat data-only SSE 和 Responses named SSE 都由 Adapter 转为累计 Canonical output：

- 文本增量会对累计前缀做临时检查，放行后释放当前窗口；
- Tool arguments 在完整 JSON、声明、Schema 和 Policy 检查前不释放；
- 结束事件到达后，对完整输出再次检查并提交一个最终 Event；
- 拦截或错误会发送脱敏 SSE error，当前未通过的窗口不释放；已经发送的窗口保持已发送状态，无法撤回。

响应头 `x-guardrail-streaming: prefix-guarded-non-retractable` 明示这一弱于完整缓冲的保证。需要完整输出原子判断时使用 `stream=False`。

非 OpenAI 对外协议格式可由可信部署代码实现 `ModelProviderAdapter`，并在 `create_app(model_routes={"/v1/providers/name": adapter})` 注册。路由和相对上游路径在启动时固定；请求不能携带动态 URL。仓内 Toy Adapter 只用非流式与自定义 `token/done` SSE 验证扩展合同，不是发布的生产 Provider。

Adapter 合同分三组方法：`parse_request/request_to_canonical/request_payload`，`parse_response/response_to_canonical/response_payload`，以及 `is_streaming/stream_decoder`；另有部署固定的 `upstream_path`。流式解码器只能返回 `HOLD/GUARD/FINAL` 与累计 `ModelResponse`，不能执行 Policy 或创建可信安全事实。公共类型从 `agent_guardrail` 导出，HTTP 组合仍由 gateway extra 的 `create_app` 完成。

Anthropic Client 使用 Gateway 根地址，SDK 会调用标准 `/v1/messages`：

```python
from anthropic import Anthropic

client = Anthropic(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080",
)
```

Messages 的文本与 client `tool_use/tool_result` 进入相同的内部统一格式、Session 和 Runtime 流程。该路由不接收 `mcp_servers` 或 Anthropic server tools，收到后会在调用模型上游前返回错误，因为让 Anthropic 服务端直接执行 MCP/Tool 会绕过本项目的 `before_tool_call`。

## 8. 通过 Gateway 接入 MCP 工具

```python
async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    result = await client.call_tool("send_email", arguments)
```

当前支持 MCP `2026-07-28` 的 `server/discover`、`tools/list` 和 `tools/call`。每个 `tools/call` 创建独立 Session，在请求固定 MCP Server 前检查工具名和参数，在返回结果前检查完整 ToolResult；其他方法不生成 Tool Event。

Provider Gateway 与 MCP Gateway 各自检查经过自己的请求并保留独立 Trace。跨步骤因果规则由应用通过 `GuardrailRun` 的 `EventRef` 明确建立。

## 9. 审计记录与本地测试工具

AuditSink 只接收 Decision，不接收 Event payload。JSONL 摘要包含时间、trace、event、action、Rule/code、Policy version/hash。

`agent_guardrail.testing` 中的 `ScriptedLLM` 提供预设模型响应，`FakeToolExecutor` 在内存中执行指定函数并记录调用次数。示例和测试用它们稳定验证放行、记录、拦截和副作用计数。检测算法的有效性由真实实现测试与独立评测验证。生产模块不得导入 testing。真实 HTTP 黑盒测试还验证 OpenAI/Anthropic/MCP 客户端只需改变 URL，且调用前拦截时固定上游调用次数为零。

精确 HTTP/MCP 合同见[Gateway 协议参考](../reference/gateway-protocol.md)，进程配置见[运行指南](operations.md)。
