# Agent 与 Enforcement 接入指南

> 适合谁：把 Runtime 接入应用、Agent、OpenAI Client 或 MCP Client 的开发者。
> 解决什么：Runtime/Session 生命周期、接入选择和四个 Enforcement Point。
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

## 2. Runtime

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

`evaluate(GuardrailContext)` 只服务直接 `/v1/evaluate` 单 Event 兼容 API；内部 Session 使用
`analyze_pending` 主路径。

## 3. Session 原子性

一次 `evaluate_candidates`：

1. 校验 batch 非空、有界、同 Phase 且 key 唯一；
2. 验证 Relation 只引用同 Trace 更早 Event 或更早 Candidate；
3. 分配连续 identity/sequence/time，构造 immutable PendingTrace；
4. 在 Session lock 内调用 Analyzer；
5. 验证 Analyzer 未修改输入，Decision 精确绑定 trace/pending/phase；
6. allow/log 原子提交全部 Event；block 丢弃原始 Event，只提交脱敏 Decision Event；
7. 在锁外写脱敏 Audit。

Trace 容量、Analyzer 异常、输入修改或 Decision identity 错误都变成 `GuardrailUnavailable`，候选原文不
提交。锁不覆盖真实 LLM/Tool 副作用。

可信 `FlowSecurityContext` 只能经 Session 专用字段提交；普通 attributes 没有授权语义。Wrapper/Gateway
只覆盖它实际掌握的 destination，并在 sink 改变时清空旧 authorization。

## 4. 选择接入方式

| Agent 情况 | 接入 | 保证 |
| --- | --- | --- |
| 可注入 LLM 与 Tool 接口 | Inline Wrapper | 中介经过包装器的模型和工具调用 |
| 可配置 OpenAI Base URL | OpenAI Gateway | 中介模型请求和响应 |
| Tool 通过 MCP Server | MCP Gateway | 中介固定 Server 的 `tools/call` |
| LLM HTTP + MCP Tool | 两种 Gateway | 分别覆盖模型和工具边界 |
| 直接 Shell/函数/HTTP | 当前不能完整覆盖 | 需要 Hook/Sandbox/网络代理 |

LLM Gateway 阻止 ToolCall 返回 Agent，不等于阻止 Agent 经其他路径执行工具。

## 5. Inline

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
request normalization → pre_llm allow → inner.complete
→ observed response normalization → post_llm allow → return
```

首次请求/响应使用独立 Event batch；重复全量历史在缺少可证明 Framework identity 时使用显式聚合桥。
observed response Event 引用该轮 request primary Event。

Inline Tool：

```text
observed ToolCall → pre_tool allow → inner.execute
→ observed ToolResult → post_tool allow → return
```

Session 在精确 payload 相等时关联 post-LLM proposal 与实际 pre-tool call；ToolResult 引用实际 ToolCall。

- pre block：底层调用次数为零；
- post block：底层副作用已发生，但原结果不返回、不提交。

## 6. OpenAI Gateway

Agent 不导入本项目，只修改 base URL：

```python
client = OpenAI(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080/v1/openai",
)
```

每个 Chat Completions 请求创建独立 Session。完整请求快照在固定上游前执行 `pre_llm`；完整非流式响应
在释放前执行 `post_llm`。当前不提供跨请求历史或实时 streaming。

## 7. MCP Gateway

```python
async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    result = await client.call_tool("send_email", arguments)
```

当前支持 MCP `2026-07-28` 的 `server/discover`、`ping`、`tools/list`、`tools/call`。只有 `tools/call`
创建 Session 并经过 `pre_tool/post_tool`；其他方法不伪造 Tool Event。每次调用独立，因此没有跨 ToolCall
计数或隐式审批。

## 8. Audit 与测试组件

AuditSink 只接收 Decision，不接收 Event payload。JSONL 摘要包含时间、trace、phase、action、Rule/code、
Policy version/hash。

`agent_guardrail.testing` 的 ScriptedLLM、FakeToolExecutor 和 SimulatedAgent 用于确定性验证 allow/log/block
和副作用计数，不证明 Detector 算法准确率；生产模块不得导入 testing。真实 HTTP 黑盒测试还验证外部
OpenAI/MCP Agent 只改变 URL，pre block 时固定上游调用次数为零。

精确 HTTP/MCP 合同见[Gateway 协议参考](../reference/gateway-protocol.md)，进程配置见
[运行指南](operations.md)。
