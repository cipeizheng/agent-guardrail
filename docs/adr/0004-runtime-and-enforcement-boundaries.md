# ADR-0004：统一 Runtime 与 Enforcement 边界

- 状态：Accepted
- 日期：2026-08-04

## 背景

当前 Core 已经可以根据 `GuardrailContext` 返回 `Decision`，Inline Tool 包装器和模拟 Agent
也已经形成首个纵向切片。但如果 LLM 包装器、HTTP Gateway 和未来的 MCP Gateway 分别负责
创建 Event、维护 Trace、调用 Engine 和写审计，它们很容易形成三套不一致的判断与错误语义。

另一方面，真实 Agent 不一定允许替换内部 Tool Executor。把整个 Agent 包装成
`GuardedAgent` 既无法形成通用接口，也容易让用户误以为任意本地 Shell、HTTP 或函数调用都已
被拦截。

参考项目提供了两个互补经验：

- Invariant 将策略判断与 LLM/MCP 代理的协议拦截分开。
- NeMo Guardrails 使用稳定门面隐藏具体 Rail Engine，并把确定性 Fake 放在 testing 包中。

## 决策

### 1. 提供稳定的本地 Runtime 门面

新增 `GuardrailRuntime` 作为本地 Core 的公共门面。它负责：

- 持有当前完整校验后的不可变 Policy 与 `GuardrailEngine`。
- 管理 Detector 等运行资源的启动、关闭和 Readiness。
- 接受 Canonical `GuardrailContext` 并返回 `Decision`。
- 暴露不含 Secret 的 Policy version/hash 与运行状态。
- 为后续原子 Policy Reload 保留单一切换点。

`GuardrailRuntime` 不负责：

- 转换 OpenAI、MCP 或 Agent Framework 的原始数据。
- 请求 LLM、执行工具或返回 HTTP Response。
- 根据 `Decision` 执行 block/log/allow。
- 保存原始 Prompt、Tool 参数或 Tool Result。

`GuardrailEngine` 保留为具体的单次评估算法，不直接承担应用生命周期。

### 2. Enforcement 只依赖 DecisionEvaluator

定义最小协议：

```python
class DecisionEvaluator(Protocol):
    async def evaluate(self, context: GuardrailContext) -> Decision: ...
```

本地 `GuardrailRuntime` 实现该协议。未来如果拆分远程 Core，可以由
`RemoteDecisionClient` 实现同一协议，Inline/Gateway 不因此改写规则逻辑。

MVP 不实现远程 Core；该协议只是依赖倒置边界，不是新增网络服务。

### 3. 每个任务使用 EnforcementSession

`EnforcementSession` 属于 Enforcement 层，而不是 Core。它负责：

- 持有一个有界 `Trace`、`DecisionEvaluator`、`AuditSink` 和请求属性。
- 统一创建单调递增、时间和 ID 可注入的 Canonical Event。
- 调用 Evaluator，并将 Decision 交给适配器执行。
- `allow/log` 时把已检查 Event 追加到 Trace。
- `block` 时不把可能敏感的原 Event 追加到 Trace，只追加脱敏的
  `guardrail_decision` Event。
- 只把已经脱敏的 Decision 发送给 AuditSink。

Session 不请求上游，也不执行工具；副作用仍由具体 Enforcement Adapter 控制。

同一次 Inline Agent 任务中的 LLM 和 Tool 包装器必须共享一个 Session。HTTP Gateway v0.1
每个请求创建一个 Session；在引入服务端 Session Store 前，不承诺跨请求历史规则。

### 4. 明确三个 Enforcement Point

| Enforcement Point | 能阻止的副作用 | 不能保证阻止的副作用 |
|---|---|---|
| Inline Wrapper | 注入到包装器中的 LLM/Tool 调用 | Agent 通过其他对象执行的调用 |
| LLM Gateway | 上游模型请求、模型响应和响应中的 ToolCall 返回 | Agent 收到响应之外自行执行的本地工具 |
| MCP Gateway | 转发给指定 MCP Server 的 `tools/call` 及 ToolResult 返回 | 非 MCP 本地函数、Shell、直接 HTTP |

需要约束任意本地代码副作用时，必须使用 Agent Framework Hook、网络代理或 Sandbox；不能把
LLM Gateway 描述成完整 Agent Sandbox。

### 5. 固定 Phase 与协议映射

不新增 NeMo 风格的 rail 类型，也不改变 ADR-0003 的四个 Phase：

| 边界数据 | EventKind | Phase |
|---|---|---|
| 即将发给模型的请求 | `model_request` | `pre_llm` |
| 模型文本或 ToolCall 响应 | `model_response` | `post_llm` |
| 即将执行的工具调用 | `tool_call` | `pre_tool` |
| 即将交回 Agent/模型的工具结果 | `tool_result` | `post_tool` |

Provider/MCP Adapter 必须先完成严格解析，再建立 Canonical Event。无法无损、安全解析的输入
直接作为协议错误拒绝，不构造“尽力而为”的 Event。

### 6. Inline 接入不是 Agent 包装器

Inline 层只提供实现相同 Protocol 的装饰器：

```python
llm: LLMClient = GuardedLLMClient(inner=provider, session=session)
tools: ToolExecutor = GuardedToolExecutor(inner=executor, session=session)
agent = SomeAgent(llm=llm, tools=tools)
```

Agent 只认识普通 `LLMClient` 和 `ToolExecutor`。如果 Agent 无法注入这些边界，则应使用 LLM
Gateway；若还需要保证 MCP Tool 不执行，则同时使用 MCP Gateway。

### 7. Fake 和模拟 Agent 只属于 testing

`ScriptedLLM`、`FakeToolExecutor`、`SimulatedAgent` 和固定时钟/ID 工厂迁入
`agent_guardrail.testing`。`SimulatedAgent` 只依赖 `LLMClient` 与 `ToolExecutor`，不依赖
`GuardedToolExecutor`、Engine 或 Trace。Trace 由共享 Session 产生，测试可以从 Session 断言
事件和副作用计数。

测试组件可以随开发包安装，但不从顶层生产 API 默认导出。

### 8. Gateway 与 Inline 复用同一流水线语义

所有 Enforcement Adapter 都必须遵守：

```text
normalize → session.evaluate(pre) → block or side effect
          → normalize result → session.evaluate(post) → block or release
```

禁止在 pre Decision 完成前并发启动上游请求或工具执行。post Decision 为 block 时，原始响应
或 Tool Result 不得进入 Session Trace、Audit 或调用方。

## 目标包结构

```text
agent_guardrail/
├── models/                 # Canonical 与 provider-neutral 数据模型
├── config/                 # 严格 YAML 加载
├── core/                   # Rule、Detector、Policy、Engine
├── runtime/                # GuardrailRuntime、DecisionEvaluator、bootstrap
├── enforcement/            # Session、Inline LLM/Tool wrapper、Audit contract
├── adapters/
│   ├── openai/             # OpenAI HTTP 双向转换
│   └── mcp/                # MCP JSON-RPC 双向转换（后续）
├── gateway/                # FastAPI composition root 与 routes
├── rules/
├── detectors/
└── testing/                # Fake 与 SimulatedAgent
```

依赖只能向内：Gateway/Adapter/Enforcement 可以依赖 Runtime/Core/Models，Core 不能导入
FastAPI、HTTP Client、MCP、具体 Agent Framework 或 testing。

## 结果

优点：

- Inline、HTTP 和 MCP 共享相同 Decision、Trace 和错误语义。
- Agent 不需要依赖具体 Guardrail 包装器类型。
- Fake 与生产集成边界清晰。
- 可在不改变规则的情况下从本地 Runtime 演进到远程 Core。
- 明确区分“阻止 ToolCall 返回”和“阻止 Tool 实际执行”。

代价：

- 在现有 Gateway 开发前需要先进行一次包结构迁移。
- `GuardrailRuntime` 与 `EnforcementSession` 增加了两个需要保持职责克制的抽象。
- HTTP Gateway v0.1 的 Trace 是请求级，调用次数等跨请求规则只在 Inline/MCP 长 Session 中可靠。

## 明确不做

- 不实现自定义 DSL、Colang 或通用对话流程引擎。
- 不自动发现和执行策略目录里的 Python 文件。
- 不承诺 LLM Gateway 可以拦截 Agent 的任意本地副作用。
- 不在本 ADR 中增加 Remote Core、Session Store、Streaming 或 Sandbox。
