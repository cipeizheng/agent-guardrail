# 总体架构

## 1. 目标

Agent Guardrail 是一个小型、可解释、可本地部署的 Agent 安全运行时。它参考
Invariant 的 Policy Decision 与 Gateway Enforcement 分层，但不复制其 DSL。

系统必须回答两个不同问题：

1. Core：当前事件和历史 Trace 是否违反已启用规则？
2. Enforcement：如果违规，应当记录、拒绝模型请求，还是阻止工具执行？

Core 不执行副作用；Inline Enforcement、Tool Executor 和 Gateway 才能执行或阻断副作用。

## 2. 设计原则

1. **判断与执行分离**：Rule 返回 Violation，Engine 汇总 Decision，Enforcement 层执行 Action。
2. **检查先于副作用**：`pre_llm` 必须先于上游网络请求，`pre_tool` 必须先于工具函数。
3. **统一事件模型**：供应商与 Agent 框架的原始数据先转换成 Canonical Event。
4. **无自定义 DSL**：规则是可信 Python 类；YAML 只实例化已注册规则。
5. **Detector 与 Rule 分离**：Detector 发现事实，Rule 判断该事实在上下文中是否违规。
6. **默认可解释**：Decision 包含 rule ID、阶段、原因和脱敏证据；对外拒绝响应只返回协议所需的
   安全摘要，不强制回显 evidence。
7. **默认本地**：MVP 中 Core 内嵌在 SDK/Gateway 进程，无云端依赖。
8. **接口可拆分**：Core API 使用稳定模型，未来可以独立成 Decision Service。
9. **测试副作用**：不能只测试 Decision；必须断言被阻止的网络/工具调用没有发生。

## 3. 系统上下文

```text
Agent ──ModelRequest──► [GuardedLLMClient] ──allow──► LLM
Agent ◄─ModelResponse── [post_llm check] ◄─────────── LLM

Agent ───ToolCall─────► [GuardedToolExecutor] ─allow► Tool
Agent ◄──ToolResult──── [post_tool check] ◄────────── Tool

OpenAI Client ◄──────► [LLM Gateway] ◄─────────────► LLM Provider
MCP Client    ◄──────► [MCP Gateway] ◄─────────────► MCP Server
                              │
                              ▼
                     EnforcementSession
                              │ DecisionEvaluator
                              ▼
                     GuardrailRuntime facade
                              │
                              ▼
                     Guardrail Engine ◄──── Policy / Detector Registry
                              │
                              ▼
                           Decision
                              │
                              └──────────────► Session / Enforcement Point
```

## 4. 逻辑组件

### 4.1 Canonical Model

当前核心对象包括：

- `Event`：一次消息、模型响应、工具调用或工具结果。
- `Trace`：按时间排序的 Event 集合及任务级元数据。
- `GuardrailContext`：当前 Event、Trace、用户、租户和环境信息。
- `Detection`：Detector 返回的结构化事实与范围。
- `Violation`：某条 Rule 对某个 Event 的违规说明。
- `Decision`：Engine 汇总后的最终动作。

事件阶段固定为：

- `pre_llm`：将消息发送给模型之前。
- `post_llm`：模型响应返回给 Agent 之前。
- `pre_tool`：工具执行之前。
- `post_tool`：工具结果进入 Agent Trace 之前。

### 4.2 Detector

Detector 只回答“内容中发现了什么”，例如：

- PII 类型和范围。
- Secret 类型和范围。
- Prompt Injection 信号与置信度。
- URL、域名或危险命令片段。

Detector 不返回 `block`，也不知道目标工具是否可信。

当前默认 Registry 只注册 `SecretDetector`；PII、Prompt Injection、URL 和危险命令 Detector 是
后续扩展方向。

### 4.3 Rule

Rule 使用 Context 与 Detector 结果回答“该事实在当前上下文是否违规”。例如：

- Secret 出现在内部日志：`log`。
- Secret 进入外部邮件参数：`block`。
- 高风险工具没有用户确认事件：`block`。

当前默认 Registry 只注册 `secret_exfiltration` Rule，支持 `post_llm` 和 `pre_tool`。

### 4.4 Engine

Engine 负责：

- 选择适用于当前 Phase 的规则。
- 以明确的超时与错误策略执行规则。
- 在一次检查中共享 Detector 缓存。
- 汇总 Violation。
- 按 `BLOCK > LOG > ALLOW` 计算 Decision。
- 返回可供度量和审计使用的结构化 Decision。

Engine 不负责：

- 请求 LLM。
- 执行工具。
- 返回 HTTP Response。
- 将任意外部 Python 载入进程。

### 4.5 GuardrailRuntime

`GuardrailRuntime` 是本地 Core 的稳定公共门面，隐藏 Policy 构建、Engine 实例和 Detector
生命周期。Gateway 与 Inline 层只依赖 `DecisionEvaluator.evaluate(context)`，而不是自行构造
Rule 或操作 Registry。

Runtime 可以读取 Policy、持有本地 Detector Registry 并报告 Readiness，但不能执行 Agent、LLM、Tool
或 HTTP 副作用。`GuardrailEngine` 仍是单次评估算法；Runtime 是它的生命周期和发布边界。

### 4.6 EnforcementSession

每次 Inline Agent 任务、LLM HTTP 请求或 MCP `tools/call` HTTP 请求创建一个
`EnforcementSession`。它统一管理：

- 有界 Trace。
- Event ID、时间和顺序。
- DecisionEvaluator。
- 已脱敏的 AuditSink。
- tenant/user/environment 等请求属性。

Session 调用 Runtime 并记录检查结果，但不执行受保护副作用。`allow/log` 时记录原 Event；
`block` 时只记录脱敏的 `guardrail_decision` Event，避免被阻止的原始响应或工具结果进入历史。

HTTP Gateway 使用请求级 Session，不承诺跨请求调用计数。Inline Agent 的 LLM 和 Tool
包装器必须共享任务级 Session。MCP `2026-07-28` 已无协议级 Session，因此每个
`tools/call` 独立创建 Session。

### 4.7 Integration / Enforcement

Enforcement Point 包括：

- `GuardedLLMClient`：模型调用前后。
- `GuardedToolExecutor`：工具调用前后。
- OpenAI-compatible LLM Gateway。
- MCP `2026-07-28` Streamable HTTP Gateway。

它们将 Decision 映射为具体行为：

- `allow`：继续执行。
- `log`：继续执行并记录。
- `block`：不执行副作用，返回结构化拒绝。

不存在通用的 `GuardedAgent`。Inline 包装器实现普通的 `LLMClient`/`ToolExecutor` Protocol，
Agent 只持有这些协议。无法注入模型或工具边界时，使用对应 Gateway；任意本地代码副作用需要
Framework Hook、代理或 Sandbox。

### 4.8 Adapter

Adapter 只做协议转换和协议级校验：

- OpenAI Request/Response 与 Canonical Event 双向转换。
- MCP JSON-RPC `tools/call`/Result 与 Canonical Event 双向转换。
- JSON、ToolCall ID、参数类型和声明 Tool Schema 等结构校验。
- Adapter/Gateway 将 block/unavailable 结果映射到协议错误。

Tool allow/deny、Secret 外发、用户确认等安全判断仍由 Rule 完成，不能隐藏在 Adapter 中。

## 5. 包结构与依赖方向

当前结构：

```text
src/agent_guardrail/
├── models/                 # Canonical / provider-neutral model
├── config/                 # YAML schema 与 loader
├── core/                   # Rule / Detector / Policy / Engine
├── runtime/                # Runtime facade、DecisionEvaluator、bootstrap
├── enforcement/            # Session、Inline wrappers、Audit contract
├── adapters/
│   ├── openai/
│   └── mcp/                # MCP 2026-07-28 严格协议转换
├── gateway/                # FastAPI composition root 与 routes
├── rules/
├── detectors/
└── testing/                # Fake 与 SimulatedAgent
```

依赖规则：

```text
gateway ──► adapters ──────────────────────────────────────► models
   └──────► enforcement ──► runtime ──► core ──────────────► models
adapters ──────────────────────────────────────────────────► models
testing ──► enforcement protocols + provider-neutral models
rules/detectors ──► core protocols + models
```

- Core 不导入 FastAPI、HTTPX、OpenAI/MCP SDK、Agent Framework 或 testing。
- Runtime 不解释 Provider 格式，也不执行 Enforcement。
- Adapter 不实现 Rule。
- testing 组件不从生产顶层 API 默认导出。
- Gateway 是 composition root，负责组装依赖而不是承载策略逻辑。

## 6. 运行序列

### 6.1 LLM 非流式调用

```text
Agent
  │ messages
  ▼
normalize request
  ▼
session → runtime(pre_llm)
  ├─ block ──► refusal；不得请求上游
  └─ allow/log
         ▼
      LLM Provider
         │ response
         ▼
normalize response
  ▼
session → runtime(post_llm)
  ├─ block ──► refusal；不得向 Agent 返回原响应
  └─ allow/log ──► return response
```

### 6.2 工具调用

```text
Agent selects tool
  ▼
normalize ToolCall
  ▼
session → runtime(pre_tool)
  ├─ block ──► GuardrailBlocked；工具调用次数必须保持为 0
  └─ allow/log
         ▼
      execute tool
         │ result
         ▼
session → runtime(post_tool)
  ├─ block ──► 不把原始结果送回 Agent
  └─ allow/log ──► append trace
```

### 6.3 Event 提交语义

每次检查遵守以下顺序：

1. Adapter 严格解析原始数据，建立当前 Event；此时 Event 尚未进入 Trace。
2. Session 使用“当前 Event + 已提交 Trace”建立 `GuardrailContext`。
3. Runtime 返回完整 Decision。
4. `allow/log`：Session 提交当前 Event，再允许 Adapter 继续。
5. `block`：Session 丢弃当前 Event，只提交脱敏 Decision Event。
6. AuditSink 只接收 Decision，不接收原始 Provider 对象。

这保证 Rule 可以检查当前敏感内容，同时被阻止的 `post_llm`/`post_tool` 原文不会污染后续
Agent 上下文。内存 Trace 是否保留已允许的原文由后续数据保留策略控制，普通日志永不记录原文。

## 7. 部署拓扑

### 7.1 MVP：单进程

```text
┌─────────────────────────────────────┐
│ Gateway / Demo Agent                │
│  ├─ Embedded Guardrail Runtime      │
│  ├─ Built-in Rules and Detectors    │
│  └─ optional JSONL Audit Sink       │
└─────────────────────────────────────┘
```

优点是部署简单、检查低延迟、完全本地。未来 Docker Compose 只需一个应用服务，但当前仓库还没有
Dockerfile/Compose。

### 7.2 后续：Core 与 Gateway 可拆分

```text
Agent ──► Gateway ──► Guardrail Decision Service
               │                 │
               ▼                 ▼
          LLM Provider       Policy Store
```

只有出现多 Gateway、多语言接入或独立扩缩容需求时才实施拆分。

## 8. 从参考项目借鉴什么

### 8.1 Invariant

- Policy Decision 与 Gateway Enforcement 分离。
- Message、ToolCall、ToolOutput 的统一 Trace 思路。
- Detector 是规则可调用能力，而不是直接的阻断动作。
- 请求与响应都检查。
- 阻断与只记录策略分离。
- 测试使用固定 Trace 描述复杂 Agent 行为。

### 8.2 NeMo Guardrails

- 使用稳定 Runtime 门面隔离调用方和具体执行引擎。
- 输入、输出、ToolCall、ToolResult 由同一编排层执行一致的短路语义。
- Fake Model 与对话 Harness 属于 testing，不混入生产 Integration。
- 可选 Provider/Detector 保持可选依赖和延迟初始化。
- Server 复用同一配置与 Runtime，不再实现一套规则判断。

## 9. 明确不复制什么

- 不复制 Invariant DSL、Lark Parser、AST 与解释器。
- 不默认调用远程 Guardrails 云服务。
- 不允许输入检查和上游 LLM 请求并发启动。
- 不在流式 token 已发送后才声称完成输出阻断。
- 不把 Explorer/UI 作为 MVP 前置依赖。
- 不把“事件在前”夸大为精确的数据污点传播。
- 不复制 NeMo 的 Colang、Dialog Rail 和完整对话编排。
- 不扫描配置目录并自动执行 `actions.py`。
- 不把大量模型、Embedding 和知识库依赖放入默认安装。

## 10. 安全不变量

以下要求优先级高于性能优化：

1. `pre_llm=block` 时，上游请求数量为零。
2. `pre_tool=block` 时，工具执行数量为零。
3. `post_llm=block` 时，原始模型响应不返回客户端。
4. `post_tool=block` 时，原始工具输出不进入后续模型上下文。
5. 策略加载失败时不静默忽略。
6. Secret Detector 的日志只保留类型、指纹或遮罩值。
7. 高风险阶段的检查超时默认 fail-closed。
8. 所有阻断都能通过 trace ID 追溯，但审计记录本身不得泄密。
9. Inline Agent 的 LLM 与 Tool 包装器必须共享同一 Session，避免历史分裂。
10. LLM Gateway 只能宣称阻止上游模型和响应，MCP Gateway 只能宣称阻止其代理的 MCP 调用。

## 11. 待决问题

- Prompt Injection 第一版使用启发式还是可选模型 Detector。
- 是否需要在现有 Inline 异常/MCP JSON-RPC Error 之外增加可配置的安全替代 ToolResult。
- 是否在 v0.3 引入 SQLite，还是继续使用 JSONL。
- Gateway 认证后续是否增加 JWT、Key 轮换和主体权限模型。
- LLM Streaming 是完全缓冲后返回，还是明确标注为 observe-only 模式。

这些问题必须通过 ADR 决定，不能在实现任务中隐式改变。
