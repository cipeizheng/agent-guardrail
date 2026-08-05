# 总体架构

## 1. 目标

Agent Guardrail 是一个小型、可解释、可本地部署的 Agent 安全运行时。它参考
Invariant 的 Policy Decision 与 Gateway Enforcement 分层，但不复制其 DSL。

系统必须回答两个不同问题：

1. Core：本次 pending Event 批次与已提交 Trace 是否违反已启用策略？
2. Enforcement：如果违规，应当记录、拒绝模型请求，还是阻止工具执行？

Core 不执行副作用；Inline Enforcement、Tool Executor 和 Gateway 才能执行或阻断副作用。

## 2. 设计原则

1. **判断与执行分离**：Rule 返回 Violation，Engine 汇总 Decision，Enforcement 层执行 Action。
2. **检查先于副作用**：`pre_llm` 必须先于上游网络请求，`pre_tool` 必须先于工具函数。
3. **统一事件模型**：供应商与 Agent 框架的原始数据先转换成 Canonical Event。
4. **双轨 Policy**：当前使用可信 Python Rule；未来的文本表达式必须由受限 Parser、类型检查和
   有界 Interpreter 执行，不能生成 Python 或获得 I/O 能力。
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
                              │ PendingTrace
                              ▼
                     PolicyAnalyzer / GuardrailRuntime
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

- `Event`：一次 Enforcement 边界事件。当前 Session 提交模型请求/响应、工具调用/结果；聊天历史
  仍整体保存在 `ModelRequest.messages` 中，不会把每条 Message 独立提交到 Trace。
- `EventOrigin`：区分 `client_asserted`、`observed` 和 `derived`；普通 Event/Candidate 默认不受信任
  地使用 `client_asserted`，只有 Enforcement 层可以提升来源。
- `CandidateEvent`：尚未获得 Trace ID/sequence/time 的封闭候选描述，可以通过类型化引用连接
  已提交 Event 或同批次中更早的 Candidate。
- `PendingTrace`：已提交 Trace snapshot、非空 pending Event 批次、primary Event 和受信任
  attributes。批次内 Event 必须属于同一 Trace 和 Phase，并连续占用 sequence。
- `Trace`：按时间排序的 Event 集合、任务级元数据和同一 Trace 内向前引用的来源关系。
- `EventRelation`：从当前 Event 指向更早 Event 的类型化、显式来源边；当前只支持
  `derived_from`。
- `GuardrailContext`：当前仅作为 Built-in Python Rule 的单 Event 只读视图；Runtime 的主边界已经
  改为 `PendingTrace`。attributes 可由 Inline 调用方承载用户、租户或环境信息，当前 Gateway 不从
  客户端 payload 填充这些属性。
- `Detection`：Detector 返回的结构化事实与范围。
- `Violation`：某条 Rule 对某个 Event 的违规说明。
- `Decision`：Engine 汇总后的最终动作。当前 model version 2，同时绑定 primary Event 和完整
  `pending_event_ids`；每个 Violation 绑定至少一个 pending Event。

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

当前默认 Registry 注册 `SecretDetector` 和基础 `PIIDetector`。PII Detector 是本地确定性实现，
只识别邮箱、常见北美格式电话、带分隔符的美国 SSN、通过 Luhn 校验的银行卡号、中国大陆
18 位居民身份证号和大陆手机号形状；Prompt Injection、URL 和危险命令 Detector 仍是后续扩展
方向。

### 4.3 Rule

Rule 使用 Context 与 Detector 结果回答“该事实在当前上下文是否违规”。例如：

- Secret 出现在内部日志：`log`。
- Secret 进入外部邮件参数：`block`。
- 高风险工具没有用户确认事件：`block`（用户确认模型尚未实现）。

当前默认 Registry 注册四个 Rule：

- `secret_exfiltration`：阻止配置的 Tool 参数携带 Secret。
- `pii_exfiltration`：阻止配置的 Tool 参数携带所选择的 PII 类型。
- `tool_access`：按严格 allowlist/denylist 控制 Tool 名称。
- `tool_result_flow`：在 `pre_tool` 根据显式、可传递的来源边，阻止配置的来源 ToolResult
  流向目标 Tool；它不凭事件时间顺序推断数据流。

前三个 Rule 支持 `post_llm` 和 `pre_tool`；`tool_result_flow` 只支持实际副作用前的
`pre_tool`。

### 4.4 Engine

Engine 负责：

- 通过 `analyze_pending` 逐个建立 pending Event 的 Rule 视图，并选择适用于当前 Phase 的规则。
- 以明确的超时与错误策略执行规则。
- 在一次批次检查中共享 Detector 服务；包含事件级 evidence 的结果不能跨 Event 错误复用。
- 汇总 Violation。
- 按 `BLOCK > LOG > ALLOW` 计算 Decision。
- 返回可供度量和审计使用的结构化 Decision。

Engine 不负责：

- 请求 LLM。
- 执行工具。
- 返回 HTTP Response。
- 将任意外部 Python 载入进程。

### 4.5 GuardrailRuntime

`GuardrailRuntime` 是本地 Core 的稳定公共门面，隐藏 Policy 构建和 Engine 实例，并提供统一的
启动、关闭与 Readiness 边界。当前内置 Detector 是本地无状态对象，没有独立生命周期 Hook；
Gateway 与 Inline 层只依赖 `PolicyAnalyzer.analyze_pending(pending)`，而不是自行构造 Rule 或操作
Registry。`evaluate(GuardrailContext)` 只保留给直接 v0.1 Decision API 和迁移期测试，Session 不再
依赖该兼容桥。

Runtime 可以读取 Policy、持有本地 Detector Registry 并报告 Readiness，但不能执行 Agent、LLM、Tool
或 HTTP 副作用。`GuardrailEngine` 是一次 pending batch 的分析算法；Runtime 是它的生命周期和
发布边界。

### 4.6 EnforcementSession

每次 Inline Agent 任务、LLM Chat Completions HTTP 请求或 MCP `tools/call` HTTP 请求创建一个
`EnforcementSession`。它统一管理：

- 有界 Trace。
- Event ID、时间和顺序。
- PolicyAnalyzer 与 PendingTrace snapshot。
- 已脱敏的 AuditSink。
- tenant/user/environment 等请求属性。
- 由 Session 校验并写入的类型化 `EventRelation` 来源边。

Session 调用 Runtime 并记录检查结果，但不执行受保护副作用。`allow/log` 时原子记录整个 pending
batch；`block` 时不记录任何原始 pending Event，只记录一个脱敏的 `guardrail_decision` Event。
单 Event `evaluate(...)` 仍有 Tool/现有 Gateway 边界用途，但已经委托 `evaluate_candidates(...)`，
不再形成第二套提交逻辑。

HTTP Gateway 使用请求级 Session，不承诺跨请求调用计数。Inline Agent 的 LLM 和 Tool
包装器必须共享任务级 Session。MCP `2026-07-28` 已无协议级 Session，因此每个
`tools/call` 独立创建 Session。

来源保存在 `Event.relations`，不保存在通用 metadata；`metadata["source_event_ids"]` 会被拒绝。
`source_event_ids` 仅保留为 Event 的只读便捷属性和 Session 的可信提交参数。Session 只接受同一
Trace 中更早且不是 `guardrail_decision` 的 Event ID，把它转换为 `derived_from` Relation，并让
Trace 保持无环的向后引用。Inline 路径只在 Canonical 结构能精确对应时推导
`ModelResponse → ToolCall` 和 `ToolResult → ModelRequest`；请求/响应与调用/结果的同一边界关系由
Wrapper/Gateway 直接记录。无法精确对应时不创建边。该保证只存在于当前 Session，不能跨 Gateway
请求延伸。

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

Tool allow/deny、Secret 外发等当前安全判断，以及未来的用户确认判断，都必须由 Rule 完成，不能
隐藏在 Adapter 中。

## 5. 包结构与依赖方向

当前结构：

```text
src/agent_guardrail/
├── models/                 # Canonical / provider-neutral model
├── config/                 # YAML schema 与 loader
├── core/                   # Rule / Detector / Policy / Engine
├── runtime/                # Runtime facade、PolicyAnalyzer、bootstrap
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

### 6.3 Candidate batch 提交语义

每次检查遵守以下顺序：

1. Adapter 严格解析原始数据，建立一个或多个 `CandidateEvent`；当前 LLM/MCP Adapter 仍使用
   单 Candidate 降级入口。
2. Session 校验 Candidate key、Phase、信任来源和显式关系，关系只能指向已提交 Event 或同批次
   更早 Candidate。
3. Session 分配 ID、sequence、timestamp，建立 `PendingTrace(committed snapshot + pending batch)`。
4. Runtime/Engine 执行 `analyze_pending`；Built-in Rule 得到当前 pending Event、committed past 和
   更早 pending Event 组成的 `GuardrailContext` 视图。
5. `allow/log`：Session 原子提交整个 pending batch，再允许 Adapter 继续。
6. `block`：Session 丢弃整个 pending batch，只提交一个脱敏 Decision Event。
7. 含 Violation 的 Decision 会发送给 AuditSink；普通 allow 不逐条审计，AuditSink 也不接收原始
   Provider 对象。

这保证 Rule 可以检查本次全部敏感候选内容，同时被阻止的 `post_llm`/`post_tool` 原文不会污染
后续 Agent 上下文。内存 Trace 是否保留已允许的原文由后续数据保留策略控制，普通日志永不记录
原文。

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
- Rule 查询类型化事件及其关系，而不是只检查孤立字符串。当前项目用受控 Trace API、显式
  `EventRelation` 和 PendingTrace 实现这一点；表达式 Policy 方向已接受，但尚未选择 CEL 或
  Invariant 风格 Interpreter。
- Detector 是规则可调用能力，而不是直接的阻断动作。
- 请求与响应都检查。
- 阻断与只记录策略分离。
- 测试使用固定 Trace 描述复杂 Agent 行为。
- PII Detector 可以接受实体类型过滤；策略再决定其出现位置是否违规。当前
  `PIIDetector`/`pii_exfiltration` 沿用这种“事实检测与上下文决策分离”，但不引入 Invariant
  DSL，且没有复制其 Presidio 依赖。

### 8.2 NeMo Guardrails

- 使用稳定 Runtime 门面隔离调用方和具体执行引擎。
- 输入、输出、ToolCall、ToolResult 由同一编排层执行一致的短路语义。
- Fake Model 与对话 Harness 属于 testing，不混入生产 Integration。
- 可选 Provider/Detector 保持可选依赖和延迟初始化。
- Server 复用同一配置与 Runtime，不再实现一套规则判断。
- PII 能力作为可替换 Rail/Detector 集成存在，可覆盖 input/output/retrieval，并可选择检测或掩码。
  当前项目只实现 ToolCall 外发阻断，不声称已实现 NeMo 的 Presidio、GLiNER、远程服务或内容改写。

## 9. 明确不复制什么

- 不机械复制 Invariant DSL、Lark Parser、AST 与解释器；先用真实策略样例评估 CEL 和安全改造
  Interpreter，任何复用都必须满足许可证、资源限制和本地信任边界。
- 不默认调用远程 Guardrails 云服务。
- 不允许输入检查和上游 LLM 请求并发启动。
- 不在流式 token 已发送后才声称完成输出阻断。
- 不把 Explorer/UI 作为 MVP 前置依赖。
- 不把“事件在前”夸大为精确的数据污点传播。
- 不采用 Invariant 当前将同一列表中所有较早事件自动视为 dataflow 来源的语义。
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
6. Secret/PII Detector 的日志只保留类型、不基于原始 PII 的事件级指纹或遮罩值。
7. 高风险阶段的检查超时默认 fail-closed。
8. 所有阻断都能通过 trace ID 追溯，但审计记录本身不得泄密。
9. Inline Agent 的 LLM 与 Tool 包装器必须共享同一 Session，避免历史分裂。
10. LLM Gateway 只能宣称阻止上游模型和响应，MCP Gateway 只能宣称阻止其代理的 MCP 调用。
11. 来源边只能指向同一 Trace 中更早、已提交的非 Decision Event；没有边时不得用时间顺序替代。
12. 一个 pending batch 被 block 时，任何原始 pending Event 都不得提交；Decision/Violation 的
    Event identity 必须完整匹配该批次。
13. `client_asserted` 历史不得被当成服务端调用次数、用户批准或可信来源。
14. Analyzer/Rule 不得修改 PendingTrace；Core 和 Session 都会校验分析前后的 snapshot，变化时
    fail-closed。

## 11. 待决问题

- Prompt Injection 第一版使用启发式还是可选模型 Detector。
- 是否需要在现有 Inline 异常/MCP JSON-RPC Error 之外增加可配置的安全替代 ToolResult。
- 是否在 v0.3 引入 SQLite，还是继续使用 JSONL。
- Gateway 认证后续是否增加 JWT、Key 轮换和主体权限模型。
- LLM Streaming 是完全缓冲后返回，还是明确标注为 observe-only 模式。
- 真实 Invariant 风格策略样例应由 CEL 覆盖，还是需要安全改造其 Parser/AST/Interpreter。
- 没有稳定 Message ID 的全量聊天请求如何暴露独立 Message，同时避免把内容相似度当成身份。

这些问题必须通过 ADR 决定，不能在实现任务中隐式改变。
