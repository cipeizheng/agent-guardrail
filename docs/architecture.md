# 总体架构

## 1. 当前结论

Agent Guardrail 是本地、无副作用的 MatchPlan Policy Analyzer 加 Enforcement Runtime/Gateway。
ADR-0011 已删除 Python Rule、Rule Registry、Structured RulePlan、mandatory anchor 和 v1/v2 Policy
兼容轨道。当前生产执行链只有一条：

```text
strict v3 YAML
  → AuthorPolicy schema/type check
  → immutable MatchPlan v1
  → Predicate/Detector capability linking
  → SnapshotMatcher.analyze_pending
  → AnalysisReport[Finding, AnalysisError]
  → MatchPolicyAnalyzer
  → Decision
  → EnforcementSession
```

MatchPlan 是 action-free 的分析 IR；Rule 的 `action` 由生产 Policy 外层保存并在 Decision 投影阶段使用。
Core、Matcher 和 Analyzer 都不执行 LLM、Tool、网络或其他 Agent 副作用。

## 2. 运行图

```text
Provider/Framework payload
        │
        ▼
Adapter / InputNormalizer
        │ CandidateEvent batch
        ▼
EnforcementSession
  ├─ 分配 Event ID / sequence / time
  ├─ 校验 origin、phase、relation 和容量
  └─ 构造 immutable PendingTrace
        │
        ▼
MatchPolicyAnalyzer
        │
        ├─ SnapshotMatcher ──► AnalysisReport
        └─ Finding/Error ────► Decision
        │
        ▼
allow/log: 原子提交全部 pending Event
block: 丢弃原始 pending Event，只提交脱敏 Decision Event
```

OpenAI Gateway 执行 `pre_llm → upstream → post_llm`；MCP `tools/call` 和 Inline Tool Wrapper 执行
`pre_tool → tool → post_tool`。所有副作用只能发生在相应 pre Decision 允许之后；非流式响应只有完整
通过 post Decision 才能释放。

## 3. Policy 与匹配模型

### 3.1 唯一生产 Schema

生产只接受 `version: 3`。每条 Rule 声明：

- 一个或多个普通命名 Event binding；没有保留的 `anchor`；
- binding domain：`visible`、`past` 或 `pending`；
- 布尔条件、比较、字段存在、顺序关系或精确来源关系；
- 有界 collection、derive 和 quantifier；
- 受信任 Predicate/Detector capability；
- 静态 Finding code/message、pending subject 和脱敏 evidence；
- Enforcement action 与可降低的 Rule budget。

旧 `version: 1/2`、`type/config/expressions/anchor` 字段在 Schema 边界失败，不自动升级、不双写求值。

### 3.2 SnapshotMatcher

Matcher 对一个完整不可变 snapshot 搜索满足条件的 binding assignment。pending 分析可见
`committed past + whole pending batch`，但返回的 Finding 至少有一个 subject 必须来自 pending；只匹配
历史 Event 不会重复阻断当前操作。

资源账本分别限制 candidate Event、binding combination、collection/derive、quantifier、condition、
Relation、Predicate/Detector 调用/输入/时间、Finding 和 evidence。Rule 可降低全局预算，不能提高。
超限返回脱敏 `AnalysisError`，不会产生部分 Finding。

### 3.3 可信 capability

YAML 只能引用部署方已注册并发布 descriptor 的 Predicate/Detector：

- Predicate 必须纯、类型化、无 I/O，并声明 arity、输入字节、deadline 和证据策略；
- Detector 可执行受控检查，但调用数、编码、输入字节、deadline、检测类型和结果数均有界；
- 未注册、类型不兼容或 descriptor 不一致在激活前失败；
- Policy 不能指定 Python module/class/function path，也不能 import 或定义 callback。

默认 Detector 是 `secrets` 和 `pii`；默认 Predicate Registry 当前为空。

## 4. AnalysisReport 到 Decision

`MatchPolicyAnalyzer` 是 Runtime 使用的 `PolicyAnalyzer` 实现：

- Finding 的 pending subject 变成 Violation `event_ids`；历史 binding 只记录安全 Event ID；
- Rule action 按 `block > log > allow` 聚合；
- `max_violations` 在完整分析后截断，优先保留更高严重度且保持稳定顺序；
- `detector_timeout` 使用 `on_detector_timeout`；其他 AnalysisError 使用 `on_analysis_error`；
- 系统错误必须显式进入 Decision，不能成为隐式 allow；
- Detector evidence 只投影类型、位置、遮罩、指纹、置信度和实现版本，不包含原值。

## 5. Canonical Event 与关系

当前一等策略 Event 是：

- `MESSAGE`：封闭 `Message/TextContent`；
- `TOOL_CALL`：规范化 call ID、名称和 JSON arguments；
- `TOOL_RESULT`：规范化 call ID、名称和 JSON output。

`MODEL_REQUEST`/`MODEL_RESPONSE` 仍是 Provider-neutral DTO 和显式兼容 EventKind，但 MatchPlan 不能绑定
它们。直接 `/v1/evaluate` 与 Inline 重复全量请求快照仍需要单 Event 桥；这不是旧 Policy 引擎。

`EventOrigin` 区分 `client_asserted`、`observed`、`derived`。外部输入默认 `client_asserted`；只有
Enforcement 可以标记 observed/derived。Provider payload 无法提升自己的信任等级。

Relation 只存在于 `Event.relations`。当前来源关系为 `derived_from`，必须由掌握事实的
Adapter/Enforcement 提交：

- request primary Event → observed response Event；
- observed post-LLM ToolCall → 实际 pre-tool ToolCall；
- pre-tool ToolCall → post-tool ToolResult；
- ToolResult → 后续完整 ModelRequest（仅在 call ID 与序列化 output 精确对应时）。

时间先后只支持 `precedes/immediately_precedes/may_influence` 查询，不得自动升级为 provenance。

## 6. Runtime 与 Enforcement

`GuardrailRuntime` 管理一个已完整编译的 `MatchPolicyAnalyzer` 生命周期，公开稳定
`analyze_pending(PendingTrace) -> Decision`。`evaluate(GuardrailContext)` 只服务直接 v0.1 API，内部
Session 不依赖它。

`EnforcementSession` 请求/任务级持有 Trace，并序列化“构造 pending → 分析 → 原子提交”。锁不覆盖
LLM 或 Tool 副作用。Analyzer 异常、Decision identity 错误、Trace 容量不足或 pending 被修改都转换为
fail-closed `GuardrailUnavailable`，原始候选不提交。

OpenAI Gateway 对每个 HTTP 请求创建独立 Session；MCP `tools/call` 也为每个请求创建独立 Session。
Inline LLM 与 Inline Tool 必须共享同一个 Session/Trace。

## 7. 当前接入状态

- OpenAI-compatible 非流式 `/v1/openai/chat/completions`：已接 v3 MatchPlan；
- MCP `2026-07-28` 无状态 `/v1/mcp`：已接 v3 MatchPlan；
- Inline LLM/Tool：已接 v3 MatchPlan；首次请求和响应使用独立 Event，重复全量请求快照仍使用显式
  ModelRequest 桥；
- `MatchMonitor`：低层 committed Finding identity 去重已实现，尚未形成跨请求 Session Store；
- `/v1/evaluate`：保留单 Event Canonical API，内部转换为 PendingTrace。

## 8. 后续规划

尚未实现：可证明 identity 的 Framework 增量 Normalizer、多模态 Content、跨请求 Session Store、
Policy 热加载、实时 LLM streaming、更多 Predicate/Detector/Rule 样例、OpenAI Agents SDK/LangGraph
Adapter、远程 Core、Dockerfile/Compose 和完整 Sandbox。

新增 MatchPlan 节点或 capability 必须先用 I01–I14 相邻 fixture 验证表达能力、成本与脱敏边界；不得
重新引入 mandatory anchor、动态 Python Policy、自动顺序 provenance 或由 Core 执行副作用。
