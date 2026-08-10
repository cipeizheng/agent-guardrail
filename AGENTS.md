# Repository Instructions

本仓库使用 AI 辅助实现。任何实现任务开始前必须阅读：

1. `AGENTS.md`。
2. `docs/architecture.md`。
3. 与任务相关的专项设计文档。
4. `docs/ai-development-guide.md`。
5. `docs/adr/` 中已接受的架构决策。

## 当前实现基线

当前版本为 `0.1.0`，已经实现：

- ADR-0011 的唯一生产 Policy 链：严格 `version: 3` YAML → `AuthorPolicy` → immutable
  `MatchPlan` → capability linking → `SnapshotMatcher` → `AnalysisReport` →
  `MatchPolicyAnalyzer` → `Decision`。生产 Rule 没有 mandatory anchor。
- `GuardrailRuntime`、请求/任务级 `EnforcementSession` 和脱敏 AuditSink。
- `GuardedLLMClient`、`GuardedToolExecutor` 与 testing 中的确定性模拟 Agent。
- OpenAI-compatible 非流式 `/v1/openai/chat/completions` Gateway。
- MCP `2026-07-28` 无状态 `/v1/mcp` Gateway；只支持 `server/discover`、`ping`、
  `tools/list`、`tools/call`。
- `Trace` 的受控关系查询、类型化 `EventRelation` 来源边和 Inline/MCP 边界来源记录；
  `source_event_ids` 只是从 Relation 计算的只读便捷属性和 Session 可信参数。
- `EventOrigin`、`CandidateEvent`、批量原子提交的 `PendingTrace` 和 `PolicyAnalyzer`；单 Event
  Session 入口委托 pending batch 主路径，Decision v2 绑定完整 pending Event ID 集合。
- 独立 `MESSAGE` EventKind、封闭 `TextContent`/`Message` payload、独立事件 Phase 映射，以及
  pending Event、Relation 和 Trace 的 Schema 硬上限。
- Enforcement `InputNormalizer`：把全量 ModelRequest 快照展开为 `client_asserted/pre_llm` 批次，
  把 ModelResponse 展开为 `observed/post_llm` 批次，并执行 turn-local ToolResult 精确关联；OpenAI
  Gateway 已在请求上游前和释放响应前使用该组件，Inline Wrapper 仍保留聚合兼容路径。
- 封闭、不可变的 `Finding`、位置/binding/脱敏 evidence、`AnalysisError`、`AnalysisReport` 和稳定
  identity v1；无 mandatory anchor 的 MatchPlan 支持 typed Event/collection binding、`split_lines`
  derive、条件/量词/顺序与精确关系、静态 Finding projection 和全局/单 Rule 分项成本账本。
- 无状态、确定性、有界的 `SnapshotMatcher` 执行 typed/multi Event
  binding、collection/`split_lines`、布尔/比较/量词、顺序与精确来源查询、matcher range evidence 和
  可信 typed parameter；Rule/全局预算失败保持原子。
- `SnapshotMatcher.analyze_pending` 使用完整 `past + pending` snapshot 与
  pending subject 过滤；有界 `MatchMonitor` 对 committed snapshot 按 `(trace_id, finding.id)` 原子去重。
  tentative pending 分析不提前推进去重状态，保证 block/error 后重试仍然命中。
- 严格 YAML Loader 与类型化 Python `AuthorPolicy` 经过同一编译器
  生成不可变 MatchPlan；支持命名 Event/collection、derive、条件/量词、显式 Relation、静态 Finding、
  typed parameter 和编译期内联的可复用声明式 predicate。
- `PredicateRegistry`、`DetectorPolicyDescriptor` 和显式
  `compile_match_plan_capabilities` 把纯 MatchPlan 绑定到部署方注册实现；Matcher 串行执行已编译能力，
  分别限制调用、输入字节、deadline 和结果数量并只输出脱敏 evidence。
- 默认 v3 示例 Policy 为 Secret、PII、Tool Access 和显式 ToolResult Flow；默认 Detector 为
  `secrets` 和 `pii`。旧 v1/v2 Policy、Python Rule Registry、Structured RulePlan 和 Safe Profile
  兼容编译器已删除，加载时不得回退。

当前没有实现：可证明 identity 的完整
Framework 增量 Normalizer、CEL/Invariant DSL、Dockerfile/Compose、Policy 热加载、跨请求 Session Store、LLM
实时 Streaming、MCP `subscriptions/listen`、OpenAI Agents SDK/LangGraph Adapter、远程 Core、
Sandbox 和更多规则集。文档和实现不得把这些规划项写成已交付能力。

## 不可破坏的约束

- 不使用 Python `eval`/`exec` 执行配置或外部策略。
- 生产只接受 ADR-0011 的 v3 YAML；必须经过 Pydantic Schema、MatchPlan 静态编译、capability linking
  和有界 Matcher。不能生成 Python、定义 callback、import 或获得 I/O。
- MatchPlan Core 只返回 Finding/AnalysisReport，MatchPolicyAnalyzer 只投影 Decision；两者都不执行
  Agent、LLM 或 Tool 副作用。
- Runtime 只管理 Core 生命周期并实现 `PolicyAnalyzer`，不解释 Provider 协议或执行 Enforcement；
  `evaluate(GuardrailContext)` 只是直接 v0.1 API 的兼容桥，内部 Session 不得重新依赖它。
- Enforcement 必须发生在 `enforcement/` 或 Gateway 层；协议 Adapter 只做转换和协议校验。
- Inline LLM 与 Tool Wrapper 必须共享同一个 EnforcementSession/Trace。
- `pre_llm` 检查完成前不得请求上游模型。
- `pre_tool` 检查完成前不得执行工具。
- 非流式响应完整通过 `post_llm` 后才能返回客户端。
- MCP `tools/call` 必须为每个 HTTP 请求创建独立 Session，完整通过 `pre_tool/post_tool`；现代
  MCP 不得重新引入 `initialize`、`Mcp-Session-Id`、GET stream 或 DELETE session。
- 任何日志和 Violation metadata 都不得包含完整 Secret/API Key 或原始 PII。
- Python Rule/Rule Registry 不受支持；可信扩展只允许部署方注册 descriptor 约束的 Predicate/Detector。
- `block` 的原始 Event 不得提交到 Trace，只能提交脱敏 Decision Event。
- Candidate batch 必须同 Trace、同 Phase、有界并原子提交；任一 pending Event 被 block 时，整个批次
  的原始 Event 都不得提交。Violation 必须绑定至少一个 pending Event。
- Event 信任来源默认 `client_asserted`；只有 Enforcement 层可以标记 `observed`/`derived`，Provider
  payload 不得提升自身信任等级。
- 来源关系只能保存在类型化 `Event.relations` 中；`metadata["source_event_ids"]` 必须拒绝。
  Enforcement 调用方只能通过 Session 的 `source_event_ids` 专用参数提交，且只能指向同一 Trace
  中更早、已允许/记录的非 Decision Event。时间先后不得冒充来源关系。
- 生产模块不得导入 `agent_guardrail.testing`。
- 新增行为必须包含正常、违规、边界与副作用未发生的测试。

## 文档一致性

- 非 ADR 文档必须明确区分“当前实现”“设计合同”和“后续规划”。
- 环境变量以 `GatewaySettings` 的 `AGENT_GUARDRAIL_*` 映射为唯一事实来源。
- 路由以 `gateway/app.py` 为唯一事实来源；未注册的规划路由不能列入“当前端点”。
- Predicate、Detector 和 Phase 支持范围以 MatchPlan Schema 与默认 capability Registry 为事实来源。
- 已 Accepted 的 ADR 是历史决策，不直接改写结论；发生变化时新增 ADR，并标记替代关系。
- MCP 版本升级属于破坏性兼容任务，必须先核对官方最终规范和官方 SDK，再更新 ADR、Adapter、
  黑盒测试与文档。
- 修改代码后同步检查 README、architecture、专项设计、roadmap 和部署配置，避免状态漂移。

## 完成与提交

提交前至少运行：

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
```

提交前必须检查 `git diff --check`、暂存文件列表和 Secret 泄露；不得提交 `.venv`、缓存、构建
产物、`.env`、审计数据或真实凭据。

## 实现优先级

正确性和安全边界 > 可解释性 > 可测试性 > 性能 > 功能数量。

参考 Invariant 时按 ADR-0010/0011 对齐 typed/multi Event binding、派生值、量词、snapshot Policy、
`past_events + pending_events` Monitor 和增量 Finding；不要复制其 Python import/link、操作 handler、
远程服务耦合或输入检查与上游请求并发。Invariant `->` 只能对齐为 `precedes/may_influence`，不能生成
`derived_from`。新增能力必须先以 I01–I14 fixture 和相邻安全预算验证，不能重新引入 anchor-centric
Safe Profile，也不能把 CEL 或 Invariant 语法直接复制进 Policy。
不要因为参考 NeMo Guardrails 而复制 Colang、动态 `actions.py` 加载或完整对话编排运行时。
