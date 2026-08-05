# Repository Instructions

本仓库使用 AI 辅助实现。任何实现任务开始前必须阅读：

1. `AGENTS.md`。
2. `docs/architecture.md`。
3. 与任务相关的专项设计文档。
4. `docs/ai-development-guide.md`。
5. `docs/adr/` 中已接受的架构决策。

## 当前实现基线

当前版本为 `0.1.0`，已经实现：

- Canonical Model、严格 YAML Policy、可信 Rule/Detector Registry 和 `GuardrailEngine`。
- `GuardrailRuntime`、请求/任务级 `EnforcementSession` 和脱敏 AuditSink。
- `GuardedLLMClient`、`GuardedToolExecutor` 与 testing 中的确定性模拟 Agent。
- OpenAI-compatible 非流式 `/v1/openai/chat/completions` Gateway。
- MCP `2026-07-28` 无状态 `/v1/mcp` Gateway；只支持 `server/discover`、`ping`、
  `tools/list`、`tools/call`。
- `Trace` 的受控关系查询、类型化 `EventRelation` 来源边和 Inline/Gateway 边界来源记录；
  `source_event_ids` 只是从 Relation 计算的只读便捷属性和 Session 可信参数。
- `EventOrigin`、`CandidateEvent`、批量原子提交的 `PendingTrace` 和 `PolicyAnalyzer`；现有单 Event
  Session 入口已经委托 pending batch 主路径，Decision v2 绑定完整 pending Event ID 集合。
- 当前内置规则为 `secret_exfiltration`、`pii_exfiltration`、`tool_access` 和
  `tool_result_flow`；当前内置 Detector 为 `secrets` 和 `pii`。

当前没有实现：独立 Message Trace Event/Input Normalizer、表达式 Policy/CEL/Invariant DSL、
Dockerfile/Compose、Policy 热加载、跨请求 Session Store、LLM 实时 Streaming、MCP
`subscriptions/listen`、OpenAI Agents SDK/LangGraph Adapter、远程 Core、Sandbox 和更多规则集。
文档和实现不得把这些规划项写成已交付能力。

## 不可破坏的约束

- 不使用 Python `eval`/`exec` 执行配置或外部策略。
- 当前 YAML 只能选择已注册规则并提供经过 Pydantic 校验的参数；表达式 Policy 必须按 ADR-0007
  在 Event/Analyzer 稳定后通过受限 Parser、类型检查和有界 Interpreter 引入，不能生成 Python。
- Core 只返回 Decision，不直接执行 Agent、LLM 或 Tool 副作用。
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
- 外部上传的 Python Rule 默认不受支持。
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
- Rule、Detector 和 Phase 支持范围以默认 Registry 为唯一事实来源。
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

参考 Invariant 时优先吸收一等事件、`past_events + pending_events`、Monitor 和 Policy/Enforcement
分层；不要复制其自动顺序 dataflow、远程服务耦合或输入检查与上游请求并发的实现。策略语言必须
先用真实样例评估 CEL 与安全改造 Invariant Interpreter，不能仅凭相似语法直接复制。
不要因为参考 NeMo Guardrails 而复制 Colang、动态 `actions.py` 加载或完整对话编排运行时。
