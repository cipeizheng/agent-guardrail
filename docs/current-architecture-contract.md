# 当前架构合同

> 状态：日常实现的短合同。治理方式由
> [ADR-0014](adr/0014-current-architecture-baseline.md) 确立；ADR-0001–0013 已移出当前文档树，不是实现输入。
> 最后核对：2026-08-11，版本 `0.1.0`。

## 1. 当前生产链

唯一生产 Policy 链：

```text
strict version: 3 YAML → AuthorPolicy → immutable MatchPlan
→ capability linking → SnapshotMatcher → AnalysisReport
→ MatchPolicyAnalyzer → Decision → EnforcementSession
```

- 生产没有 Python Rule、Rule Registry、Structured RulePlan、mandatory anchor 或 v1/v2 fallback。
- Core/Matcher 只产生 Finding/AnalysisReport；Analyzer 只投影 Decision；它们不执行 Agent、LLM 或 Tool。
- Runtime 管理 Analyzer 生命周期；Provider 协议属于 Adapter/Gateway，副作用控制属于 Enforcement。
- pending 分析使用完整 `committed past + whole pending batch`；batch 同 Trace、同 Phase、有界并原子提交。

## 2. 当前接入与数据模型

- OpenAI-compatible 非流式 `POST /v1/openai/chat/completions`。
- MCP `2026-07-28` 无状态 `POST /v1/mcp`：`server/discover`、`ping`、`tools/list`、`tools/call`。
- Inline LLM/Tool Wrapper 必须共享一个请求/任务级 `EnforcementSession` 与 `Trace`。
- 一等 MatchPlan Event：`MESSAGE`、`TOOL_CALL`、`TOOL_RESULT`；payload 封闭且有 Schema 硬上限。
- 来源只存在于类型化 `Event.relations`；时间顺序不得冒充 `derived_from`。
- 外部 Event 默认 `client_asserted`；只有 Enforcement 可建立 `observed/derived`。

## 3. 安全对象与上下文

- 核心资产：用户数据、用户意图、用户资源；威胁使用 `source → transform → sink` 描述。
- `FlowSecurityContext` 的 trust/sensitivity/owner/destination/authorization 只能经 Session/PendingTrace
  专用通道注入，非 unknown 事实必须带允许的 authority。
- 普通 attributes、metadata、HTTP/Provider payload 和直接 `/v1/evaluate` 客户端不能写入保留的
  `security_*` 参数或自我授权。
- Detector 只产生事实；没有可信 source/sink/owner/destination/authorization 语境时，不得宣称完成
  隐私、控制完整性或资源完整性保护。

## 4. 不可破坏约束

1. 不使用 `eval`/`exec`、动态 Python、callback、import 或代码生成执行外部策略。
2. YAML 只能引用部署方显式注册、descriptor 约束的 Predicate/Detector；不能选择实现路径或 I/O 权限。
3. Predicate 必须纯且无 I/O；Detector 调用、输入字节、deadline、结果和 evidence 必须有界并失败安全。
4. `pre_llm` 完成前不得请求上游模型；`pre_tool` 完成前不得执行工具。
5. 非流式输出完整通过 `post_llm` 后才能释放；post block 不能撤回已经发生的上游调用。
6. MCP `tools/call` 每个 HTTP 请求使用独立 Session，并完整经过 `pre_tool/post_tool`；不得重新引入
   `initialize`、`Mcp-Session-Id`、GET stream 或 DELETE session。
7. `block` 不提交原始 pending Event，只提交脱敏 Decision Event；任一 Event block 时整批不提交。
8. Violation 必须绑定 pending Event；系统错误、超时和预算耗尽不能静默变成 no-match/allow。
9. 日志、Error、Finding、Violation metadata 和 Audit 不得包含完整 Secret、原始 PII 或完整 prompt。
10. Enforcement 来源参数只能引用同 Trace 中更早、已允许/记录的非 Decision Event。
11. 生产模块不得导入 `agent_guardrail.testing`。
12. 协议路由以 `gateway/app.py`、环境变量以 `GatewaySettings` 为事实来源。

## 5. 当前 capability 事实

- 默认 Detector：`secrets`、`pii`、`prompt_injection`、`jailbreak`、`dangerous_command`、
  `unicode_security`、`python_ast_ipython`、`hidden_content`。
- 默认 Predicate：`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`、
  `embedding_similarity`；默认 embedding 只做纯数值向量余弦。
- `prompt_injection_model`、Semgrep、YARA 和 Presidio NER 只有部署代码显式注入后才发布；adapter 测试不代表
  真实模型、ruleset 或 backend 已验证。文本 embedding 必须在 Policy 执行外预先计算。
- 运行时实际发布名称以默认 Registry 为事实来源；交付验证状态、稳定 roadmap ID 和完成定义以
  [`capability-status.yaml`](capability-status.yaml) 为事实来源。

## 6. 明确未交付

Framework 可证明增量 identity、CEL/Invariant DSL、Docker/Compose、Policy 热加载、跨请求 Session Store、
实时 LLM streaming、MCP subscriptions、Agents SDK/LangGraph Adapter、远程 Core、Sandbox、Event 级
Security Fact、principal/tenant/destination Registry、授权凭证、owner-aware 端到端 Policy、Redaction
TransformationPlan，以及状态矩阵中标为 `planned` 的能力。

## 7. 行为完成定义

代码行为只有同时满足以下条件才能写成“已交付”：

- 实际实现或声明的真实后端运行，不以 mock/fake 代替算法有效性；
- 正常、攻击、相邻边界、异常/timeout/预算和脱敏测试通过；
- pre block 的受保护副作用为 0，post block 不释放原始结果；
- Registry descriptor、MatchPlan linking 和 Decision evidence 路径通过；
- README、专项文档、roadmap 和 capability 状态同步；
- 项目质量门通过。

外部模型/服务的 adapter 测试只证明接入合同；在真实后端 smoke/eval 完成前状态必须是 `adapter_only`。
