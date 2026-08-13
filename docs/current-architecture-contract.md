# 当前架构合同

> 状态：日常实现的短合同。治理方式由
> [ADR-0014](adr/0014-current-architecture-baseline.md) 与
> [ADR-0016](adr/0016-phase-free-events.md) 确立；ADR-0001–0013 已移出当前文档树，不是实现输入。
> 最后核对：2026-08-13，版本 `0.1.0`。

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
- pending 分析使用完整 `committed past + whole pending batch`；batch 同 Trace、有界并原子提交。
- `DetectorRunner` 是不经过 Policy/Decision 的直接事实接口；它与 MatchPlan 复用同一个 descriptor-enforced
  Detector 执行器，因此不构成第二套 Policy 解释器或第二个 Detector 执行语义。

## 2. 当前接入与数据模型

- 框架无关 `GuardrailRun` SDK 直接提交语义 Event 与显式 `EventRef` Relation；应用自行选择插入位置，
  不要求每个 Agent Framework 提供专用 Adapter。
- 框架无关 `DetectorRunner` 可在任意应用位置直接运行一个或多个已发布 Detector；它不需要 YAML，返回
  脱敏 `Detection` fact，不返回 allow/log/block，也不执行 Agent 的 LLM/Tool/业务副作用。
- OpenAI-compatible 非流式 `POST /v1/openai/chat/completions`。
- MCP `2026-07-28` 无状态 `POST /v1/mcp`：`server/discover`、`ping`、`tools/list`、`tools/call`。
- Gateway 可选择进程内 Runtime，或通过版本化内部 HTTP 协议调用固定 Policy 的无状态 Core；两种模式复用
  同一 `PolicyAnalyzer.analyze_pending` 和唯一 v3 执行链。
- Inline LLM/Tool Wrapper 是低层便利接入，并必须共享一个请求/任务级 `EnforcementSession` 与 `Trace`。
- 一等 MatchPlan Event：`MESSAGE`、`MODEL_CALL`、`TOOL_CALL_PROPOSAL`、`TOOL_CALL`、
  `TOOL_RESULT`；payload 封闭且有 Schema 硬上限。Event、PendingTrace、Decision 和 YAML binding 不含
  Enforcement Phase。
- 数据来源和可能影响只存在于类型化 `Event.relations`：`derived_from` 表示派生，`may_influence` 表示
  可能影响；时间顺序不得冒充任一种 Relation。
- 外部 Event 默认 `client_asserted`；只有 Enforcement 可建立 `observed/derived`。

## 3. 安全对象与上下文

- 核心资产：用户数据、用户意图、用户资源；威胁使用 `source → transform → sink` 描述。
- `FlowSecurityContext` 的 trust/sensitivity/owner/destination/authorization 只能经 Session/PendingTrace
  专用通道注入，非 unknown 事实必须带允许的 authority。
- 普通 attributes、metadata、HTTP/Provider payload 和 SDK Event payload 不能写入保留的
  `security_*` 参数或自我授权。
- Detector 只产生事实；没有可信 source/sink/owner/destination/authorization 语境时，不得宣称完成
  隐私、控制完整性或资源完整性保护。
- Runtime 只完整中介经过 Wrapper/Gateway 的调用。任意 Shell、直接 socket/HTTP、宿主文件或进程访问、
  凭据读取、持久化、资源耗尽和隔离逃逸不因 Detector/Policy 存在而受控；需要独立 Sandbox、网络
  egress、OS 权限和 Secret 隔离。Guardrail 应位于不可信 Agent Sandbox 外部的可信执行边界。

## 4. 不可破坏约束

1. 不使用 `eval`/`exec`、动态 Python、callback、import 或代码生成执行外部策略。
2. YAML 只能引用部署方显式注册、descriptor 约束的 Predicate/Detector；不能选择实现路径或 I/O 权限。
3. Predicate 必须纯且无 I/O；Detector 调用、输入字节、deadline、结果和 evidence 必须有界并失败安全。
4. Gateway 的 `before_model_call` 完成前不得请求上游模型；`before_tool_call` 完成前不得执行工具。
5. 非流式输出完整通过 `before_model_output_release` 后才能释放；输出检查 block 不能撤回已经发生的
   上游调用。
6. MCP `tools/call` 每个 HTTP 请求使用独立 Session，并完整经过 `before_tool_call` 与
   `before_tool_output_release`；不得重新引入
   `initialize`、`Mcp-Session-Id`、GET stream 或 DELETE session。
7. `block` 不提交原始 pending Event，只提交脱敏 Decision Event；任一 Event block 时整批不提交。
8. Violation 必须绑定 pending Event；系统错误、超时和预算耗尽不能静默变成 no-match/allow。
9. 日志、Error、Finding、Violation metadata 和 Audit 不得包含完整 Secret、原始 PII 或完整 prompt。
10. Enforcement 来源参数只能引用同 Trace 中更早、已允许/记录的非 Decision Event。
11. 生产模块不得导入 `agent_guardrail.testing`。
12. 外部协议路由以 `gateway/app.py`、Gateway 环境变量以 `GatewaySettings` 为事实来源；远程分析路由以
    `core_service/app.py`、Core 环境变量以 `CoreSettings` 为事实来源。
13. 远程模式中 Core 只分析完整 PendingTrace；Gateway 持有 Trace、Audit、Provider Key 和全部副作用。
    Core 不可达、认证/协议/超限错误或 Policy identity 变化必须失败关闭。

## 5. 当前 capability 事实

- 默认 Detector：`secrets`、`pii`、`prompt_injection`、`unicode_security`、`python_ast_ipython`、
  `hidden_content`。
- 默认 Predicate：`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`。
- `prompt_injection_model`、带外部 backend 的 `pii`、`semgrep`、`yara_injection_signatures` 和
  `is_similar` 只有部署代码显式注入后才发布。内置部署 profile `full_local_v1` 固定并离线加载
  Presidio/spaCy、锁定提交的 DeBERTa、Semgrep 1.170.0 与包内 YARA ruleset。`is_similar` 的
  `EmbeddingProfile` 由部署方选择 encoder model、identity 和资源上限，Policy 只能提供 data、target 和
  threshold，不能选择 model、endpoint 或凭据。
- 运行时实际发布名称以默认 Registry 为事实来源；交付验证状态、稳定 roadmap ID 和完成定义以
  [`capability-status.yaml`](capability-status.yaml) 为事实来源。
- Policy 与直接 SDK 只能调用 Registry 中带 `DetectorPolicyDescriptor` 的 Detector；两条入口共享 encoding、
  输入字节、deadline、结果数量、类型与 evidence 校验。任一失败都显式返回/抛出脱敏错误，不能变成 no-hit。

## 6. 明确未交付

Framework 自动 history cursor、CEL/Invariant DSL、Policy 热加载、跨请求 Session Store、
实时 LLM streaming、MCP subscriptions、特定 Framework 生命周期 Adapter、Sandbox、Event 级
Security Fact、principal/tenant/destination Registry、授权凭证、owner-aware 端到端 Policy、Redaction
TransformationPlan、SBOM/镜像签名/集群编排，以及状态矩阵中标为 `planned` 的能力。

当前 Compose 的 Core/Gateway 容器加固只缩小服务自身权限，不构成 Agent Sandbox，也不提供 Agent 的
default-deny egress、宿主隔离或资源配额。

## 7. 行为完成定义

代码行为只有同时满足以下条件才能写成“已交付”：

- 实际实现或声明的真实后端运行，不以 mock/fake 代替算法有效性；
- 正常、攻击、相邻边界、异常/timeout/预算和脱敏测试通过；
- 调用前 block 的受保护副作用为 0，输出释放前 block 不释放原始结果；
- Registry descriptor、MatchPlan linking 和 Decision evidence 路径通过；
- README、专项文档、roadmap 和 capability 状态同步；
- 项目质量门通过。

外部模型/服务的 adapter 测试只证明接入合同；在真实后端 smoke/eval 完成前状态必须是 `adapter_only`。
