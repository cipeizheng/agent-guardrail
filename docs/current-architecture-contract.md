# 当前架构合同

> 状态：日常实现的唯一架构合同，只描述当前事实、不可破坏约束和明确范围。架构历史只存在于 Git，
> 不属于实现输入。
> 最后核对：2026-08-14，版本 `0.1.0`。

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
- Model Provider Adapter 只负责封闭 wire Schema 与 provider-neutral `ModelRequest/ModelResponse` 转换；
  可信部署代码可在 `/v1/providers/...` 注册固定相对上游路径，客户端不能选择 URL。
- OpenAI Chat Completions 与 Responses API 均支持非流式和 SSE Streaming；内置路由同时提供
  `/v1/openai/...` 与标准 SDK base URL 所需的 `/v1/...` 形式。
- MCP `2026-07-28` 无状态 `POST /v1/mcp`：`server/discover`、`ping`、`tools/list`、`tools/call`。
- Gateway 可选择进程内 Runtime，或通过版本化内部 HTTP 协议调用固定 Policy 的无状态 Core；两种模式复用
  同一 `PolicyAnalyzer.analyze_pending` 和唯一 v3 Policy 执行链。当前内部 Remote Core 协议版本为 v4。
- Inline LLM/Tool Wrapper 是低层便利接入，并必须共享一个请求/任务级 `EnforcementSession` 与 `Trace`。
- Canonical `Event.model_version` 为 4；一等 MatchPlan Event：`MESSAGE`、`MODEL_CALL`、
  `TOOL_CALL_PROPOSAL`、`TOOL_CALL`、`TOOL_RESULT`；payload 封闭且有 Schema 硬上限。Event、
  PendingTrace、Decision 和 YAML binding 不含 Enforcement Phase。`MODEL_CALL` 是轻量实际模型操作，
  不是完整请求快照；`TOOL_CALL_PROPOSAL` 是模型建议，`TOOL_CALL` 才表示即将发生真实副作用的调用。
- 数据来源和可能影响只存在于类型化 `Event.relations`（边挂在后发生事件上、指回 source，读作被动语态）：
  `derived_from` 表示派生，`influenced_by` 表示可能受其影响；时间顺序不得冒充任一种 Relation。
  策略条件算子 `may_influence` 读作主动语态（source 可能影响 target），查询的是这两类边。
- `EventSecurityFacts` 只持久保存绑定到具体 Event payload 的 `trust_class + trust_authority`；它由可信
  Session/SDK 接入显式提供，不能由普通 HTTP/Provider payload、metadata 或 EventOrigin 自我声明。
- 外部 Event 默认 `client_asserted`；只有 Enforcement 可建立 `observed/derived`。

## 3. 安全对象与上下文

- 核心资产：用户数据、用户意图、用户资源；威胁使用 `source → transform → sink` 描述。
- `FlowSecurityContext` 的 trust/sensitivity/destination/authorization 只能经 Session/PendingTrace
  专用通道注入，非 unknown 事实必须带允许的 authority。
- `EventSecurityFacts` 与 `FlowSecurityContext` 不自动互相复制：前者描述一个 Event payload 的来源可信度并
  随 Event 提交，后者描述当前 pending flow 的 source→sink 判断语境。Policy 可通过 Event safe envelope
  将历史 source trust 与显式 Relation 组合。
- 普通 attributes、metadata、HTTP/Provider payload 和 SDK Event payload 不能写入保留的
  `security_*` 参数或自我授权。
- Detector 只产生事实；没有可信 source/sink/destination/authorization 语境时，不得宣称完成
  隐私、控制完整性或资源完整性保护。
- 产品只支持单用户；公共 Schema、Policy 和运行时不建立 principal、tenant、数据 owner、跨用户授权或
  跨租户状态。Gateway/Core 服务凭据只保护部署边界，不代表终端用户身份。
- Runtime 只完整中介经过 Wrapper/Gateway 的调用。任意 Shell、直接 socket/HTTP、宿主文件或进程访问、
  凭据读取、持久化、资源耗尽和隔离逃逸不因 Detector/Policy 存在而受控；需要独立 Sandbox、网络
  egress、OS 权限和 Secret 隔离。Guardrail 应位于不可信 Agent Sandbox 外部的可信执行边界。

## 4. 不可破坏约束

1. 不使用 `eval`/`exec`、动态 Python、callback、import 或代码生成执行外部策略。
2. YAML 只能引用部署方显式注册、descriptor 约束的 Predicate/Detector；不能选择实现路径或 I/O 权限。
3. Predicate 必须纯且无 I/O；Detector 调用、输入字节、deadline、结果和 evidence 必须有界并失败安全。
4. Gateway 的 `before_model_call` 完成前不得请求上游模型；`before_tool_call` 完成前不得执行工具。
5. 非流式输出完整通过 `before_model_output_release` 后才能释放；输出检查 block 不能撤回已经发生的
   上游调用。Streaming 每个文本窗口只在累计 Canonical 前缀通过 tentative Decision 后释放，Tool arguments
   必须完整 JSON/Schema/Policy 检查后释放，终止时再原子提交完整输出；Gateway 只释放 Adapter 重新编码的
   封闭 SSE event，不透传原始 event；已释放窗口不能撤回。
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
13. 远程模式中 Core 启动时只读加载固定 Policy 与 Detector profile，请求不能上传 Policy、模型、规则、
    路径、命令或 endpoint；Core 只分析完整 PendingTrace，Gateway 持有 Trace、Audit、Provider Key 和
    全部副作用。
14. Remote Core 只接受当前封闭协议 v4；其他版本、Core 不可达、认证/协议/超限错误、非法 Decision 或
    Policy identity 变化必须失败关闭。Gateway 必须校验 trace、pending Event 与 Policy identity；破坏性
    wire Schema 变化必须更换协议版本，不能静默复用现有版本号。

## 5. 当前 capability 事实

- 默认 Detector：`secrets`、`pii`、`prompt_injection`、`unicode_security`、`python_ast_ipython`、
  `hidden_content`。
- 默认 Predicate：`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`。
- `prompt_injection_model`、`prompt_injection_judge`、带外部 backend 的 `pii`、`semgrep`、
  `yara_injection_signatures` 和 `is_similar` 只有部署代码显式注入后才发布。部署侧配置是逐组件的（环境变量
  `..._DETECTOR_PII/_SEMGREP/_YARA/_PROMPT_MODEL` 自由组合）；内置 preset（如 `full_local_v1`
  = presidio + semgrep + yara + 锁定提交的 DeBERTa，固定并离线加载）是组件组合的命名快捷
  方式，preset 与组件变量互斥。`is_similar` 的
  `EmbeddingProfile` 由部署方选择 encoder model、identity 和资源上限，Policy 只能提供 data、target 和
  threshold，不能选择 model、endpoint 或凭据。
- 运行时实际发布名称以默认 Registry 为事实来源；交付验证状态、稳定 roadmap ID 和完成定义以
  [`capability-status.yaml`](capability-status.yaml) 为事实来源。
- Policy 与直接 SDK 只能调用 Registry 中带 `DetectorPolicyDescriptor` 的 Detector；两条入口共享 encoding、
  输入字节、deadline、结果数量、类型与 evidence 校验。任一失败都显式返回/抛出脱敏错误，不能变成 no-hit。

## 6. 明确未交付

Framework 自动 history cursor、CEL/Invariant DSL、Policy 热加载、跨请求 Session Store、
MCP subscriptions、特定 Framework 生命周期 Adapter、Sandbox、Event 级 sensitivity、自动 source trust
分类、destination Registry、授权凭证、Redaction
TransformationPlan、SBOM/镜像签名/集群编排，以及状态矩阵中标为 `planned` 的能力。

多用户/多租户身份、数据所有权、跨用户共享与状态、按用户授权和租户控制面不属于未交付 roadmap，而是
明确的产品范围外能力；不得在后续阶段逐字段恢复。

当前 Responses Adapter 不接受隐藏服务端历史、内置远程 Tool、background、多模态或无法完整映射的 output；
Streaming 尚未做增量 Matcher/cache，每个累计前缀会重新分析，长流性能优化属于 P4。

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

## 8. 文档治理

- 当前合同、专项设计、roadmap 和 capability 状态只描述当前架构，不保存废弃方案、替代关系或迁移时间线。
- 需要讨论的复杂跨层改动可以使用临时 `docs/proposals/<topic>.md`；接受后必须把结论合并到当前合同、
  专项设计、代码与测试，并删除 proposal。
- Git commit、diff、tag 和发布记录承担历史追溯；活动文档不得建立第二套历史决策档案。
