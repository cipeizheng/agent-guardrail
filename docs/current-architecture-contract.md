# 当前架构合同

> 日常实现的唯一架构合同，描述当前事实、不可破坏约束和产品边界。版本为 `0.1.0`，最后核对日期为 2026-09-02。

## 1. 规则执行流程

系统先读取 YAML 规则并编译成可执行的检查计划。每次收到待检查的事件时，规则匹配阶段会找出命中的规则并生成分析报告；决策分析阶段再把报告转换为放行、记录或拦截的决定，最后由执行层负责调用模型、工具和其他业务操作。

生产规则经过一条固定链路：

```text
version-3 YAML
  → PolicyDocument / AuthorPolicy（校验后的规则模型）
  → MatchPlan（不可变的检查计划）
  → 能力连接（capability linking：连接已注册的检测能力）
  → SnapshotMatcher（执行规则匹配）
  → AnalysisReport（命中项和分析错误）
  → MatchPolicyAnalyzer（将报告转换为决定）
  → Decision（放行、记录或拦截）
  → EnforcementSession（提交事件、返回决定并记录结果）
```

- 规则匹配阶段从事件快照中生成规则命中项和分析报告（代码对象为 `Finding` 和 `AnalysisReport`）；`MatchPolicyAnalyzer` 再把报告转换为 `Decision`。可信应用或 Gateway 在决定允许后执行模型、工具和业务副作用。
- 待提交分析（`pending`）读取完整的已提交历史和本次整批待提交事件；同一任务记录（`Trace`）中的事件批次一次性提交。
- `DetectorRunner` 与 `MatchPlan` 复用同一个受限检测器执行器。直接调用只返回检测事实；规则分析器才会生成放行、记录或拦截的 `Decision`。

## 2. 接入方式与数据模型

- `GuardrailRun` 是与具体框架无关的 SDK。应用提交语义事件，并用返回的 `EventRef` 建立明确关系；应用决定把检查放在生命周期中的哪个位置。
- `DetectorRunner` 可在任意应用位置运行已发布的检测器，返回脱敏 `Detection` 检测事实；应用决定如何处理该事实。
- 模型服务适配器负责在外部 HTTP 格式与内部 `ModelRequest/ModelResponse` 之间转换。可信部署代码可在 `/v1/providers/...` 注册固定的上游路径。
- OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 支持非流式与 SSE 流式响应。Anthropic 路由覆盖文本和客户端工具调用；服务端 MCP、thinking、缓存、container 和多模态内容属于协议拒绝范围。
- MCP `2026-07-28` 通过无状态 `POST /v1/mcp` 提供 `server/discover`、`tools/list` 和 `tools/call`。
- Gateway 可以使用进程内 Runtime，也可以使用版本化的独立 Core；两者都调用 `PolicyAnalyzer.analyze_pending`。
- Gateway 为每个模型请求和每个 MCP `tools/call` 分别创建请求级 `EnforcementSession` 与 `Trace`。模型请求中的完整对话历史会在本次请求内展开并检查；模型 Trace 与 MCP Trace 之间不建立自动关系。
- Gateway 直接接收的 Responses 请求，只有在可信部署注入 `ResponsesStateStore` 时才使用 `previous_response_id`；Gateway 先恢复有界的前序 input/output history，再创建本次请求的 canonical 快照并执行 Guardrail。当前 `InMemoryResponsesStateStore` 在进程内保存状态；Chat Completions 不使用该状态层。
- 外部 Responses 拓扑使用 `vendor/agentic-api` submodule 中的 Agentic API fork 作为 state owner，单实例配置使用 SQLite；Agentic API 恢复并展开前序 items 后，将完整 input 发送到 Gateway，Gateway 不读取 Agentic API 数据库。当前集成模式为 `client_only`，客户端 function call/output 经过 Agentic API、Gateway 和 Provider。
- 内部 `Event` 的 `model_version` 为 4。规则可以读取 `MESSAGE`、`MODEL_CALL`、`TOOL_CALL_PROPOSAL`、`TOOL_CALL` 和 `TOOL_RESULT`；执行层还会追加脱敏的 `GUARDRAIL_DECISION` 记录，但它不能作为规则输入或关系来源。
- `derived_from` 表示派生，`influenced_by` 表示可能影响；关系挂在后发生事件上并指向来源。`precedes` 与 `immediately_precedes` 只表达先后顺序，`linked_by` 查询显式的来源/影响关系。
- `EventSecurityFacts` 随具体事件内容保存 `trust_class + trust_authority`，由可信的 Session/SDK 接入显式提供。外部事件默认标记为 `client_asserted`；`observed/derived` 由执行层建立。

## 3. 安全对象与信任上下文

- 规则建模对象包括用户数据、用户意图和用户资源；执行路径描述数据来源、处理过程、目的地和授权。
- `FlowSecurityContext` 的 trust、sensitivity、destination、authorization 通过 Session/PendingTrace 的专用通道注入；非 `unknown` 值必须携带允许的 authority。
- `EventSecurityFacts` 描述单个事件内容的来源可信度；`FlowSecurityContext` 描述当前待提交数据从来源到目的地的判断语境。两者都需要显式提供，规则可以通过事件安全外壳和关系组合它们。
- Detector 只产生检测事实；规则需要把事实与可信来源、目的地或授权语境组合，才能形成相应的安全判断。
- 产品服务单用户。公共 Schema、Policy 和 Runtime 使用部署服务凭据保护边界，不建立 principal、tenant、data owner 或跨用户授权模型。
- Gateway 负责完整中介经过其模型和 MCP 路由的调用；使用 `GuardrailRun` 时，可信应用代码读取 `Decision` 后再执行模型、工具或其他副作用。Shell、直接 socket/HTTP、宿主文件或进程访问、凭据读取、持久化、资源耗尽和隔离逃逸由独立 Sandbox、网络 egress、OS 权限和 Secret 隔离控制。Guardrail 位于不可信 Agent Sandbox 外部的可信执行边界。

## 4. 不可破坏约束

1. 外部 Policy 使用封闭数据 Schema；执行路径不使用 `eval`、`exec`、动态 Python、callback、外部 import 或代码生成。
2. YAML 只能引用部署方显式注册且受 descriptor 约束的 Predicate/Detector；实现路径和 I/O 权限由部署代码固定。
3. Predicate 纯且无 I/O；Detector 的输入字节、deadline、结果数量、类型和 evidence 受 descriptor 与分析预算约束，并在异常、超时或非法返回时显式失败。
4. Gateway 在 `before_model_call` 完成后请求上游模型，在 `before_tool_call` 完成后执行工具。应用内接入在 `Decision.blocked` 为 false 后执行对应操作。
5. 非流式模型输出在 `before_model_output_release` 通过后释放。流式输出的每个文本窗口先检查累计的内部统一格式前缀，Tool arguments 先完成 JSON、Schema 和 Policy 检查；终止时原子提交完整输出。已释放窗口保持已发送状态。
6. 每个 MCP `tools/call` 使用独立的请求级 Session，并经过 `before_tool_call` 和 `before_tool_output_release`。MCP Gateway 使用无状态协议交互。
7. `block` 不提交原始 pending Event，只提交脱敏 Decision Event；一个 batch 中任一 Event block 时整批不提交。
8. Violation 绑定 pending Event；系统错误、超时和预算耗尽进入显式失败路径。
9. 日志、Error、Finding、Violation metadata 和 Audit 不包含完整 Secret、原始 PII 或完整 prompt。
10. Enforcement 来源参数只引用同 Trace 中更早、已允许或记录的非 Decision Event。
11. 生产模块不导入 `agent_guardrail.testing`。
12. 外部路由与配置分别以 `gateway/app.py`、`GatewaySettings`、`core_service/app.py` 和 `CoreSettings` 为事实来源。
13. Remote Core 启动时从只读部署文件加载固定 Policy 与检测配置（Detector profile）；Gateway 持有 Trace、Audit、Provider Key 和副作用顺序，Core 只分析完整 PendingTrace。
14. Remote Core 只接受封闭协议 v4。协议、认证、超限、Policy identity 或 Decision 校验失败时 Gateway 失败关闭；破坏性对外协议 Schema 变化使用新协议版本。

## 5. 当前检测能力

- 默认检测器：`secrets`、`pii`、`prompt_injection`、`unicode_security`、`python_ast_ipython`、`hidden_content`。
- 默认条件判断：`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`。
- `prompt_injection_model`、带外部后端的 `pii`、`semgrep`、`yara_injection_signatures`、`is_similar` 和 `prompt_injection_judge` 由部署配置或可信 Registry 提供。
- 实际发布名称、配置、入口、证据和状态以[`capability-status.yaml`](capability-status.yaml)为准。规则与直接 SDK 只调用带 descriptor 的已发布能力；两条入口共享输入编码、字节数、截止时间、结果类型和证据校验。

## 6. 当前范围与后续规划

当前运行范围是单用户、Gateway 请求级 Trace、完整请求历史展开和每个累计流式前缀重新分析。Gateway 内置 Responses 状态层是显式注入的进程内状态接口；外部 Responses 状态由独立 Agentic API 进程使用 SQLite 保存；Remote Core 是无状态分析服务；Compose 不启动外部 Agentic API。

后续规划见[`roadmap.md`](roadmap.md)，包括增量 Matcher/cache、Policy 热加载、TransformationPlan、目的地 Registry、一次性授权、Sandbox、内容审核/多模态能力、Framework 生命周期 recipe、SBOM、镜像签名、可观测性和集群编排。产品范围固定为单用户部署。

## 7. 行为完成定义

实现或文档只有在以下证据齐备时才写成“已交付”：

- 真实算法或真实后端位于声明的运行路径；
- 正常、违规、边界、异常/timeout/预算和脱敏测试通过；
- 调用前 block 的受保护副作用为 0，输出释放前 block 不释放原始结果；
- Registry descriptor、MatchPlan 的能力连接和 Decision evidence 路径通过；
- README、专项文档、roadmap 和 capability 状态同步；
- 项目质量门通过。

分类指标描述指定 Detector 与固定语料；规则、Gateway 和真实 Agent 部署分别使用其工作负载的安全与效用指标。适配器测试对应 `adapter_only`；真实后端仅在独立评测路径运行时对应 `experimental`；进入标准生产路径后按完成定义标记为 `baseline` 或 `verified`。

## 8. 文档治理

当前合同、专项设计和 capability 状态表达当前实现与设计合同；roadmap 表达后续规划。历史追溯使用 Git commit、diff、tag 和发布记录，活动文档保持单一当前口径。
