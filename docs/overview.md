# 架构概览

> 适合谁：第一次理解系统或评审跨层变化的人。
> 解决什么：从安全目标、Policy 分析到实际 Enforcement 的完整主线。
> 不包含什么：YAML 字段参考、Matcher 细节和协议错误码。

## 1. 系统定位

Agent Guardrail 是本地 Policy Analyzer 加 Enforcement Runtime/Gateway。它保护用户的数据、意图和资源，
使用 `source → transform → sink` 描述威胁；Detector 只产生事实，完整违规还需要可信 source/sink、
destination 或 authorization 语境。

当前唯一生产策略链是：

```text
strict v3 YAML
  → AuthorPolicy schema/type check
  → immutable MatchPlan
  → capability linking
  → SnapshotMatcher
  → AnalysisReport[Finding, AnalysisError]
  → MatchPolicyAnalyzer
  → Decision
  → EnforcementSession
```

生产没有 Python Rule、动态 import、callback、mandatory anchor、v1/v2 fallback 或第二套解释器。Core、
Matcher 和 Analyzer 都不执行 LLM、Tool 或其他 Agent 业务副作用。

项目同时提供一个较小的 `DetectorRunner` 事实接口：应用不写 YAML，直接对 text/canonical JSON 调用部署方
发布的 Detector。该接口只返回脱敏 Detection，不做跨 Event 判断或 allow/log/block；其 Detector 调用与
上述 Policy 链共享同一个 descriptor、timeout 和结果校验执行器，不是第二套 Policy 链。

## 2. 运行图

```text
Semantic SDK call / Provider payload or SSE
          │
          ▼
GuardrailRun / Adapter / InputNormalizer
          │ CandidateEvent batch
          ▼
EnforcementSession
  ├─ 分配 Event identity、sequence 和 time
  ├─ 校验 origin、relation、security context 和容量
  └─ 构造 immutable PendingTrace
          │
          ▼
MatchPolicyAnalyzer
  ├─ SnapshotMatcher ──► AnalysisReport
  └─ Finding/Error ────► Decision
          │
          ▼
allow/log：原子提交全部 pending Event
block：丢弃原始 pending Event，只提交脱敏 Decision Event
```

Runtime 管理 Analyzer 生命周期；Adapter 只处理 Provider/Framework wire↔canonical 协议；Enforcement
控制何时允许副作用；Gateway 组合 HTTP、认证、固定上游和请求级 Session。OpenAI Chat/Responses 以及可信
部署注册的非 OpenAI Adapter 复用同一 InputNormalizer/Session/Runtime，不复制 Policy 执行链。

三种产品入口的职责不同：

| 入口 | 是否需要 YAML | 输入与输出 | 谁决定/控制副作用 |
| --- | --- | --- | --- |
| `DetectorRunner` | 否 | text/JSON → Detection fact | 应用代码；SDK 不返回 Decision |
| `GuardrailRun` | 是 | Event/Relation → Decision | 应用在副作用前检查 `blocked` |
| Gateway/Inline | 是 | Provider 调用 → Decision + enforcement | 受信 Gateway/Wrapper |

Gateway 的 Decision backend 可以是进程内 `GuardrailRuntime`，也可以是独立 Core 容器中的同一 Runtime。
远程模式传输封闭、版本化的 `PendingTrace → Decision`；Core 不持有 Provider Key、不调用 LLM/Tool，Gateway
不挂载 Policy 或 Detector 资产并继续负责 Trace 原子提交、Audit 和副作用顺序。

## 3. Event、Trace 与来源

长期策略 Event 是：

- `MESSAGE`：封闭的 role 和 TextContent；
- `MODEL_CALL`：一次即将发生的模型操作；
- `TOOL_CALL_PROPOSAL`：模型建议、尚未实际执行的 ToolCall；
- `TOOL_CALL`：实际准备执行的 call ID、工具名和 JSON arguments；
- `TOOL_RESULT`：规范化 call ID、工具名和 JSON output。

Event 不含 `pre/post LLM/Tool` Phase；Policy 因而可以用于 Agent 的 memory、retrieval、prompt builder、
handoff 等任意语义插入位置。`GuardrailRun` 是框架无关 SDK：应用提交这些 Event，并用同一 run 返回的
`EventRef` 显式连接关系，不需要为每个 Framework 编写专用 Adapter。

`EventOrigin` 只回答声明来自客户端、实际观察还是可信派生，不代表内容可信或已授权。外部输入默认
`client_asserted`；只有 Enforcement 可以建立 `observed/derived`。

精确来源只存在于类型化 `Event.relations`。Adapter/Enforcement 只能在掌握对应事实时建立
`derived_from` 或 `may_influence`；`precedes/immediately_precedes` 只由 sequence 得出，绝不自动生成
Relation。

## 4. Snapshot 与 pending 分析

Matcher 在不可变 snapshot 上枚举 typed/multi Event binding、collection、derive 和量词，并执行显式条件。
pending 分析看到 `committed past + whole pending batch`，但 Finding 至少有一个 subject 必须属于 pending，
避免只匹配历史 Event 就重复阻断当前操作。

所有搜索、关系、Predicate/Detector、Finding 和 evidence 都使用分项预算。超限、timeout、参数或实现错误
进入结构化 AnalysisError，由生产 Policy 显式映射，不能静默变成 allow。

## 5. Policy 与 capability

MatchPlan 是 action-free 分析 IR。Rule action 和失败动作保存在生产 Policy 外层；Analyzer 在完整匹配后按
`block > log > allow` 聚合 Decision。

直接 Detector SDK 使用同一部署 Registry，但不编译 MatchPlan。`detect_text`、`detect_json` 和
`detect_many` 先完成 capability/encoding/输入上限预校验，再按 descriptor deadline 调用 Detector，并严格
校验 detection type、数量、span、mask 和 fingerprint。timeout、backend 异常和非法返回通过脱敏
`DetectorExecutionError` 显式失败，绝不伪装成空检测结果。

YAML 只能引用部署方注册并发布 descriptor 的 Predicate/Detector。Predicate 必须纯且无 I/O；Detector
输入编码、字节、deadline、结果类型、数量和 evidence 均受 descriptor 与 MatchPlan 预算约束。Policy
不能指定 module、模型地址、文件、进程、网络 endpoint 或实现参数。

默认 Registry 只包含本地确定性算法。`prompt_injection_model`、带外部 backend 的 `pii`、`semgrep` 和
`yara_injection_signatures` 必须由部署启动代码绑定固定 backend/profile 后显式发布；Policy 只能看到稳定
capability 名称和有限类型，不能看到或更换 profile。内置 `full_local_v1` 是一个已真实运行的固定部署
profile；默认仍为 `local`。文本 `is_similar` 只在部署注入 `EmbeddingProfile` 和 backend 后发布；Policy
提供比较文本和阈值，但不能选择 model、endpoint 或凭据。

## 6. Enforcement 保证

- `before_model_call` allow 前不请求模型上游。
- `before_tool_call` allow 前不执行工具。
- 非流式 `before_model_output_release` allow 前不向客户端/Agent 释放原始模型响应。
- Streaming 文本窗口只在累计 Canonical 前缀通过 tentative Decision 后释放；Tool arguments 在完整
  JSON/Schema/Policy 检查前不释放；terminal 时完整输出再检查并只提交一次。
- `before_tool_output_release` allow 前不释放 ToolResult；但输出检查 block 不能撤销已经执行的工具。
- block 不提交原始 pending Event，Audit 只接收脱敏 Decision。

Streaming block/error 会隐藏当前未通过窗口并以脱敏 SSE error 终止，但不能撤回早先已经通过并发送的窗口，
也不能保证未来上下文不会改变对旧前缀的判断。需要完整输出原子保证时使用非流式模式。当前累计前缀重复
分析，增量性能属于 P4。

这些名称只属于 OpenAI/MCP Gateway 的执行检查点，不进入 Event、PendingTrace、Decision、Inline Wrapper
或 YAML。编程式 SDK 只负责分析并返回 Decision；应用必须在真正副作用前检查 `blocked`。

OpenAI 和 MCP Gateway 每个受保护 HTTP 请求创建独立 Session；Inline LLM 与 Tool Wrapper 则必须共享同一
任务级 Session/Trace。Gateway 只能中介经过它的流量，Agent 直接 Shell/函数/HTTP 需要 Framework Hook、
Sandbox 或网络代理。Guardrail 不拦截 syscall、进程、宿主文件系统或任意网络 egress；对应边界外威胁和
所需强制控制见[安全模型的 Sandbox 责任矩阵](security-model.md#8-guardrail-无法替代的-sandbox-控制)。

## 7. 接下来读什么

- 写 Policy：[Policy 作者指南](guides/policy-authoring.md)
- 理解 Matcher：[分析引擎参考](reference/analysis-engine.md)
- 增加 Detector/Predicate：[Capability 参考](reference/capabilities.md)
- 接入 Agent：[接入指南](guides/integration.md)
- 审查资产与威胁：[安全模型](security-model.md)
- 修改 HTTP/MCP：[Gateway 协议](reference/gateway-protocol.md)
