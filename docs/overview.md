# 架构概览

> 适合谁：第一次理解系统或评审跨层变化的人。
> 解决什么：从安全目标、Policy 分析到实际 Enforcement 的完整主线。
> 不包含什么：YAML 字段参考、Matcher 细节和协议错误码。

## 1. 系统定位

Agent Guardrail 是本地 Policy Analyzer 加 Enforcement Runtime/Gateway。它保护用户的数据、意图和资源，
使用 `source → transform → sink` 描述威胁；Detector 只产生事实，完整违规还需要可信 source/sink、owner、
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

## 2. 运行图

```text
Provider / Framework payload
          │
          ▼
Adapter / InputNormalizer
          │ CandidateEvent batch
          ▼
EnforcementSession
  ├─ 分配 Event identity、sequence 和 time
  ├─ 校验 origin、phase、relation、security context 和容量
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

Runtime 管理 Analyzer 生命周期；Adapter 只处理 Provider/Framework 协议；Enforcement 控制何时允许副作用；
Gateway 组合 HTTP、认证、固定上游和请求级 Session。

## 3. Event、Trace 与来源

长期策略 Event 是：

- `MESSAGE`：封闭的 role 和 TextContent；
- `TOOL_CALL`：规范化 call ID、工具名和 JSON arguments；
- `TOOL_RESULT`：规范化 call ID、工具名和 JSON output。

`EventOrigin` 只回答声明来自客户端、实际观察还是可信派生，不代表内容可信或已授权。外部输入默认
`client_asserted`；只有 Enforcement 可以建立 `observed/derived`。

精确来源只存在于类型化 `Event.relations`。Adapter/Enforcement 只能在掌握对应事实时建立
`derived_from`；`precedes/immediately_precedes/may_influence` 只是顺序或保守可见性，不能冒充数据来源。

## 4. Snapshot 与 pending 分析

Matcher 在不可变 snapshot 上枚举 typed/multi Event binding、collection、derive 和量词，并执行显式条件。
pending 分析看到 `committed past + whole pending batch`，但 Finding 至少有一个 subject 必须属于 pending，
避免只匹配历史 Event 就重复阻断当前操作。

所有搜索、关系、Predicate/Detector、Finding 和 evidence 都使用分项预算。超限、timeout、参数或实现错误
进入结构化 AnalysisError，由生产 Policy 显式映射，不能静默变成 allow。

## 5. Policy 与 capability

MatchPlan 是 action-free 分析 IR。Rule action 和失败动作保存在生产 Policy 外层；Analyzer 在完整匹配后按
`block > log > allow` 聚合 Decision。

YAML 只能引用部署方注册并发布 descriptor 的 Predicate/Detector。Predicate 必须纯且无 I/O；Detector
输入编码、字节、deadline、结果类型、数量和 evidence 均受 descriptor 与 MatchPlan 预算约束。Policy
不能指定 module、模型地址、文件、进程、网络 endpoint 或实现参数。

## 6. Enforcement 保证

- `pre_llm` allow 前不请求模型上游。
- `pre_tool` allow 前不执行工具。
- 非流式 `post_llm` allow 前不向客户端/Agent 释放原始模型响应。
- `post_tool` allow 前不释放 ToolResult；但 post block 不能撤销已经执行的工具。
- block 不提交原始 pending Event，Audit 只接收脱敏 Decision。

OpenAI 和 MCP Gateway 每个受保护 HTTP 请求创建独立 Session；Inline LLM 与 Tool Wrapper 则必须共享同一
任务级 Session/Trace。Gateway 只能中介经过它的流量，Agent 直接 Shell/函数/HTTP 需要 Framework Hook、
Sandbox 或网络代理。

## 7. 接下来读什么

- 写 Policy：[Policy 作者指南](guides/policy-authoring.md)
- 理解 Matcher：[分析引擎参考](reference/analysis-engine.md)
- 增加 Detector/Predicate：[Capability 参考](reference/capabilities.md)
- 接入 Agent：[接入指南](guides/integration.md)
- 审查资产与威胁：[安全模型](security-model.md)
- 修改 HTTP/MCP：[Gateway 协议](reference/gateway-protocol.md)
