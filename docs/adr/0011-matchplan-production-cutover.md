# ADR-0011：MatchPlan 生产硬切换

- 状态：Accepted
- 日期：2026-08-10
- 替代范围：ADR-0001 的 Python Rule/Rule Registry 生产轨道；ADR-0007 的双轨 Policy 与
  `GuardrailContext` Rule 视图；ADR-0009 的 Structured RulePlan、mandatory anchor 和 v1/v2 兼容
  合同；ADR-0010 中“完成旧 Safe Profile 等价证明后再接生产”的迁移顺序
- 保留范围：严格 YAML、无动态 Python、Canonical Event、PendingTrace 原子性、显式 Relation、
  Policy/Enforcement 分层、可信 Predicate/Detector descriptor、有界执行与失败安全

## 背景

ADR-0009 的 anchor-centric Structured RulePlan 能表达有限 Gateway 规则，但它把当前 Event、可见性、
预算重置和 Finding subject 混成一个特殊 anchor，不能自然承载 Invariant 对齐的多 Event snapshot
匹配。ADR-0010 随后定义了无 mandatory anchor 的 MatchPlan，并已经实现严格作者 YAML、不可变 IR、
SnapshotMatcher、MatchMonitor、可信 capability 编译和 Finding/AnalysisReport。

继续保留 Python Rule、Structured RulePlan 和 MatchPlan 三条生产或迁移轨道，会增加 Schema、成本模型、
Detector 调度和文档的长期重复。项目仍处于 `0.1.0`，本次明确接受一次破坏性 Policy 升级，不再为未发布
的 v1/v2 Policy 保持运行兼容。

## 决策

### 1. 生产 Policy 只有一条编译链

唯一生产配置版本为 `version: 3`：

```text
strict YAML v3
  -> AuthorPolicy schema/type validation
  -> immutable MatchPlan v1
  -> trusted Predicate/Detector capability linking
  -> SnapshotMatcher
  -> AnalysisReport
  -> MatchPolicyAnalyzer
  -> Decision
```

YAML Rule 使用普通命名 Event binding，不存在保留字或 mandatory anchor。`action` 是 Enforcement
映射，不进入 action-free MatchPlan IR。生产 Policy 必须支持 `pending` scope；运行时参数必须有默认值，
避免 Gateway 从不可信请求注入部署参数。

### 2. 删除旧 Rule 执行轨道

删除 `Rule` Protocol、`RuleServices`、`RuleRegistry`、`GuardrailEngine`、内置 Python Rule、
Structured RulePlan Interpreter 和 Safe Profile 兼容编译器。受信任 Python 扩展只允许实现经过
descriptor 发布的纯 Predicate 或 Detector；Policy 不能指定 module、class、callback 或 import。

旧 v1/v2 YAML 在 Schema 边界直接拒绝，不做自动升级、双写求值或静默回退。历史 ADR 保留并标记为
Superseded，用于解释决策演进；实现和普通设计文档不继续维护旧轨道。

### 3. AnalysisReport 到 Decision 的失败安全映射

`MatchPolicyAnalyzer` 对完整 `PendingTrace` 执行一次 whole-pending 匹配：

- Finding 只把 pending subject 投影成 Violation event IDs；历史 binding 只以 Event ID 出现在脱敏元数据；
- Rule action 按 Rule ID 显式映射，最终动作仍为 `block > log > allow`；
- `max_violations` 只截断已完成分析后的报告，并优先保留更高严重度；
- Detector timeout 使用 `on_detector_timeout`，其余 AnalysisError 使用 `on_analysis_error`；
- 分析错误不得变成隐式 allow，也不得包含原始 payload。

### 4. Enforcement 继续拥有关系和副作用

Gateway 与 Inline Wrapper 在调用上游前完成 `pre_llm`，在释放响应前提交独立 Message/ToolCall 批次；
Tool Wrapper 在执行前后提交 ToolCall/ToolResult。Enforcement 为确切的 request→response、
proposed ToolCall→executed ToolCall 和 call→result 记录类型化来源边。Matcher 只读取这些边，不根据时间
顺序伪造 provenance。

`ModelRequest`/`ModelResponse` DTO 和直接 `/v1/evaluate` 单 Event 桥仍有协议职责，不属于已删除的
Policy/Rule 兼容轨道。Inline 重复全量请求快照在可证明增量 identity 完成前仍使用显式聚合边界，且
MatchPlan 不允许绑定该聚合 EventKind。

## 结果

优点：生产只有一个 Schema、一个 IR、一个 matcher 和一个错误模型；SDK 与 Gateway 使用同一多 Event
规则能力；不再为错误的 anchor 抽象支付兼容成本。

代价：所有旧 v1/v2 Policy 必须人工改写为 v3；依赖 Python Rule API 的调用方必须改为 MatchPlan 或
受信任 capability；项目不提供自动迁移器。

## 验收

- v1/v2、`type/config/expressions/anchor` 等旧生产字段在加载时失败；
- 默认 Secret、PII、Tool Access 和显式 ToolResult Flow 示例均为 v3 MatchPlan YAML；
- Gateway、Inline 与 MCP 的正常、违规和副作用未发生测试直接经过 MatchPolicyAnalyzer；
- 生产包不存在 `RuleRegistry`、`GuardrailEngine`、Structured RulePlan 或 Safe Profile 兼容编译引用；
- README、architecture、policy、runtime、roadmap 和代码阅读地图只描述 v3 当前事实。
