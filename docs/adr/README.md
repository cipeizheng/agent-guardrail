# Architecture Decision Records

ADR 用于记录会长期约束实现的架构决策。

状态：

- Proposed
- Accepted
- Superseded
- Rejected

新增 ADR 使用四位递增编号。已有 Accepted ADR 不应直接重写结论；需要变更时新增 ADR 并将
旧记录标记为 Superseded。

当前记录：

- [0001：Python Rule + YAML Config](0001-python-rules-yaml-config.md)（由 0011 替代）
- [0002：Inline Core，同时规划 Gateway](0002-inline-core-gateway-planned.md)
- [0003：Canonical Event Model](0003-canonical-event-model.md)
- [0004：统一 Runtime 与 Enforcement 边界](0004-runtime-and-enforcement-boundaries.md)
- [0005：MCP 2026-07-28 无状态 Gateway](0005-mcp-2026-stateless-gateway.md)（部分替代 0004 的
  MCP 长 Session 假设）
- [0006：一等 Event Relation](0006-first-class-event-relations.md)（补充 0003/0004 的来源关系模型）
- [0007：面向 Invariant 的事件分析架构](0007-invariant-oriented-event-analysis.md)（部分替代
  0001/0004/0006，建立 PendingTrace 与 PolicyAnalyzer；双轨 Policy 方向后由 0011 替代）
- [0008：独立 Message Event 与 Input Normalization](0008-independent-message-input-normalization.md)
  （补充 0007，固定全量快照、显式增量、兼容迁移和批次安全语义）
- [0009：Structured RulePlan YAML Policy](0009-structured-rule-plan-policy.md)
  （历史决策；由 0010/0011 替代）
- [0010：Invariant 对齐的 Policy/Monitor 与通用匹配模型](0010-invariant-aligned-policy-monitor.md)
  （部分替代 0007/0009 的通用策略载体结论；其 MatchPlan 结论保留，v2 迁移结论由 0011 替代）
- [0011：MatchPlan 生产硬切换](0011-matchplan-production-cutover.md)
  （删除 Python Rule、Structured RulePlan、mandatory anchor 和 v1/v2 生产兼容轨道）
