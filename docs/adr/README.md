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

- [0001：Python Rule + YAML Config](0001-python-rules-yaml-config.md)
- [0002：Inline Core，同时规划 Gateway](0002-inline-core-gateway-planned.md)
- [0003：Canonical Event Model](0003-canonical-event-model.md)
- [0004：统一 Runtime 与 Enforcement 边界](0004-runtime-and-enforcement-boundaries.md)
- [0005：MCP 2026-07-28 无状态 Gateway](0005-mcp-2026-stateless-gateway.md)（部分替代 0004 的
  MCP 长 Session 假设）
- [0006：一等 Event Relation](0006-first-class-event-relations.md)（补充 0003/0004 的来源关系模型）
- [0007：面向 Invariant 的事件分析架构](0007-invariant-oriented-event-analysis.md)（部分替代
  0001/0004/0006，建立 PendingTrace、PolicyAnalyzer 与双轨 Policy 方向）
