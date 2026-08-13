# Architecture Decision Records

当前架构从 2026-08-11 起重新建立基线。ADR-0001–0013 已移出当前文档树，不再作为实现约束或日常
阅读材料；当前仓库不维护它们的索引。

日常任务先读 [`current-architecture-contract.md`](../current-architecture-contract.md)。只有当任务要改变该
合同中的长期边界时，才读取现行 ADR 或提出新 ADR。实现既有 roadmap capability 不需要历史 ADR。

## 现行 ADR

| ADR | 状态 | 作用 | 读取条件 |
| --- | --- | --- | --- |
| [0014](0014-current-architecture-baseline.md) | Accepted | 确立当前合同、事实来源和增量决策方式 | 修改架构合同、事实来源或 ADR 流程 |
| [0015](0015-remote-core-service.md) | Accepted | 固定 Policy 的远程 Core、协议与失败关闭边界 | 修改 Core/Gateway 服务边界或远程协议 |
| [0016](0016-phase-free-events.md) | Accepted | 分离 Phase-free Event 与 Enforcement checkpoint | 修改 Event、YAML 或 pre/post 接入语义 |
| [0017](0017-provider-streaming-boundary.md) | Accepted | Provider-neutral Adapter 与不可撤回的流式释放边界 | 修改 LLM Provider Adapter、Streaming 或输出释放承诺 |

## 何时需要新 ADR

以下变化需要短 ADR：新增 Action；改变 Policy/MatchPlan 执行语言或生产链；改变 Canonical Event/Relation
语义；改变 pre/post 安全承诺；引入远程 Core、持久化状态或新的信任主体；保存原始敏感内容；引入可修改
payload 的 Transformation；破坏性协议版本升级。

普通 Detector/Predicate 实现、规则集、文档修正和不改变上述合同的 Adapter 工作不需要 ADR，只需遵守
当前合同、专项设计和 capability 状态矩阵。

新 ADR 使用 [`template.md`](template.md)，正文目标不超过约 120 行。调研、竞品对比、执行清单、测试日志
和频繁变化的实现状态必须放入专项文档，不能重新塞回 ADR。
