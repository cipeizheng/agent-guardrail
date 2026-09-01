# 与 Invariant 的规则语义对照

> 本文说明本项目如何对照 Invariant 的规则语义，以及哪些语义已经由生产代码和测试覆盖。
> 相关参考：[规则编写指南](../guides/policy-authoring.md)、[分析引擎参考](../reference/analysis-engine.md)。

## 1. 对照基线

参考对象是同级目录 `../invariant` 中 commit `2340fe2` 的代码。本页描述该参考实现与本项目生产模型之间的语义对应关系；具体交付状态见[检测能力状态矩阵](../capability-status.yaml)。

本项目使用自己的标准数据模型、Schema、匹配器和注册表，在本项目的安全边界内实现相应语义。I01–I14 由直接调用生产 Schema、编译器和匹配器的测试覆盖；测试不另写一套解释器。

## 2. 概念对照

| Invariant | 本项目 |
| --- | --- |
| `Policy.analyze(trace)` | 无状态 snapshot → AnalysisReport |
| typed/collection binding | typed Event / 有界 collection binding |
| predicate / derived variable | 声明式条件或可信 Predicate / derive |
| `raise PolicyViolation` | 静态脱敏 Finding |
| `->` | `precedes` 或 `linked_by`，不是来源 |
| `~>` | `immediately_precedes` |
| ToolOutput | Canonical `tool_result` |
| Python detector/import | 部署方 Registry descriptor |

## 3. I01–I14 行为对照

| ID | 能力 | 本项目合同 |
| --- | --- | --- |
| I01 | 按类型选择事件 | Event binding 与 origin/domain filter |
| I02 | 选择多个事件 | 命名笛卡尔积与组合预算 |
| I03 | 访问嵌套工具数据 | 安全字段路径与有界 collection |
| I04 | 派生值 | 有界 `split_lines` |
| I05 | 组合条件 | 编译期内联；代码只来自 Registry |
| I06 | 量词与局部变量 | 有界量词和 lexical binding |
| I07 | 判断先后顺序 | 顺序查询不写 Relation |
| I08 | 查询明确关系 | direct/ancestor 类型化 Relation |
| I09 | 无状态分析 | 确定性 SnapshotMatcher |
| I10 | 整批待提交分析 | 已提交历史 + 本次完整批次，命中结果必须涉及待提交事件 |
| I11 | 增量分析 | 当前为 snapshot 分析；增量 Matcher/cache 属于后续规划 |
| I12 | 部署方提供能力 | 显式 Registry；拒绝 Policy import |
| I13 | 范围与证据 | 有界脱敏位置与 evidence |
| I14 | 参数 | 可信 typed scalar |

## 4. 安全边界

- Policy 使用声明式 binding、Predicate 和 Registry capability；执行计划不加载任意 Python module/function，也不遍历任意对象。
- Matcher 只消费规范化 Event 和可信 capability 结果；Tool/LLM 调用由入口适配器与宿主负责。
- 时间先后使用 `precedes` 表达顺序，数据来源使用 `derived_from` 或 `linked_by` 表达。
- Finding、Error 和 Decision 使用脱敏投影，不携带完整 Event/content。
- MatchPlan 使用候选、组合、递归、evidence 等分项预算。

新增语义先扩展相邻 I01–I14 生产行为测试，并同步[路线图](../roadmap.md)或[当前架构合同](../current-architecture-contract.md)。作者格式见[规则编写指南](../guides/policy-authoring.md)。
