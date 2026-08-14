# Invariant 对齐基线

> 适合谁：评审本项目与 Invariant Policy/Monitor 语义差异的人。
> 解决什么：参考版本、I01–I14 映射和有意不兼容项。
> 不包含什么：本项目作者语法教程。

## 1. 参考基线

参考对象是同级 checkout `../invariant` 的 commit `2340fe2`。2026-08-10 对 flow、monitor、quantifier、
derive、range 和 guarding 测试执行本地回放，结果 63 passed、2 skipped；跳过项依赖可选
Presidio/Transformers detector。

本项目要求自己的 Canonical Model、Schema、Matcher 和 Registry 得到等价安全结果，不复制 Invariant
源码、IPL、Python import、handler 或异常类型。I01–I14 由直接调用生产 Schema/编译器/Matcher 的测试覆盖，
不维护 test-only 影子解释器。

## 2. 术语映射

| Invariant | 本项目 |
| --- | --- |
| `Policy.analyze(trace)` | 无状态 snapshot → AnalysisReport |
| `Monitor` | 未实现；增量 Finding 去重属于 P4 roadmap |
| typed/collection binding | typed Event / 有界 collection binding |
| predicate / derived variable | 声明式条件或可信 Predicate / derive |
| `raise PolicyViolation` | 静态脱敏 Finding |
| `->` | `precedes` 或 `may_influence`，不是来源 |
| `~>` | `immediately_precedes` |
| ToolOutput | Canonical `tool_result` |
| Python detector/import | 部署方 Registry descriptor |

## 3. I01–I14

| ID | 能力 | 本项目合同 |
| --- | --- | --- |
| I01 | typed selection | Event binding 与 origin/domain filter |
| I02 | multi Event | 命名笛卡尔积与组合预算 |
| I03 | nested Tool | 安全字段路径与 collection |
| I04 | derive | 有界 `split_lines` |
| I05 | predicate composition | 编译期内联；代码只来自 Registry |
| I06 | quantifier/closure | 有界量词和 lexical binding |
| I07 | order | 顺序查询不写 Relation |
| I08 | exact relation | direct/ancestor 类型化 Relation |
| I09 | stateless | 确定性 SnapshotMatcher |
| I10 | whole-pending | past + pending，subject 含 pending |
| I11 | incremental | 未对齐（P4：增量 Matcher/cache） |
| I12 | host capability | 显式 Registry；拒绝 Policy import |
| I13 | range/evidence | 有界脱敏位置与 evidence |
| I14 | parameter | 可信 typed scalar |

## 4. 有意差异

- Policy 不能 import、指定 module/function 或遍历任意 Python object。
- Matcher 不调用或包装 Tool/LLM。
- 时间先后不生成 data lineage。
- Finding/Error/Decision 不携带完整 Event/content。
- 使用分项预算，不用单一迭代上限。

新增语义先扩展相邻 I01–I14 生产行为测试。作者格式见
[Policy 作者指南](../guides/policy-authoring.md)，执行合同见
[分析引擎参考](../reference/analysis-engine.md)。
