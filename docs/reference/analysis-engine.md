# 规则分析引擎参考

> 本文说明规则检查计划如何执行、如何生成命中结果和分析报告，以及预算和失败如何影响结果。适合修改相关代码或进行安全 review 的开发者阅读。
> 相关参考：[规则编写指南](../guides/policy-authoring.md)、[检测能力参考](capabilities.md)。

本文中的 `Event` 是一次消息、模型调用或工具操作的记录，`binding` 是规则变量与事件的绑定，`domain` 是变量可以搜索的事件范围，`collection` 是规则展开的有限数组。它们是源码中的固定类型名，下面同时给出中文含义。

## 1. 组件关系

```text
AuthorPolicy（用于编写规则的结构）
  → 编译为 MatchPlan（不可变的检查计划）
  → 连接部署中注册的检测能力
  → CompiledMatchPlan（检查计划及其实际检测能力）
  → SnapshotMatcher（根据计划检查一组事件）
  → AnalysisReport（本次检查的分析报告）
      ├─ findings：规则命中项
      └─ errors：分析错误
```

这些对象的职责如下：

| 代码对象 | 作用 |
| --- | --- |
| `MatchPlan` | 编译后的规则检查计划，只描述检查方式，不描述副作用 |
| `CompiledMatchPlan` | `MatchPlan` 与部署中实际注册的条件判断和检测器连接后的运行对象 |
| `SnapshotMatcher` | 在一份事件快照上执行计划，生成规则命中项和分析错误 |
| `Finding` | 一条规则命中结果，包含规则编号、事件范围和脱敏证据 |
| `AnalysisReport` | 汇总本次检查的命中结果和错误 |
| `MatchPolicyAnalyzer` | 在上层把报告转换为 `Decision` |

`MatchPlan` 是与模型服务无关、也不包含动作的分析中间表示。它不包含 handler、callback、module path、import 或 I/O 字段；`SnapshotMatcher` 不创建 Relation、Decision，也不执行模型或工具。

## 2. 检查计划的结构

一个 `MatchPlan` 包含：

- `scopes`：`snapshot`、`pending` 或两者；
- `parameters`：可信调用方提供的严格标量；
- `limits`：整次分析的共享预算；
- `rules`：一个或多个 `MatchRulePlan`。

每条规则按以下顺序执行：

```text
事件绑定范围 / 命名组合
  → 有序派生（derive）
  → 有序集合展开（collection）
  → 条件判断（where）
  → 静态命中结果（Finding）
```

Event binding 允许 `message/model_call/tool_call_proposal/tool_call/tool_result` 五类 Policy 输入 Event；Enforcement 生成的 `guardrail_decision` 记录属于系统输出。字段首段限定为 `id/sequence/kind/origin/payload/security_facts`，`security_facts` 首段投影为 Detector fact 的 JSON 字典（`EventSecurityFacts.model_dump(mode="json")`），后续路径段可继续访问其结构化内容。

pending 分析中的 domain：

| domain | 可见 Event |
| --- | --- |
| `visible` | 已提交历史 + 本次完整待提交批次 |
| `past` | 已提交历史 |
| `pending` | 本次完整待提交批次 |

snapshot 分析中 `visible/past` 都看到完整 Trace，`pending` 为空。

## 3. 条件的执行语义

`MatchCondition` 是封闭的递归条件树，包含布尔组合、字段存在性、严格比较、成员判断、文本包含、先后顺序、精确 Relation、Predicate/Detector 和有界量词。

- 多个 Event 变量按有方向的命名笛卡尔积枚举，包括同一 Event 分配给多个变量；不同对象或先后必须显式写条件。
- collection 缺失或类型不适用产生空 domain；实际访问元素仍计预算。
- `forall` 空 domain 为 true，`exists` 为空为 false；`count` 至少声明一个上下界。
- `precedes/immediately_precedes` 只比较 sequence，不创建 Relation。
- `linked_by` 查询显式 `influenced_by` 或 `derived_from` 关系路径；`derived_from_direct/ancestor` 只查询显式 `derived_from` Relation。
- 未链接 capability 在 Rule 搜索前产生 `capability_error`，不会因空 domain 或短路退化为 no-match。

## 4. 资源预算

`MatchLimits` 是分析共享上限；Rule override 只能降低。主要默认值：

| 维度 | 默认上限 | 计费对象 |
| --- | ---: | --- |
| `candidate_events` | 10,000 | typed domain 候选 Event |
| `binding_combinations` | 8,192 | 完整顶层 binding 赋值 |
| `collection_items` | 2,048 | 展开的 collection 元素 |
| `derived_items` | 2,048 | derive 集合元素 |
| `derived_bytes` | 131,072 | derive UTF-8/Canonical JSON 字节 |
| `quantifier_iterations` | 8,192 | 量词访问元素 |
| `condition_steps` | 16,384 | 实际求值节点 |
| `relation_nodes` | 4,096 | 顺序/Relation 查询节点或边 |
| `relation_hops` | 64 | 传递来源边 |
| `predicate_calls` | 256 | Predicate 调用 |
| `predicate_input_bytes` | 262,144 | Predicate 输入总字节 |
| `predicate_time_ms` | 5,000 | cache miss deadline 预留 |
| `detector_calls` | 32 | Detector 调用 |
| `detector_input_bytes` | 262,144 | Detector 输入总字节 |
| `detector_time_ms` | 5,000 | cache miss deadline 预留 |
| `findings` | 1,000 | 生成 Finding |
| `evidence` | 512 | evidence/location 项 |

每次消费先同时检查 Rule 和全局额度，全部通过才递增。Rule 超限丢弃该 Rule 暂存 Finding，其他 Rule 可继续；全局超限还会停止后续 Rule。超限变成脱敏 `resource_exhausted`，不能解释为无匹配。

## 5. 命中结果的身份与安全输出

命中结果的 identity v1 对下列规范结构计算 SHA-256。它用于在同一任务中稳定识别同一条命中结果：

```text
policy_hash + rule_id + code
+ sorted subject_event_ids
+ sorted (binding_name, binding_key)
```

message、location、masked evidence 和 confidence 不参与身份。Finding ID 的命名空间是 `(trace_id, finding.id)`；Event ID 只保证 Trace 内唯一。

绑定键（binding key）只能散列稳定的结构坐标，例如 Event ID、字段路径、collection index 或参数名；不得输入 Message、Tool 参数、Secret、PII 或 Detector 原文。低熵敏感值即使 hash 也可能被枚举。

Finding 只包含静态 Rule/code/message、subject Event ID、结构 binding、受限位置和脱敏 evidence。location/evidence 引用必须属于本次 snapshot 的 subject 或 bound Event。

## 6. 分析报告

| scope | pending IDs | Finding 约束 |
| --- | --- | --- |
| `snapshot` | 空 | 所有引用属于 snapshot |
| `pending` | 非空子集 | 每条 Finding 至少一个 subject 属于 pending |

`AnalysisReport` 校验 Event ID、Finding ID、Policy hash 和所有事件引用的一致性。它可以同时包含命中结果和错误；调用方必须按显式失败动作处理错误，不能因为已经有命中结果就忽略错误。

Schema 硬上限包括：每个 Finding 64 subject、128 binding、64 location、64 evidence；每个 Report 1,000 Finding、100 error。它们是输出边界，不替代搜索预算。

## 7. 快照匹配器

`SnapshotMatcher` 每次调用都会复制输入事件，创建本次分析独立的预算记录和能力缓存，并返回全部匹配结果。相同的计划、Policy hash、输入和参数必须产生相同的报告。

cache key 包含 capability/version、规范输入哈希以及 trace/Event/Rule/condition 上下文。cache hit 仍计 calls/input bytes；cache miss 在调度前预留 deadline，并受真实异步 timeout 控制。

Finding 投影前会过滤 past-only subject，因此历史匹配不消费 pending Finding/evidence 输出预算。

## 8. 修改要求

I01–I14 直接由生产 MatchPlan/Matcher/capability 行为测试覆盖。新增节点必须同时定义 Schema、静态类型、求值顺序、成本维度、失败代码、脱敏投影以及相邻边界测试，不得引入第二解释器或自动 provenance。

规则格式见[规则编写指南](../guides/policy-authoring.md)，可信扩展见[检测能力参考](capabilities.md)。
