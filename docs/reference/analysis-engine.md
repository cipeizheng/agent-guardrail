# 分析引擎参考

> 适合谁：修改 MatchPlan、SnapshotMatcher、MatchMonitor、Finding 或预算的人。
> 解决什么：IR、执行顺序、输出身份、失败原子性和增量语义。
> 不包含什么：生产 YAML 教程和具体 Detector 算法。

## 1. 组件关系

```text
AuthorPolicy
    │ compile
    ▼
immutable MatchPlan ── capability linking ──► CompiledMatchPlan
    │
    ▼
SnapshotMatcher ──► AnalysisReport[Finding, AnalysisError]
    │
    ├─ snapshot / whole-pending
    └─ MatchMonitor：committed Finding identity 去重
```

MatchPlan 是 provider-neutral、action-free 的分析 IR。它不包含 handler、callback、module path、import 或
I/O 字段；SnapshotMatcher 不创建 Relation、Decision，也不执行 LLM/Tool。

## 2. MatchPlan 结构

一个 Plan 包含：

- `scopes`：`snapshot`、`pending` 或两者；
- `parameters`：可信调用方提供的严格标量；
- `limits`：整次分析的共享预算；
- `rules`：一个或多个 `MatchRulePlan`。

Rule 固定顺序：

```text
event binding domains / named cartesian product
  → ordered derive
  → ordered collection expansion
  → where condition
  → static Finding projection
```

Event binding 只允许独立 `message/tool_call/tool_result`，字段首段限定为
`id/sequence/kind/phase/origin/payload`，不能读取 metadata 或任意 Python 属性。

pending 分析中的 domain：

| domain | 可见 Event |
| --- | --- |
| `visible` | committed past + whole pending batch |
| `past` | committed past |
| `pending` | 当前完整 pending batch |

snapshot 分析中 `visible/past` 都看到完整 Trace，`pending` 为空。

## 3. 条件语义

MatchCondition 是封闭递归树：布尔、presence、严格比较、membership、contains、顺序、精确 Relation、
Predicate/Detector 和有界量词。

- 多个 Event 变量按有方向的命名笛卡尔积枚举，包括同一 Event 分配给多个变量；不同对象或先后必须显式
  写条件。
- collection 缺失或类型不适用产生空 domain；实际访问元素仍计预算。
- `forall` 空 domain 为 true，`exists` 为空为 false；`count` 至少声明一个上下界。
- `precedes/immediately_precedes/may_influence` 不创建来源边。
- `derived_from_direct/ancestor` 只查询 Trace 中已有的类型化 Relation。
- 未链接 capability 在 Rule 搜索前产生 `capability_error`，不会因空 domain 或短路退化为 no-match。

## 4. 分项成本

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

每次消费先同时检查 Rule 和全局额度，全部通过才递增。Rule 超限丢弃该 Rule 暂存 Finding，其他 Rule 可
继续；全局超限还会停止后续 Rule。超限变成脱敏 `resource_exhausted`，不能解释为无匹配。

## 5. Finding identity 与安全输出

Finding identity v1 对下列规范结构计算 SHA-256：

```text
policy_hash + rule_id + code
+ sorted subject_event_ids
+ sorted (binding_name, binding_key)
```

message、location、masked evidence 和 confidence 不参与身份。去重命名空间是
`(trace_id, finding.id)`；Event ID 只保证 Trace 内唯一。

binding key 只能散列稳定结构坐标，例如 Event ID、字段路径、collection index 或参数名；不得输入
Message、Tool 参数、Secret、PII 或 Detector 原文。低熵敏感值即使 hash 也可能被枚举。

Finding 只包含静态 Rule/code/message、subject Event ID、结构 binding、受限位置和脱敏 evidence。
location/evidence 引用必须属于本次 snapshot 的 subject 或 bound Event。

## 6. AnalysisReport

| scope | pending IDs | Finding 约束 |
| --- | --- | --- |
| `snapshot` | 空 | 所有引用属于 snapshot |
| `pending` | 非空子集 | 每条 Finding 至少一个 subject 属于 pending |

Report 校验 Event ID、Finding ID、Policy hash 和所有 Event 引用的一致性。它可以同时包含 findings 与
errors；调用方必须按显式失败动作处理 error，不能因已有 Finding 就忽略错误。

Schema 硬上限包括：每个 Finding 64 subject、128 binding、64 location、64 evidence；每个 Report
1,000 Finding、100 error。它们是输出边界，不替代搜索预算。

## 7. SnapshotMatcher

Matcher 每次调用深拷贝输入 Event tuple，创建独立 ledger 和 analysis-local capability cache，返回
`emission=all`。相同 Plan、Policy hash、输入和参数必须产生相同 Report。

cache key 包含 capability/version、规范输入哈希以及 trace/Event/phase/Rule/condition 上下文。cache hit
仍计 calls/input bytes；cache miss 在调度前预留 deadline，并受真实异步 timeout 控制。

Finding 投影前会过滤 past-only subject，因此历史匹配不消费 pending Finding/evidence 输出预算。

## 8. MatchMonitor

MatchMonitor 复用 SnapshotMatcher，但返回 `emission=new`：

| 入口 | 是否推进 seen identity |
| --- | --- |
| `analyze(committed Trace)` | 无 error 且状态预算允许时原子推进 |
| `analyze_pending(PendingTrace)` | 不推进；pending 仍是 tentative |

tentative pending 不能立即去重：被 block 的原始 Event 不会提交；若先记住 Finding，同一调用重试可能被
错误放行。Monitor 默认最多保存 100,000 个 identity，满额返回 `resource_exhausted`，不做静默 LRU。

当前状态仅在进程内，不持久化、不跨进程共享，也不参与生产 Enforcement Decision。

## 9. 修改要求

I01–I14 直接由生产 MatchPlan/Matcher/capability 行为测试覆盖。新增节点必须同时定义 Schema、静态类型、
求值顺序、成本维度、失败代码、脱敏投影以及相邻边界测试，不得引入第二解释器或自动 provenance。

作者格式见[Policy 作者指南](../guides/policy-authoring.md)，可信扩展见
[Capability 参考](capabilities.md)。
