# MatchPlan IR 与分项成本账本

> 状态：不可变 MatchPlan Schema、静态引用校验、两级成本限制、分析局部账本和结构节点 snapshot
> Matcher、有界增量 MatchMonitor、严格 YAML/类型化 Python 作者编译器，以及显式可信
> Predicate/Detector descriptor 编译、有界执行和 v3 Gateway/Runtime 接入均已实现。
> 架构依据：[ADR-0010](adr/0010-invariant-aligned-policy-monitor.md)和
> [ADR-0011](adr/0011-matchplan-production-cutover.md)。

## 1. 定位

`src/agent_guardrail/core/match_plan.py` 是当前通用 Policy/Monitor 的低层、provider-neutral IR。它描述
“在一个可见 Event snapshot 上枚举变量并检查约束”，不要求 mandatory anchor，也不是给最终用户直接
书写的 YAML 格式。

```text
strict v3 YAML / 独立 MatchPlan 作者 YAML / typed Python AuthorPolicy
                         │
                         ▼
                 immutable MatchPlan v1
                         │ capability linking
                         ▼
                 bounded SnapshotMatcher
                         │
                         ▼
                 AnalysisReport[Finding]
```

MatchPlan 没有 `action`、handler、callback、module path、import 或 I/O 字段。独立的
`load_match_plan_yaml` 可以从封闭作者 Schema 构造纯分析 Plan；生产 `load_policy_yaml` 还保存 action、
failure mapping 和规范化 Policy hash。

## 2. Schema 结构

一个 `MatchPlan` 包含：

- `scopes`：允许 `snapshot`、`pending` 或两者；同一 IR 可以被无状态 Policy 和增量 Monitor 复用；
- `parameters`：由分析调用方可信注入的严格标量参数，不读取 Provider payload；
- `limits`：整次分析共享的有效硬预算；
- `rules`：一个或多个无 anchor 的 `MatchRulePlan`。

每条 Rule 的逻辑求值顺序被固定为：

```text
event_bindings cross product
  → ordered derive
  → ordered collection_bindings expansion
  → where condition
  → static finding projection
```

`derive` 只能引用 Event binding 和更早的 derivation；collection binding 可以引用 Event、全部已完成的
derivation 和更早的 collection binding。Schema 在构造时拒绝未知引用、forward derivation、变量重名、
量词 shadowing、超深条件树和错误 evidence source。

### 2.1 Event 与 collection binding

`EventBinding` 当前只允许独立 `message/tool_call/tool_result`，避免把聚合兼容 Event 带入长期 IR。每个
binding 有一个明确域：

| domain | pending 分析 | snapshot 分析 |
| --- | --- | --- |
| `visible` | past + pending | 全部 Event |
| `past` | committed past | 全部 Event 都视为 past |
| `pending` | 仅当前 pending batch | 空集合 |

`phases/origins` 是额外 typed filter。字段读取使用静态 `str | int` 路径；Event binding 的首段只能是
`id/sequence/kind/phase/origin/payload`，不能读取 metadata、任意 Python 属性或 Provider 对象。

`CollectionBinding` 声明 collection source 和 item type。缺失字段或非 collection 值在 Matcher 中
产生空 domain；真正遍历的元素数仍计入 `collection_items`，相邻超限产生资源错误而不是无匹配。

### 2.2 derive、条件与量词

当前 corpus 支撑的第一个 derivation 只有 `split_lines`。增加新的纯操作前必须先补 I01–I14 相邻
fixture、类型规则、输出字节成本和失败语义。

`MatchCondition` 是封闭的递归树：

- `all/any/not`；
- `equals/not_equals/in/not_in/contains/not_contains`；
- 显式字段存在性；
- `precedes/immediately_precedes/may_influence`；
- `derived_from_direct/derived_from_ancestor`；
- 注册 Predicate/Detector 调用；
- 具有 lexical local binding 的 `exists/forall/count`。

顺序运算符只读可信 sequence，不创建 Relation；`may_influence` 也不等于 lineage。只有后两种
`derived_from` 运算符读取可信 Enforcement/Adapter 已提交的类型化来源边。

`forall` 的空 domain 后续固定为 vacuous true；`exists` 为空时 false；`count` 必须声明 minimum、maximum
或两者。Matcher 使用确定性短路，并对实际访问的节点和 domain item 消费 condition/quantifier 预算。

### 2.3 capability 与 Finding projection

`PredicateCondition` 和 `DetectorCondition` 只能保存 Registry capability 名称和有限 Value reference，
不能保存 Python callable。纯 Schema 不解析 Registry；显式 `compile_match_plan_capabilities()` 必须在 Plan
激活前把全部名称绑定到部署方发布的 descriptor 和实现，任一缺失或不兼容都会原子拒绝。

YAML 作者层的可复用 declarative predicate 不作为 MatchPlan 内的可调用代码存在：当前编译器检查参数、
引用、递归和环，再把它内联为条件树。可信宿主 Predicate 则保留为 Registry capability。

`FindingTemplate` 的 code/message 是静态文本。subject 必须是顶层 Event binding；每个顶层 Event/collection
binding 都必须投影为脱敏 `FindingBinding`，避免同一 Event 内不同 collection match 得到相同 identity。
Plan 还可以显式投影 parameter/derived coordinate，但不得把它们的原值写入 Finding。

comparison、Predicate 和 Detector 可以声明 Rule 内唯一的结果 ID；`EvidenceProjection` 只能引用相同
来源类型的已声明 ID。静态 mask 可以来自 Policy，但 Event/Detector 原值的脱敏仍由 Matcher 和
capability descriptor 负责。

## 3. 分项成本模型

成本不是费用，而是一次分析中的工作量。`MatchLimits` 为整次分析共享上限；每条 Rule 的
`MatchLimitOverrides` 只能降低某一维度，不能提高全局额度。

| 维度 | 默认全局上限 | 实现硬上限 | 计费对象 |
| --- | ---: | ---: | --- |
| `candidate_events` | 10,000 | 1,000,000 | typed domain 扫描出的候选 Event |
| `binding_combinations` | 8,192 | 1,000,000 | 完整顶层 binding 赋值 |
| `collection_items` | 2,048 | 100,000 | collection binding 展开的元素 |
| `derived_items` | 2,048 | 100,000 | derive 产生的集合元素 |
| `derived_bytes` | 131,072 | 4,194,304 | derive 产生的 UTF-8/Canonical JSON 字节 |
| `quantifier_iterations` | 8,192 | 1,000,000 | 量词访问的 domain item |
| `condition_steps` | 16,384 | 2,000,000 | 实际求值的条件节点 |
| `relation_nodes` | 4,096 | 1,000,000 | Relation/顺序查询访问的节点或边 |
| `relation_hops` | 64 | 1,024 | 分析中传递关系实际访问的来源边 |
| `predicate_calls` | 256 | 100,000 | 已注册纯 Predicate 调用 |
| `predicate_input_bytes` | 262,144 | 8,388,608 | Predicate canonical JSON 参数总字节 |
| `predicate_time_ms` | 5,000 | 60,000 | 调用前按 Predicate deadline 预留的总时间 |
| `detector_calls` | 32 | 1,024 | Detector 调用 |
| `detector_input_bytes` | 262,144 | 8,388,608 | Detector 编码输入总字节 |
| `detector_time_ms` | 5,000 | 60,000 | 调用前按 descriptor deadline 预留的总时间 |
| `findings` | 1,000 | 1,000 | 生成的 Finding |
| `evidence` | 512 | 8,192 | 投影的 evidence/location 项 |

`predicate_time_ms`/`detector_time_ms` 不依赖不稳定的事后计时决定是否允许：Matcher 调度 cache miss
前按 descriptor deadline 预留预算，每次真实调用仍有异步 timeout。cache hit 仍计 calls/input bytes，
但不重复预留执行时间。

## 4. 两级原子账本

`MatchCostLedger` 每次 `Policy.analyze` 或 `Monitor.analyze_pending` 新建一次，不跨请求共享。每个 Rule
消费一个维度时，账本先同时检查：

1. 该 Rule 的有效上限；
2. 整次分析的共享上限。

两者都通过后才同时递增；任一失败时两个计数都保持不变。这样既能阻止一条 Rule 产生笛卡尔积，也能
阻止许多小 Rule 合计耗尽进程资源。

超限抛出不含输入原文的 `MatchBudgetExceeded`，只公开 dimension、limit、current、requested 和可选
rule ID。SnapshotMatcher 将其转换为 `AnalysisError(code=resource_exhausted)`；未来 Enforcement 再按
Policy failure action 决定 fail-closed，不能把超限当成“没有匹配”。

`snapshot()` 返回不可变 `MatchCostSnapshot`，用于测试、指标和安全诊断；当前没有把它加入
`AnalysisReport` 公共 Schema。

## 5. I01–I14 覆盖与生产边界

Schema 测试已经构造全部上述 Plan。`core/matcher.py` 现在实际执行 I01 typed binding、I02 命名笛卡尔
积、I03 collection、I04 `split_lines`、I06 量词、I07 顺序、I08 精确关系、I09 stateless determinism、
I10 whole-pending、I13 matcher range 和 I14 typed parameter；`core/monitor.py` 执行 I11 的稳定 identity
去重，`core/capabilities.py` 与 Matcher 执行 I12 的可信 Predicate/Detector。完整合同见
[SnapshotMatcher 执行合同](snapshot-matcher.md)、[可信能力执行合同](capability-execution.md)与
[MatchMonitor 增量执行合同](match-monitor.md)。

MatchPlan 已是生产 Enforcement 的唯一策略 IR，`MatchPolicyAnalyzer` 负责 Finding/Error 到 Decision
的投影。`MatchMonitor` 仍只是进程内 committed identity 去重；跨请求持久化、Policy 热加载和更多
capability/derive 节点属于后续规划。
