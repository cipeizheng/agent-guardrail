# SnapshotMatcher 执行合同

> 状态：MatchPlan v1 的无状态 snapshot/whole-pending 执行器已实现并接入 v3 生产 Policy、Runtime 与
> Gateway。增量去重由 MatchMonitor 提供；可信 Predicate/Detector descriptor 编译与有界调用已实现。

## 1. 当前入口与边界

`core/matcher.py` 提供：

```python
matcher = SnapshotMatcher(plan, policy_version=3, policy_hash="...")
report = await matcher.analyze(trace, parameters={...})
pending_report = await matcher.analyze_pending(pending_trace, parameters={...})
```

每次调用对输入 Event 建立独立的深拷贝 tuple，创建新的 `MatchCostLedger`，返回 `emission=all` 的
AnalysisReport；Matcher 对象不保存 finding、成本或 dedupe 状态。因此同一 Plan、Policy hash、输入与
参数的重复调用必须得到完全相同的 Report。pending 入口返回 `scope=pending`，并只保留 subject 含当前
pending Event 的 Finding。

它只分析已有 Event，不创建 Relation、Violation、Decision，也不执行 LLM、Tool、网络、文件或其他 I/O。
当前生产 Enforcement 通过 `PendingTrace -> MatchPolicyAnalyzer -> SnapshotMatcher -> Decision` 使用
同一语义。

## 2. 确定性枚举

一条 Rule 按固定顺序执行：

```text
每个 event binding 的有序 domain
  → 所有命名 binding 的笛卡尔积
  → ordered split_lines derive
  → ordered collection binding expansion
  → where 条件
  → static Finding projection
```

多个同类型变量仍是有方向的命名变量。`m1`、`m2` 会枚举完整笛卡尔积，包括同一个 Event 分配给两个
变量；若规则要求二者不同或有先后，必须显式写 `m1 precedes m2` 等约束。Invariant 的 multipath 样例也
是由变量笛卡尔积加 `m1 -> m2` 得到唯一顺序，而不是解释器暗中把变量改成无序组合。

snapshot 中 `visible` 与 `past` 都看到完整 Event tuple，`pending` 是空 domain。whole-pending 中
`visible=past+pending`、`past=committed`、`pending=当前完整 batch`。跨调用 finding dedupe 由
[MatchMonitor](match-monitor.md) 提供，不由无状态 Matcher 猜测。

## 3. 已实现的节点语义

- typed Event domain，以及 phase/origin 过滤；
- 静态安全 Event envelope 路径：`id/sequence/kind/phase/origin/payload`；
- 有界 list/tuple collection 展开和严格 item type；缺失或非 collection 是空 domain；
- `split_lines` 纯派生及原字段内的字符区间；
- `all/any/not`、presence、严格比较、membership 和 string/array contains；
- `exists/forall/count` lexical 量词和外层 binding 闭包；空 `forall` 为 true，空 `exists` 为 false；
- `precedes/immediately_precedes/may_influence` 顺序查询；
- 只读取 `Event.relations` 的 direct/ancestor provenance 查询；
- typed trusted scalar parameter；未知、缺失或错误类型在 Rule 搜索前返回 `parameter_error`；
- matcher range 的脱敏 `FindingEvidence`、结构化 binding key 和稳定 Finding identity。
- 显式编译后的可信 Predicate/Detector、analysis-local cache、deadline 与脱敏 capability evidence。

缺失字段或不适用类型不是 Python 异常，也不能因 `not` 变成命中：这类比较产生 incomplete false，否定
后仍为 false。`present` 用于作者需要显式区分“缺失”和“存在但为 null”的场景。

`may_influence` 当前是保守的时间可达关系，与 `precedes` 同值；它绝不创建或冒充 `derived_from`。
`immediately_precedes` 按同一 Trace 的连续可信 sequence 判断。direct/ancestor 只接受已经通过
Canonical Trace 校验的类型化来源边。

## 4. 能力与失败语义

纯 MatchPlan 可以声明 Predicate/Detector capability，但不会自行解析代码。若直接交给 Matcher，包含
任一能力节点的 Rule 仍在枚举前产生固定、脱敏的 `capability_error`，即使 domain 为空或前置条件本可
短路；这是固定的未链接失败行为。部署方显式调用 `compile_match_plan_capabilities()` 后，Matcher 才按 Registry
descriptor 执行达到的节点。编译期检查名称、Predicate arity/静态类型、Detector encoding/type filter；
运行期检查动态类型、输入字节、调用数、deadline、Detection 数量/身份/span 和脱敏字段。

Rule 输出是原子的：若该 Rule 在后续赋值中超出单 Rule 预算，已经暂存的 Finding 全部丢弃，并返回一条
`resource_exhausted`；其他 Rule 可以继续。若触发分析全局预算，则当前 Rule 的暂存 Finding 丢弃并停止
后续 Rule。错误不包含输入值、Secret、PII 或 Detector 原文。

真正执行的工作会消费 MatchPlan 分项账本：typed candidate、完整 binding assignment、访问的 collection
item、派生 item/UTF-8 byte、量词迭代、实际条件节点、顺序/关系节点、传递边、Predicate/Detector 的
calls/input bytes/deadline 预留、Finding 与 evidence。
每次消费先同时检查 Rule 限额和全局限额，失败时不递增任一计数。

## 5. Finding 安全边界

Finding 只投影：

- 静态 Rule/code/message；
- subject Event ID；
- binding 名称、结构坐标 hash、可选 Event ID/位置；
- 明确请求的 matcher evidence 类型、区间和静态 mask。

原字段、collection item 和 parameter 值不会写入 Report，也不会进入 binding key 的公开字段。量词的
lexical binding 不能逃逸为 Finding binding；量词内部位置只有在其 Event 已由顶层 subject/binding 引用时
才能投影，避免 Report 引用 snapshot 外或未绑定 Event。

## 6. 尚未实现

跨请求持久 Monitor、Policy 热加载、更多 derive/quantifier 优化和更多默认 capability 尚未实现。
严格作者 YAML 的 declarative predicate 只作为编译期宏内联；YAML 始终不能绕过 descriptor compiler
指向 Python callable。
