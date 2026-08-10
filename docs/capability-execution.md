# MatchPlan 可信能力编译与执行

> 状态：已接入 v3 Policy、MatchPolicyAnalyzer、Runtime 与 Gateway。
> 架构依据：[ADR-0010](adr/0010-invariant-aligned-policy-monitor.md)和
> [ADR-0011](adr/0011-matchplan-production-cutover.md)。

## 1. 两个边界

可序列化的 `MatchPlan` 只保存 capability 名称、有限 Value reference、输入 encoding 和 evidence
projection，不保存 Python callable、module path、import、callback 或 I/O 权限。加载 YAML 只产生纯
`MatchPlan`；它不会自动找到或执行进程中的代码。

部署所有者在应用启动代码中显式构造 `PredicateRegistry` / `DetectorRegistry`，注册经过代码审查的实现
及 descriptor，再调用：

```python
compiled = compile_match_plan_capabilities(
    plan,
    predicates=predicate_registry,
    detectors=detector_registry,
)
matcher = SnapshotMatcher(
    compiled,
    policy_version=3,
    policy_hash="...",
)
```

`CompiledMatchPlan` 是部署进程内对象，可以持有可信实现，不能序列化回 Policy。未经过这一步的纯
`MatchPlan` 的未链接失败行为是：只要 Rule 含 capability 节点，该 Rule 就在枚举前返回脱敏
`capability_error`。

## 2. 编译期合同

`compile_match_plan_capabilities()` 在分析任何 Event 前原子验证全部引用：

- Predicate/Detector 必须已注册并显式发布 descriptor；
- 实现的 name/version 必须有效，descriptor name 必须与实现一致；
- Predicate 参数个数必须精确一致；静态可知的 literal、parameter、Event envelope 和 collection item
  类型必须兼容；动态 payload 路径在运行时再次检查；
- Predicate 固定为纯、布尔输出，并声明参数类型、单次输入字节上限和 deadline；
- Detector input encoding 与 `types_any` 必须属于 descriptor 发布的有限集合，并声明单次输入字节、
  deadline 与最大 Detection 数；
- descriptor 显式携带固定的失败类别和 evidence policy：Predicate 只能投影 Policy 静态 mask，Detector
  只能投影经过输出合同检查的 masked Detection 字段；
- 未注册、未发布或不兼容 capability 使整个编译失败，不产生部分可执行 Plan。

YAML 不能声明 descriptor、实现位置或 import。可信 Python 扩展的授权主体是部署应用，不是策略作者。

## 3. 有界执行

Matcher 串行、确定性地执行达到的 capability 条件，不并发调度。每次逻辑调用都会计入
`predicate_calls`/`detector_calls` 和对应 UTF-8 输入字节；cache miss 在调用前按 descriptor deadline
预留 `predicate_time_ms`/`detector_time_ms`，并使用真实异步 timeout。cache hit 仍计调用和输入字节，
但不重复预留执行时间。

缓存只存在于一次 `analyze`/`analyze_pending` 内。key 包含 capability/version、规范化输入哈希和
trace/Event/phase/Rule/condition 上下文；不会跨请求、跨 Policy 或跨 Event 身份复用含上下文的事实。

Predicate 只收到规范化 JSON 参数和 payload-free `PredicateContext`。Event 参数会转换为不含 metadata
和 Relation 的安全 envelope。Detector 只收到 `text` 或确定性 canonical JSON 字符串及最小
`DetectionContext`。缺失值或运行时类型不匹配是 incomplete false，不调用 capability。

## 4. 失败与 evidence

- 超过 descriptor 或 MatchPlan 字节/调用/时间预算：`resource_exhausted`；
- Detector deadline：`detector_timeout`，`retryable=true`；
- Predicate deadline：`capability_error`，`retryable=true`；
- 实现异常、非布尔 Predicate 结果、Detector 身份/type/span/数量/脱敏字段违反 descriptor：
  `capability_error`。

同一 Detector 条件聚合的可投影 evidence 还有 64 项硬上限；超过时返回 `resource_exhausted`，不静默
截断也不让 Finding Schema 失败退化为 `internal_error`。

错误只包含稳定类别、Rule ID 和 capability 名，不包含输入、异常文本或 Detector 原文。一条 Rule 的
能力失败会丢弃该 Rule 已暂存的全部 Finding；其他 Rule 继续，分析全局预算耗尽除外。

Predicate evidence 只包含 condition ID、capability、可选结构位置和 Policy 静态 mask。Detector evidence
只接受受信 descriptor 约束后的 type、capability、位置、`masked_evidence`、fingerprint 和 confidence；
原始输入及 Detector `path` 不进入 Finding。文本 span 可映射回输入字段，canonical JSON span 不冒充
原 Event 字符位置。

## 5. 已验证与剩余工作

I12 fixture 覆盖注册 Predicate hit/miss、未注册拒绝、Policy import 拒绝、Detector evidence、timeout
和相邻字节超限。生产测试继续覆盖 capability 编译、Finding 到 Decision 的 evidence 投影、错误动作和
Secret/PII 不泄漏。

尚未实现更多默认 Predicate、Prompt Injection/URL/危险命令 Detector，以及跨请求 capability cache；
后者必须先定义租户、Policy version、Event identity 和失效边界，不能直接扩张当前 analysis-local cache。
