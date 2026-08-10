# Invariant Policy/Monitor 兼容性基线

> 状态：I01–I14 已固化为严格、机器可读 fixture，并由 test-only trusted oracle 执行；
> Finding/AnalysisReport、identity v1、MatchPlan v1 Schema、分项成本账本、结构节点 SnapshotMatcher、
> 有界 MatchMonitor、严格 YAML/类型化 Python 作者编译器、可信 capability 和 v3 生产接入已实现。
> 架构决策：[ADR-0010](adr/0010-invariant-aligned-policy-monitor.md)与
> [ADR-0011](adr/0011-matchplan-production-cutover.md)。

## 1. 审计基线

参考对象是同级 checkout `../invariant` 的 commit `2340fe2`。2026-08-10 使用本地模式实际运行：

```bash
cd ../invariant
LOCAL_POLICY=1 uv run pytest -q \
  invariant/tests/analyzer/test_flow.py \
  invariant/tests/analyzer/test_monitor.py \
  invariant/tests/analyzer/test_quantifiers.py \
  invariant/tests/analyzer/test_derived_variables.py \
  invariant/tests/analyzer/test_ranges.py \
  invariant/tests/analyzer/test_guarding.py
```

结果为 63 passed、2 skipped；跳过项依赖可选的 Presidio/Transformers detector，不影响语言与 Monitor
语义。审计还阅读了 `policy.py`、`base_policy.py`、`monitor.py`、`runtime/input.py`、`runtime/rule.py`、
`runtime/evaluation.py`、`language/linking.py` 和相关 stdlib。

本基线要求本项目用自己的 Canonical Model、Schema、Matcher 和 Registry 得到等价的安全结果；不要求
复制 Invariant 源码、IPL 文本或异常类型。

机器可读输入位于 `tests/fixtures/invariant_compatibility/`，严格 Schema 与确定性 reference oracle
位于 `tests/invariant_compatibility_corpus.py`，回放测试位于
`tests/unit/test_invariant_compatibility_corpus.py`。reference oracle 只存在于测试，不是
SnapshotMatcher 的实现依赖。

## 2. 术语映射

| Invariant | 本项目目标语义 |
| --- | --- |
| `Policy.analyze(trace)` | 无状态 `Policy.analyze(snapshot) -> AnalysisReport` |
| `Monitor` / incremental Policy | 带稳定 finding identity 的增量 Monitor，只返回新 finding |
| `(x: EventType)` | typed Event binding |
| `(x: T) in collection` | 有界 collection binding |
| predicate / derived variable | 编译后的纯 Predicate / `derive` 节点 |
| `raise PolicyViolation(...)` | 结构化、默认脱敏的 Finding |
| `->` | `precedes` 或保守 `may_influence`，不是精确来源 |
| `~>` | `immediately_precedes` |
| ToolOutput | Canonical `tool_result` |
| Python detector/import | 可信 Registry descriptor；YAML 不能 import |

## 3. 兼容性能力矩阵

“当前”列描述当前 `agent-guardrail` 工作树；“目标”记录仍需扩张的边界。

| ID | 参考能力 | Invariant 实证 | 当前 | 目标 |
| --- | --- | --- | --- | --- |
| I01 | typed Event selection | `test_monitor.py::test_simple` | SnapshotMatcher 与生产 v3 已对齐 | 完整对齐 |
| I02 | 多 Event binding/cross product | `test_flow.py::test_multipath` | SnapshotMatcher 已对齐命名笛卡尔积与组合预算 | 完整对齐并有组合预算 |
| I03 | 嵌套字段与 Tool pattern | `test_flow.py::test_simple`、README examples | SnapshotMatcher 已对齐安全路径/collection 子集 | 对齐安全字段/对象/数组模式 |
| I04 | 派生变量与 collection binding | `test_derived_variables.py` | SnapshotMatcher 已支持有界 `split_lines` | 对齐白名单纯派生和有界展开 |
| I05 | 用户定义 predicate 组合 | `test_predicates.py` | 作者 YAML 已编译期验证并内联 declarative predicate | 对齐 declarative predicate；代码只来自可信 Registry |
| I06 | `count` / `forall` / closure | `test_quantifiers.py` | SnapshotMatcher 已对齐有界量词与外层闭包 | 对齐有界量词和外层 binding 捕获 |
| I07 | 先后与立即前驱 | `test_flow.py::TestFlowImmediatePredecessor` | SnapshotMatcher 已实现，且不写来源边 | 行为对齐为 `precedes` / `immediately_precedes` |
| I08 | 精确关系查询 | Invariant tool id link | SnapshotMatcher 与 v3 支持 direct/ancestor | 保留显式类型化 Relation；与 I07 分离 |
| I09 | stateless snapshot Policy | `test_flow.py::test_stateful_vs_stateless` | SnapshotMatcher 已对齐 | 对齐 |
| I10 | whole-pending analysis | `test_monitor.py::test_analyze_pending*` | SnapshotMatcher 已看完整 batch 并过滤 pending subject | 对齐 snapshot，并要求 finding subject 含 pending |
| I11 | incremental finding dedupe | `test_monitor.py::test_simple/objects` | MatchMonitor 已对齐 committed identity；tentative pending 不提前确认 | 对齐稳定 identity，不依赖对象地址 |
| I12 | Detector/host function | README prompt injection/RBAC/code examples | 显式 Registry compiler/executor 已接生产；未编译纯 Plan 返回 capability_error | 对齐受控 Registry；拒绝 Policy import |
| I13 | range/evidence 定位 | `test_ranges.py` | SnapshotMatcher 已支持 matcher string range/mask | 对齐可选、有界、脱敏的结构化位置 |
| I14 | Policy parameter | README RAG `username` | SnapshotMatcher 已支持可信 typed scalar 参数 | 对齐声明式只读参数 Schema |
| I15 | operation wrapper/handler | `monitor.py::run/validated` | Enforcement 独立 | 明确不对齐；由 Enforcement 保持副作用顺序 |

## 4. 最小相邻 fixture

以下 fixture 已经成为机器可读、可执行 oracle。它们覆盖命中、不命中、边界以及适用能力的相邻超限
变体；任何 YAML/MatchPlan 节点都不能只凭一个 happy path 加入 Schema。

### I01：typed binding

- 输入：user Message、assistant Message、ToolCall 各一条。
- 规则：绑定 assistant Message 且内容含 `blocked`。
- oracle：只为该 Message 产生一个 finding；ToolCall 不进入 Message 域。

### I02：多 Event binding

- 输入：两个 user Message 后跟一个 ToolCall。
- 规则：绑定 `m1`、`m2`、`call`，要求两条 Message 都在 call 之前且角色为 user。
- oracle：按变量赋值产生确定数量 finding；交换顺序或更改任一角色不命中；超过组合预算 fail-closed。

### I03：Tool 模式与嵌套集合

- 输入：`send_email.arguments.emails` 含两个对象。
- 规则：展开每封 mail，绑定 `outgoing_mail`，匹配 recipient 不在 allowlist。
- oracle：每个违规元素形成独立 match；缺字段、非数组和过长数组走确定边界语义。

### I04：派生值

- 输入：多行 Message。
- 规则：`lines = split_lines(content)`，再绑定包含指定 token 的 line。
- oracle：相同 token 出现两行得到两个 match；派生字符串和集合总大小计入预算。

### I05：predicate 组合

- 规则：`invalid_role(message)` 与 `invalid_pattern(message)` 组合，二者都是纯 declarative predicate。
- oracle：predicate 可复用、局部变量不泄漏、递归和环在编译期拒绝。

### I06：量词与闭包

- 输入：一个 `scroll_down` ToolCall 和若干后续 ToolResult。
- 规则：对与该 call 关联且包含 `django` 的 result 执行 `count(min=5)`。
- oracle：5 条命中，4 条不命中；量词可读取外层 `call`，不能越过关系/组合预算。

### I07：顺序不是来源

- 输入：`get_website` ToolResult 先于 `send_email` ToolCall，但没有来源边。
- 规则 A：`precedes(output, call)`；规则 B：`derived_from(output, call)`。
- oracle：A 命中，B 不命中；执行后 Trace 仍没有新增 `derived_from` Relation。

### I08：精确来源

- 输入：与 I07 相同，但由可信 Session 增加显式来源边。
- oracle：`derived_from` direct/ancestor 按边命中；伪造 metadata、时间戳或 client origin 不能命中。

### I09：stateless Policy

- 同一 snapshot 连续分析两次。
- oracle：两次 AnalysisReport 的 finding identity 和内容相同。

### I10：pending Monitor

- past 含一个匹配 Message；pending 含两个匹配 Message 和一个无关 Message。
- oracle：只返回 subject 位于 pending 的两个 finding；允许同一规则绑定整个 pending snapshot；past-only
  match 不返回。

### I11：增量去重

- Monitor 连续收到相同 snapshot，然后追加一个新违规 Event。
- oracle：第一次返回旧 finding，第二次为空，第三次只返回新增 finding；deep copy 输入不改变 identity。

### I12：可信 Detector/Predicate

- 同一个 declarative rule 分别选择注册和未注册 capability。
- oracle：注册 capability 按 descriptor、deadline 和 byte budget 执行；未注册/超限/timeout 走固定失败
  action；YAML 中 module path/import 在加载期拒绝。

### I13：命中位置和脱敏

- 输入：Message 和 Tool argument 各包含两处敏感片段。
- oracle：finding 只含 Event ID、字段路径和区间/掩码 evidence；不含完整字段、Secret 或原始 PII。

### I14：Policy parameter

- 规则声明只读 `principal: string`，并交给注册的 RBAC predicate。
- oracle：缺失、错误类型在分析前拒绝；Provider payload 不能覆盖 Session 注入的可信 principal。

## 5. 安全差异不是兼容缺口

以下差异是有意拒绝，不应通过“兼容 Invariant”重新引入：

- 任意 `import os`、自定义 module/function path 或原始 Python object traversal；
- `Monitor.run/validated` 直接调用或包装 Tool；
- 把所有更早 Event 写成真实 data lineage；
- 动态 Violation 携带完整 Event/content；
- 只用 `INVARIANT_MAX_ITERATIONS` 一项限制所有搜索、关系、Detector 和输出成本。

本项目需要分别记录 binding combinations、condition steps、collection items/bytes、relation nodes/hops、
Detector calls/bytes/time 和 finding/evidence 数量。任何账本超限都必须产生稳定、脱敏、可配置但默认
fail-closed 的系统 finding/Decision。

## 6. 实现顺序

1. 将 I01–I14 固化为 provider-neutral fixture schema，不依赖 Policy YAML 表面（已完成）。
2. 定义 Finding/AnalysisReport 与稳定 identity（已完成）。
3. 定义 MatchPlan IR、成本模型和结构节点 snapshot matcher（已完成）。
4. 实现 Monitor whole-pending + dedupe（已完成；tentative pending 使用 retry-safe 语义）。
5. 设计严格、可读 YAML/类型化 Python 作者模型并编译到 MatchPlan（已完成）。
6. 接入可信 Predicate/Detector Registry（已完成）。
7. 通过 v3 Policy、MatchPolicyAnalyzer 将 MatchPlan 硬切到 Runtime/Gateway，并删除旧执行轨（已完成）。

兼容性 fixture YAML 仍只是测试数据载体，不是 Policy 作者格式；作者格式见
[MatchPlan 可读策略作者格式](match-policy-authoring.md)。不得重新引入 `anchor/query` 专用模型来模拟
I02–I14。
