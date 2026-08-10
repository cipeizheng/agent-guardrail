# ADR-0010：Invariant 对齐的 Policy/Monitor 与通用匹配模型

- 状态：Accepted
- 后续变更：ADR-0011 已完成 MatchPlan 生产硬切换，并替代本 ADR 保留 v2 Safe Profile 兼容轨道的
  迁移结论
- 日期：2026-08-10
- 替代范围：ADR-0009 将 anchor-centric `StructuredRulePlan` 作为长期通用表达式载体的结论；
  ADR-0007 完全排除顺序查询和 whole-pending 分析的结论
- 保留范围：ADR-0007/0008 的 Canonical Event、`PendingTrace`、批次原子性、来源信任与
  Policy/Enforcement 分层；ADR-0009 的严格 YAML、静态编译、有界解释器、Detector descriptor、
  失败安全和当前 v2 兼容合同
- 实现状态：目标架构；当前只固化兼容性合同，尚未交付通用 MatchPlan、Policy SDK 或 Monitor SDK

## 背景

ADR-0009 使用 C01–C10 证明了一个安全、可执行的 Gateway RulePlan 子集，但该样例集主要围绕单个
pending anchor、显式 provenance 和 Enforcement 副作用边界。它没有充分覆盖 Invariant Policy 的
通用分析能力：多 Event binding、派生值、集合展开、量词、snapshot 分析、pending batch 匹配、
增量 finding 去重和命中区间。

对同级 `../invariant` commit `2340fe2` 的源码与真实测试重新审计后，结论是：Invariant 的核心价值
不只来自 IPL 表面语法，更来自“在一个事件 snapshot 上寻找满足约束的变量赋值”的匹配模型。
mandatory anchor 适合 Gateway 当前事件检查，却不应成为通用 SDK 的唯一计算模型。

同时，Invariant 的一些实现选择不能直接成为本项目的安全合同：本地 Policy 可以链接 Python
module/function，`->` 由列表顺序自动构造，`Monitor.run/validated` 可以包装并执行操作，Violation
可以携带原始对象。这些能力与外部上传策略、精确 provenance、Core 无副作用和默认脱敏边界冲突。

因此，本项目对齐 Invariant 的**分析语义和作者能力**，不复制 IPL 语法、Python 链接器、远程服务
耦合或操作执行器。

## 决策

### 1. 通用模型是 snapshot matcher，不是单 anchor evaluator

长期 Core 增加一个不可变、可序列化的 MatchPlan IR。一个 MatchPlan 至少包含：

- `scope`：本次可见的 committed 与 pending Event snapshot；
- `bindings`：一个或多个带类型和来源域的 Event/value 变量；
- `where`：纯条件、显式关系、受控 Detector/predicate 和量词；
- `derive`：有界的标量/集合派生值；
- `subjects`：本次 finding 负责的 Event，至少一个必须来自 pending；
- `finding`：静态 code/message、脱敏 evidence 和有界命中位置。

MatchPlan 的求值结果是零个或多个结构化 `Finding`。匹配器不得因为存在一个“当前 Event”而要求所有
Detector 或关系都围绕它；多 Event binding 是核心能力，不是多个 anchor query 的偶然组合。

当前 `StructuredRulePlan(anchor, history, query, report)` 保持可执行，并定义为 **Gateway Safe
Profile v2**。后续兼容编译器应把它降解为“逐 pending cursor、只见 cursor 之前事件、cursor 作为
subject”的 MatchPlan；在兼容编译完成前保留现有解释器，不做双写求值。

### 2. Policy、Monitor 与 Enforcement 使用同一匹配语义

目标 API 分成三层：

```text
Policy.analyze(snapshot) -> AnalysisReport[Finding]
Monitor.analyze_pending(past, pending) -> AnalysisReport[new Finding]
Enforcement PolicyAnalyzer.analyze_pending(PendingTrace) -> Decision
```

- `Policy` 是无状态 snapshot 分析；相同输入产生相同 finding。
- `Monitor` 在相同 MatchPlan 上增加稳定 finding identity 和增量去重；它不执行 handler 或上游操作。
- Enforcement 的 `PolicyAnalyzer` 把当前 pending 相关 finding 映射为 `allow/log/block` Decision；
  副作用仍只由 `enforcement/` 或 Gateway 在 Decision 之后执行。

`Monitor.analyze_pending` 可以查看 `past_events + pending_events` 的完整不可变 snapshot，但每条返回的
finding 必须通过声明的 `subjects` 绑定至少一个 pending Event。只匹配 past Event 的 finding 不得重复
返回或阻断当前操作。Gateway 继续以整个 pending batch 为原子提交/阻断单位。

这不改变当前 Session 已实现的安全合同：在新 API 落地前，现有 Engine 仍返回 Decision，当前
RulePlan 仍使用 prefix history。

### 3. 对齐的 Invariant 能力

通用 MatchPlan 和安全 YAML 作者层必须以
[Invariant 兼容性基线](../invariant-policy-compatibility.md) 为验收 oracle，按阶段覆盖：

1. typed Event selection 与多个 Event binding；
2. 嵌套字段选择、ToolCall/ToolResult 模式和纯布尔组合；
3. 有界派生值、集合展开和局部变量；
4. `exists`、`count`、`forall` 及其外层 binding 闭包；
5. snapshot Policy、whole-pending Monitor 和稳定 finding 去重；
6. 显式 relation、顺序关系、Detector/predicate、policy parameter；
7. 脱敏 evidence 与可选的结构化命中位置。

“对齐”表示相邻 fixture 的输入和 finding oracle 等价，不要求支持 IPL 文本，也不要求内部 AST、Parser
或搜索算法相同。

### 4. 顺序、可能影响与精确来源必须分开

Invariant `->` 的真实实现是同一顶层列表中的“较早对象可流向较晚对象”；`~>` 是立即前驱。它们适合
表达 `get_website` 之后是否出现 `send_email` 之类的保守规则，但不能证明后者读取或派生自前者。

本项目因此提供三类不同语义：

| 语义 | 依据 | 可用于精确 provenance/taint |
| --- | --- | --- |
| `precedes` / `immediately_precedes` | 同一 Trace 的可信 sequence | 否 |
| `may_influence` | 明确的可见性/执行边界，或兼容 profile 中的保守顺序 | 否 |
| `derived_from` 及后续精确来源 Relation | 可信 Adapter/Enforcement 显式提交的类型化边 | 是 |

兼容 Invariant `->` 的规则必须编译为 `precedes` 或 `may_influence`，不得生成
`EventRelation(kind=derived_from)`，也不得让时间顺序提升 Event origin。只有真正掌握调用、结果、包含或
数据变换事实的宿主 instrumentation 才能提交对应的精确 Relation。

### 5. YAML、IR 与可信扩展是三个边界

目标架构不是“在 YAML 中写 Python”，而是：

```text
严格 YAML 作者格式 ─┐
当前 v2 Safe Profile ├─> schema/type check ─> immutable MatchPlan ─> bounded matcher
Python builder SDK ───┘                              ↑
                                      trusted registry predicates/detectors
```

- YAML 只能构造封闭 Schema；不能 import、声明 callback、引用 module path 或取得 I/O。
- Python builder SDK 用类型化对象构造同一个 MatchPlan，适合应用作者动态组装规则，但不绕过编译和预算。
- 可信宿主扩展是由部署者在进程启动时显式注册、随应用代码审查和发布的 Detector、纯 Predicate、
  Event Adapter 或 Relation Emitter。它不是终端用户上传的 Python，也不是 Policy 文件中的 import。
- 外部 Python Policy、动态 module loading、`eval`/`exec` 继续不受支持。

Predicate 必须声明输入/输出类型、纯度、deadline、输入字节/调用次数成本、错误码和脱敏策略。拥有 I/O
或副作用的检查只能作为受控 Detector，由 Engine 统一调度和计费，不能伪装成普通表达式函数。

### 6. 安全 YAML 对齐能力，而不是复刻任意语言表面

后续 YAML Schema 必须能自然表示兼容性 corpus 中的 rule，但不以 IPL 或 CEL 为语法基准。允许加入的
首批通用节点限于：

- typed `bindings` 与 collection binding；
- `all/any/not`、有限比较和存在性；
- `derive` 的白名单纯操作；
- `exists/count/forall`；
- `precedes/immediately_precedes/may_influence` 与类型化精确 Relation；
- descriptor 驱动的 Detector/Predicate；
- 显式 `subjects` 和结构化 `finding`。

每个节点必须先在兼容性 corpus 添加正常、违规、边界和相邻超限 fixture，再定义静态类型、成本账本和
failure action。YAML 可读格式和低层 MatchPlan 序列化可以不同，但必须编译为同一 IR，并通过同一 oracle。

### 7. 明确不对齐的 Invariant 能力

以下能力不属于 Guardrail Policy 的默认执行面：

- Policy source 中任意 Python import、module linking、函数或方法调用；
- `Monitor.run`、`validated`、wrapping handler 或其他直接执行应用副作用的 action；
- 用列表顺序伪造精确 data lineage；
- 远程 Policy 服务环境切换和客户端任意上传 executable policy；
- 无统一硬预算的开放搜索、函数调用或原始对象输出；
- 把完整 Secret、PII、Event payload 或未脱敏 Detector 输出放入 Finding/Decision/Audit。

可信宿主可以在自己的应用代码中执行任意业务逻辑，但那是应用权限，不会因此成为 YAML Policy 权限。

### 8. 兼容层与遗留处理

| 当前部分 | 决策 |
| --- | --- |
| v1 Registry Python Rule | 保留；逐步区分复杂 Rule 与可注册 Predicate/Detector |
| v2 Structured RulePlan | 保留为 Gateway Safe Profile；冻结无 corpus 支撑的横向扩张 |
| `GuardrailContext` per-anchor 视图 | 保留为 v1 Rule/v2 兼容层；新通用 SDK 不以它为主模型 |
| `GuardrailEngine` / `PolicyAnalyzer -> Decision` | 当前 Enforcement 主路径保留；未来消费 AnalysisReport，不承担通用 SDK 返回类型 |
| `PendingTrace.context_for` prefix | 保留给兼容 Rule；通用 Monitor 使用 whole snapshot + pending subject 约束 |
| Detector Registry/descriptor/cache/budget | 保留并提升为 MatchPlan 的受控扩展边界 |
| `EventRelation(derived_from)` | 保留精确含义；不得承接顺序兼容语义 |
| C01–C10 | 保留为 Gateway/Safe Profile 安全 corpus，不再代表通用 SDK 完整性 |

只有在引用审计证明新 MatchPlan、Monitor 和 Safe Profile 编译器已接管生产路径后，才可删除旧解释器或
per-anchor 兼容代码。迁移期间不得让相同 Policy 在两个执行器中同时产生重复 Decision。

## 结果

优点：

- 通用 SDK 的能力边界与 Invariant 的真实 Policy/Monitor 模型对齐，不被 Gateway anchor 限死。
- YAML、Python builder 与 Gateway Safe Profile 可以共享一个可审计 IR。
- 顺序策略仍然灵活，同时不污染精确 provenance。
- 扩展代码的信任归属从“规则语言能力”中独立出来。

代价：

- 需要新的 Finding/AnalysisReport、MatchPlan、matcher、Monitor 和兼容编译器；当前 v2 只是子集。
- whole-pending 与 per-anchor prefix 共存期间必须写清 API 和去重语义。
- 多 binding、量词和集合派生会扩大搜索空间，必须先做预算模型而不能只增加语法。

## 分阶段验收

1. 固化 Invariant 兼容性 corpus 与当前覆盖矩阵。
2. 定义 `Finding`、稳定 identity、`AnalysisReport` 与 MatchPlan Schema；不接 Gateway。
3. 实现无状态 Policy matcher 和增量 Monitor，并通过多 binding/量词/pending fixture。
4. 实现严格 YAML 作者格式和 v2 Safe Profile → MatchPlan 兼容编译器。
5. 通过受控 Registry 接入 Predicate/Detector，验证预算、timeout、脱敏和缓存。
6. 让 Enforcement `PolicyAnalyzer` 消费 AnalysisReport；批次原子性和副作用测试必须保持通过。
7. 迁移 Built-in Rule，完成引用审计后删除无职责的 per-anchor 遗留实现。

## 本 ADR 明确不做

- 本阶段不实现或复制 IPL/CEL Parser。
- 本阶段不改变现有 Gateway、Session、Decision 或 v2 Policy 的运行行为。
- 不把顺序查询改写成 `derived_from`，不声称自动获得真实数据 lineage。
- 不开放第三方 Python Policy、sandbox、跨请求 TraceStore 或远程 Core。
