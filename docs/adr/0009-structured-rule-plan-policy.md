# ADR-0009：Structured RulePlan YAML Policy

- 状态：Superseded（由 ADR-0010 取代长期模型，由 ADR-0011 删除生产兼容轨道）
- 日期：2026-08-10
- 补充范围：ADR-0007 的双轨 Policy 决策；不改变其 `PendingTrace`、显式 Relation、增量可见性与
  Enforcement 边界

## 背景

ADR-0007 要求在 Canonical Event/Analyzer 稳定后，用真实样例评估受限表达式策略。C01–C10 corpus、
CEL 最小 spike 与同级 Invariant Interpreter 审计显示：基础 selector 和有限计数不需要通用语言；而
provenance、pending prefix、Detector 调度和资源预算必须由 Guardrail Core 显式控制。现有 Invariant
执行链包含 import/link、任意函数调用、自动顺序 dataflow 和 whole-pending 输入，不能安全复用。

## 决策

### 1. v2 选择 Structured RulePlan

新增 `version: 2` Policy：

```yaml
version: 2
engine: {}
rules: []
expressions: []
```

`rules` 继续只选择 Registry 中的可信 Python Rule；`expressions` 是严格 YAML 序列化的
Structured RulePlan。二者分列，不能用 expression type 混入 Python Rule 轨道，也不能从 YAML 指定
module/class/function path。

v1 的 schema、hash 语义和可信 Rule 行为保持不变。v2 不会降级按 v1 解析；一个 v2 Policy 必须在
所有 Python Rule 与 RulePlan 都完成校验、编译后原子激活。

### 2. 编译器与执行器是受限查询模型

Loader 将严格 YAML 解析为 Pydantic Schema，再编译为不可变 RulePlan。编译期必须验证：

- Rule/Binding/Check 标识符及唯一性；独立 Event kind 与 phase 的兼容性；
- 固定的 Event envelope/allowed payload path；没有 JSONPath、数组索引、通配符、反射或方法访问；
- 有限的 `all`、`any`、`not`、`has`、比较、history binding、direct/ancestor Relation 和 threshold；
- 只引用已声明 check、binding、RelationKind 和具备 Policy descriptor 的 Detector；
- 静态报告、检测 evidence 引用与 Policy hard cap。

PlanExecutor 每次只接受一个 `GuardrailContext`：anchor 是当前 pending Event，history 是 committed
Trace 加该 anchor 前的 pending prefix。Relation 只读取类型化 `Event.relations`；sequence、timestamp
和数组位置不得推导 flow。它不执行 Python、I/O 或 Provider 协议逻辑。

### 3. Detector 是 descriptor 驱动的脱敏事实

表达式只能选择 Registry 公布的 `DetectorPolicyDescriptor`，并以固定 `canonical_json` 编码读取明确
列出的 anchor 字段。Policy 不传递任意 detector 参数，不能定义 callback，也不能读取 Detector 原文。
只有 matched、masked `Detection` 才能由静态 report 引用为 evidence。

### 4. 预算与失败安全

EngineConfig 为 history candidates、binding combinations、condition steps、Relation nodes、Detector
调用/输入字节、匹配事件和 evidence 声明 hard cap；Policy 只能请求不超过 cap 的更低限制。任何超限、
内部解释器错误或 Detector timeout 都进入现有 Engine 的 system Violation/failure action，不能变成
allow，也不能泄露原始 payload。`max_violations` 继续只截断报告，不停止 Plan 求值。

### 5. 初版范围与非目标

初版覆盖 C01–C10 所需的独立 Message/ToolCall/ToolResult selector、origin、有限 history、显式
direct/ancestor Relation、缺失字段、Detector type filter、threshold 与资源错误。复杂算法、开放式
量化、正则/算术/字符串计算、动态 Violation、CEL、Invariant IPL、用户函数、import 和跨请求
TraceStore 不在范围内，仍须使用可信 Python Rule 或后续 ADR。

## 结果

优点：安全语义、budget 和 evidence 归属保留在审计得到的 YAML/Plan 中；v1 Python Rule 保持兼容；
不会把核心 provenance/Detector 逻辑隐藏在 CEL host callback。

代价：RulePlan 只能表达有界结构化查询；每次扩张节点、字段或 Relation 语义都需要 Schema、成本和
兼容性审计，不能把它演变成 YAML 形式的 Python。
