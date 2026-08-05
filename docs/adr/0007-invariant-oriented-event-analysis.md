# ADR-0007：面向 Invariant 的事件分析架构

- 状态：Accepted
- 日期：2026-08-06
- 替代范围：ADR-0001 中“YAML 是唯一外部策略形式、动态表达式继续暂缓”的排他性结论；
  ADR-0004 中以单个 `GuardrailContext` 作为 Runtime 主评估边界的结论；ADR-0006“明确不做”中的
  独立 Message、候选事件批次和受限表达式策略
- 保留范围：ADR-0001 的受信任 Python Rule、显式 Registry 和禁止动态 Python；ADR-0004 的
  Runtime/Enforcement 职责分离与副作用顺序；ADR-0006 的类型化 Relation、显式来源和图不变量

## 背景

现有实现已经可以围绕一个候选 Event 查询已提交 Trace，并通过可信 `EventRelation` 表达来源。
这足以实现少量内置 Python Rule，但不能自然表达以下需求：

- 一次模型请求或响应包含多个 Message、ToolCall 和 Content 节点，需要作为一个候选批次原子判断。
- Policy 需要量化多个事件并判断它们之间的关系，而不只检查一个边界 payload。
- Gateway 或 Framework Adapter 需要区分客户端声称的历史、服务端实际观察的事件和由可信事件精确
  派生的事件。
- 非开发者最终需要通过文本策略组合事件查询和 Detector，而不是每增加一个组合条件就发布新的
  Python Rule。

本项目因此转向 Invariant 风格的事件分析与 Enforcement Gateway 定位。这里的“Invariant 风格”
指一等事件、关系查询、`past_events + pending_events` 增量分析和 Policy/Enforcement 分层，不表示
复制其顺序 dataflow、远程服务耦合或具体策略语言实现。

## 决策

### 1. Policy Analyzer 取代单事件 Evaluator 成为主边界

Core/Runtime 的主协议改为：

```python
class PolicyAnalyzer(Protocol):
    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
```

`PendingTrace` 至少包含：

- 一个不可在分析期间变化的已提交 Trace snapshot。
- 一个非空、顺序连续的 pending Event 批次。
- 该批次的 primary Event ID。
- 受信任的 task/tenant attributes。

Decision 必须绑定整个 pending Event ID 集合和 primary Event；Violation 必须指出它涉及的 pending
Event。分析结果不能因为只匹配 past Event 而重复阻断当前操作。

现有 Python Rule 暂时继续接收 `GuardrailContext(event, trace)`。Engine 为批次中的每个候选 Event
建立只包含 committed past 和更早 pending Event 的只读 Rule 视图，并在一次
`analyze_pending` 中共享 Detector Cache。`GuardrailContext` 因而降为 Python Rule 的事件视图，
不再是 Runtime 的长期主边界。

### 2. Candidate Batch 由 Session 验证后变成 Pending Trace

运行链改为：

```text
Provider / Framework payload
  → Adapter 生成 CandidateEventBatch
  → EnforcementSession 分配 ID/sequence/time 并验证信任与关系
  → PendingTrace(past snapshot, pending events)
  → PolicyAnalyzer.analyze_pending
  → allow/log: 原子提交整个 pending batch
  → block: 不提交原始 pending events，只提交一个脱敏 Decision Event
```

Adapter 不能直接提交一个自称可信的完整 Trace。Candidate 只能通过封闭 Schema 引用已提交 Event
或同批次中更早的 Candidate；Session 解析引用并再次执行 Trace 图不变量。

一个批次必须属于同一 Trace 和同一个 Enforcement phase。批次大小、合并后的 Trace 大小和
Relation 数量必须有界。Session 锁覆盖“构造 snapshot → 分析 → 原子提交”，但不得覆盖 LLM、Tool
或其他受保护副作用。

### 3. Event 信任来源是一等字段

Event 增加封闭的来源枚举：

- `client_asserted`：当前请求携带的历史、身份声明或其他未经服务端历史证明的数据。
- `observed`：Enforcement Point 实际接收或产生的数据；observed 只证明经过该边界，不证明内容
  真实或安全。
- `derived`：可信 Adapter/Session 能从同一 Trace 中已观察事件精确派生的数据。

默认值必须是 `client_asserted`。只有 Enforcement 层可以把 Candidate 提升为 `observed` 或
`derived`；Provider payload 中的同名字段不能覆盖它。Policy 可以读取来源，但不能把
`client_asserted` 历史当成用户批准、服务端调用次数或可信 provenance。

### 4. Message、ToolCall 和 ToolOutput 演进为独立事件

`ModelRequest`、`ModelResponse` 继续作为 LLMClient/Provider Adapter 的协议 DTO，不作为最终策略
图的唯一节点。后续 Input Normalizer 将其拆为独立 Message、ToolCall 和 ToolResult Event，并保留
稳定 ID、角色、Content 和显式关系。

迁移必须解决“全量聊天历史重复提交”的问题。没有稳定消息 ID 的 Gateway 请求只能把历史标记为
`client_asserted`；Framework Adapter 只有在掌握真实增量或精确对应同 Session 历史时才能提交
`observed/derived` Message。不得通过内容相似度或时间位置静默合并两条消息。

第一阶段允许原有边界 Event 作为降级 Adapter 输入，但所有 Session 判断必须立即通过
`PendingTrace` 主路径。独立 Message 接入完成后，再根据使用情况删除不再承担协议或兼容职责的
边界 EventKind。

### 5. Relation 仍然显式且类型化

不采用 Invariant 当前把同一顶层列表中较早对象自动视为流向较晚对象的顺序 dataflow。Sequence
只表达提交顺序，不表达来源。

第一阶段继续使用 `derived_from`。增加 `result_of`、`contained_by`、`responds_to` 等 RelationKind
前，必须定义它是否参与 provenance/taint 查询。通用关系遍历和数据来源遍历必须可区分，避免
`responds_to` 之类的会话关系被误当成敏感数据传播证据。

### 6. 双轨 Policy，但表达式实现后置到 Analyzer 稳定之后

长期 Policy Engine 支持两条轨道：

- Built-in Python Rule：受信任、显式注册，承载复杂 Detector 调度、性能敏感和需要专项审计的
  底层逻辑。
- Sandboxed Expression Policy：从文本解析、类型检查并由受限解释器执行，用于动态组合事件、
  Relation 和 Detector。

表达式策略不得生成或执行 Python，不得 import、访问文件、联网或创建进程。字段、函数、Detector
和图查询全部来自白名单，并必须有 AST 深度、求值步数、遍历节点数、耗时和输出数量限制。

本 ADR 不预先锁定 CEL。先使用真实 Invariant 风格策略样例验证 CEL 对事件量化、变量绑定、关系
遍历、错误定位和资源限制的覆盖度；如果大量语义只能隐藏在复杂宿主函数中，则评估安全改造
Invariant 的 Parser/AST/Interpreter。任何源码复用必须单独记录 Apache-2.0 attribution 和本项目
修改，不能直接复制 Gateway 耦合代码。

### 7. 兼容与遗留代码处理

| 现有能力 | 处理 |
|---|---|
| Built-in Python Rule/Detector Registry | 保留，作为双轨 Policy 的可信底层能力 |
| 严格 YAML Rule 配置 | 保留；未来增加 expression entry，而不是允许 Python module path |
| `GuardrailContext` | 保留为 Python Rule 的单事件只读视图，不再作为 Session 主入口 |
| `GuardrailEngine.evaluate(context)` / `GuardrailRuntime.evaluate(context)` | 暂作直接 `/v1/evaluate` 和测试兼容桥；内部 Session 不再依赖，v0.2 API 定稿后删除 |
| `DecisionEvaluator` | 由 `PolicyAnalyzer` 替代；内部引用和公共导出立即迁移，不保留同义协议 |
| `EnforcementSession.evaluate(...)` | 保留为单 Candidate 便利入口，必须委托批次主路径；Tool 边界仍有真实用途 |
| `ModelRequest` / `ModelResponse` | 保留为 Provider-neutral DTO；不得继续扩张为策略查询模型 |
| `source_event_ids` 便利参数 | 暂保留给单 Candidate 入口；批次 API 使用类型化 Candidate Relation |
| 自动顺序来源、动态 Python Policy | 不兼容且不保留 |

删除代码前必须用引用搜索和测试确认没有生产调用方；仅仅因为类名来自旧架构不能删除仍承担协议
DTO、兼容 API 或 Enforcement 职责的实现。兼容桥必须在文档中标记，且新生产路径不得继续依赖。

### 8. TraceStore、Multimodal 和 Transformation 继续分阶段

- 先完成进程内 PendingTrace/Monitor 语义，再通过独立 ADR 设计跨请求 TraceStore 的租户隔离、
  Run Token、TTL、CAS、幂等和保留策略。
- Content 使用封闭联合类型演进；图片下载、SSRF、大小限制和媒体 Detector 需要专项设计。
- 第一阶段继续只返回 `allow/log/block`。掩码、替换和安全响应使用独立 `TransformationPlan`，不能
  偷塞进 Action。

## 结果

优点：

- Core 可以原子分析一次操作产生的多个一等事件。
- 策略语言、Python Rule、Inline 和 Gateway 共享同一个增量分析语义。
- 保留比顺序 dataflow 更严格的来源可信边界。
- 明确哪些旧模型是协议 DTO、规则视图或兼容桥，避免两套长期内核并存。

代价：

- Decision、Runtime Protocol 和 Session API 发生破坏性演进。
- 独立 Message 需要 Adapter 处理全量历史与真实增量的差异。
- 表达式语言在可用前需要 Parser/类型/资源限制和大量兼容性测试。
- Gateway 跨请求关系仍需独立 TraceStore，不能由本 ADR 自动获得。

## 第一阶段验收

- Session 的单事件入口和批次入口都走 `PendingTrace → PolicyAnalyzer`。
- allow/log 原子提交全部 pending Event；block 不提交任何原始 pending Event。
- Decision 绑定完整 pending Event ID 集合，Violation 至少绑定一个 pending Event。
- Candidate 不能引用未来 Candidate、未知 past Event 或 Decision Event。
- `client_asserted` 是外部 Candidate 的默认信任来源，Provider payload 不能提升信任。
- 批次容量不足、Analyzer 异常或 Decision identity 不一致时 fail-closed 且不提交原文。
- 现有 Inline/Gateway pre/post 副作用不变量继续通过。

## 本 ADR 明确不做

- 不在第一阶段实现 CEL 或 Invariant Policy Language。
- 不实现自动顺序 dataflow、隐式内容相似度 provenance 或完整污点引擎。
- 不实现跨请求 TraceStore、MCP 协议 Session、多模态下载或 Transformation。
- 不复制 Invariant Gateway 的远程 Policy 服务耦合、客户端上传 Policy 或并发启动上游请求。
