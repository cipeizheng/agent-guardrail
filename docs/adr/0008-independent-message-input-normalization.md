# ADR-0008：独立 Message Event 与 Input Normalization

- 状态：Accepted
- 日期：2026-08-06
- 补充范围：ADR-0007 的 Candidate batch、Event 来源、独立 Message 和全量历史迁移结论
- 保留范围：ADR-0007 的 `PendingTrace → PolicyAnalyzer` 主边界、显式类型化 Relation、
  Runtime/Enforcement 分层、兼容桥和禁止隐式顺序 dataflow 的结论

## 背景

ADR-0007 已经确定 `ModelRequest`、`ModelResponse` 最终不能是策略图中的唯一节点，但有意把以下问题
留给后续设计：

- 没有稳定 Message ID 的 OpenAI-compatible 全量历史应如何进入请求级 Trace。
- Provider DTO、Input Normalizer、Session 分别负责哪些验证和信任决策。
- 聚合边界 Event 与独立 Message/ToolCall/ToolResult 在迁移期间如何共存，且不造成漏检或重复
  Violation。
- Tool role 消息如何与准确的 ToolCall 建立关系，尤其是在不同对话轮次可能重复使用 call ID 时。
- `max_violations` 在批次分析中是结果数量限制，还是提前终止评估的资源限制。

当前 OpenAI Gateway、Inline LLM Wrapper 和直接 `/v1/evaluate` 仍把 `ModelRequest` 或
`ModelResponse` 作为一个 Event 提交。直接在 Provider Adapter 中拆分消息会让协议层决定 Event
信任；在 Session 或 Core 中拆分又会让它们解释 LLM 协议。若同时把聚合 Event 和独立子 Event
交给现有 Rule，还会产生同一内容被检查两次的中间状态。

本 ADR 固定第一阶段的规范化边界和迁移顺序。它是设计合同；被接受不表示下述 Schema、Normalizer
或 Gateway 批次接入已经交付。

## 决策

### 1. 独立 Event 是新生产路径的策略表示

Canonical Model 增加 `MESSAGE` EventKind 和封闭的 Message payload。第一阶段只支持文本，Message
payload 只表达角色和文本 Content；多模态 Content 继续后置。角色与展开规则如下：

- `system`、`user` 和带文本的 `assistant` DTO 消息分别产生一个 Message Event。
- 同一个 `assistant` DTO 中的每个 tool call 分别产生一个 ToolCall Event；同时存在文本时，文本
  Message 和 ToolCall 都保留。
- 只有 tool call、没有文本的 `assistant` DTO 不创建空 Message Event。
- `tool` DTO 消息产生 ToolResult Event，不产生 Message Event。
- Model response 中非 `None` 的文本产生 assistant Message；每个 tool call 产生独立 ToolCall。

`ChatMessage`、`ModelRequest` 和 `ModelResponse` 继续作为 Provider-neutral 协议 DTO，不扩张成策略
查询模型。Session 分配的 Event ID 是当前 Trace 内的 Canonical identity；不得把 request-local
Candidate key、内容摘要或 Provider 列表位置宣称为跨请求稳定 Message ID。

新生产批次只提交独立 Message/ToolCall/ToolResult Event，不在同一批次中同时提交聚合
ModelRequest/ModelResponse Event 及其展开结果。聚合边界 Event 暂时只作为兼容输入存在。

### 2. Input Normalizer 属于 Enforcement 层

运行链固定为：

```text
Provider payload
  → Provider Adapter：协议校验并生成 ModelRequest/ModelResponse DTO
  → Enforcement Input Normalizer：生成封闭的 Candidate batch 和 primary key
  → EnforcementSession：分配 Event ID/sequence/time，验证来源、关系与容量
  → PendingTrace → PolicyAnalyzer
```

Input Normalizer 必须是 provider-neutral、确定性且无 I/O 的 Enforcement 组件。它接收已经校验的
DTO 和由 Enforcement Point 提供的 phase、来源模式及资源上限，输出 `CandidateEvent` 及类型化
Candidate Relation。它不分配正式 Event ID、sequence 或 timestamp，不执行 LLM/Tool/Audit
副作用，也不读取 Provider payload 中自称的 `origin`、Relation 或 Canonical Event identity。

Provider Adapter 只负责协议字段、JSON 形状和 Provider 到 DTO 的转换；Core/Runtime 不解释聊天
协议。Session 继续作为 Candidate 转换为 Canonical Event、构造 immutable PendingTrace 和原子提交
的唯一入口，并对 Normalizer 已检查的约束做防御性复验。

### 3. 全量快照与显式增量使用不同信任模式

OpenAI-compatible Gateway 的一次请求使用新的 request-scoped Session/Trace。Normalizer 可以展开该
请求携带的全部历史，但所有请求历史 Event 都必须是 `client_asserted`：

- 相同内容出现两次就是两个 Event，不做内容、摘要、角色加位置或时间近似去重。
- 不跨 Gateway 请求复用 Event ID 或关系；跨请求身份需要未来 TraceStore ADR。
- 客户端提供的 call ID 只用于当前快照内的精确结构关联，不能提升 Event 来源。

上游模型只能在 `pre_llm` 批次通过后调用。实际收到的模型响应在 `post_llm` 展开为 `observed`
Message/ToolCall；`observed` 只证明响应经过受信任 Enforcement Point，不证明其内容正确或安全。

Framework Adapter 只有在掌握真实新增项，或能把输入 identity 精确对应到同一 Session 已提交
历史时，才可以使用显式增量模式并提交 `observed`/`derived` Event。通用 Inline LLM Wrapper 在
无法区分全量历史和真实增量时，不得反复展开完整请求历史，也不得自行猜测去重；其请求侧聚合
兼容路径保留到专用 Framework Adapter 能提供这个合同为止。可精确观察的响应侧不受此限制。

### 4. ToolResult 只按有效 tool-call turn 精确关联

Normalizer 在一个全量快照中维护当前有效的 assistant tool-call group：

- ToolResult 的 `tool_call_id` 必须准确匹配当前 group 中一个尚未消费的 ToolCall。
- ToolResult 的 tool name 从匹配的 ToolCall 得到，不能由缺少该字段的 tool role 消息猜测。
- 一个 ToolCall 在同一 group 中最多匹配一个 ToolResult。
- 进入后续非 tool 消息后，旧 group 不再参与匹配；因此 call ID 可以在不重叠的后续轮次重新使用。
- 孤立、重复、歧义、跨轮次和结构不完整的 ToolResult 必须作为输入验证错误拒绝，不使用“最后一个
  ToolCall”等回退。

成功匹配的 ToolResult 使用显式 `derived_from` Candidate Relation 指向对应 ToolCall。若两者都来自
客户端快照，它们仍然是 `client_asserted`；结构关系不能把客户端声明升级成服务端观察事实。

Message 与同一 DTO 中的 ToolCall 目前不增加 `contained_by`，响应与前序请求也不自动增加
`responds_to` 或 dataflow 边。Sequence 只表示批次提交顺序。增加新的 RelationKind 仍需先定义它
是否参与 provenance 查询。

### 5. Phase 表示当前 Enforcement checkpoint

Event phase 表示该 Candidate 正在哪个检查点接受判断，不冒充其最初发生时间：

| Enforcement checkpoint | 允许的独立 Event | 来源 |
|---|---|---|
| `pre_llm` Gateway 快照 | Message、ToolCall、ToolResult | `client_asserted` |
| `post_llm` 上游响应 | Message、ToolCall | `observed` |
| `pre_tool` 实际工具调用 | ToolCall | 由 Enforcement 确定，通常为 `observed`/`derived` |
| `post_tool` 实际工具结果 | ToolResult | 由 Enforcement 确定，通常为 `observed`/`derived` |

Provider payload 不能通过字段覆盖 phase 或 origin。Rule 必须同时考虑 kind、phase 和 origin，不能把
`pre_llm` 中客户端重放的 ToolResult 当成服务端已经执行过一次工具。

### 6. `max_violations` 限制证据，不限制安全评估覆盖面

`max_violations` 只限制 Decision 返回和审计的 Violation 数量，不能在达到上限时停止评估后续
pending Event 或 Rule。Engine 必须完成有界批次内所有适用 Rule 的评估，并独立聚合所有命中的
最高 Action。

保留的 Violation 必须使用确定性、有界的优先选择：先按 Action 严重度，再按稳定的 Event/Rule
评估顺序选择前 `max_violations` 条。因此后出现的 BLOCK 必须能够替换先进入结果集的 LOG，且结果
中至少保留一条代表最终最高 Action 的证据。`max_violations` 不是 Rule 执行步数或时间预算；Rule
超时、Detector 超时和异常继续使用 Policy 中显式的 fail-closed Action。

### 7. 批次和关系必须在副作用前有界

Normalizer 必须在调用 Session 前限制展开后的 Candidate 数量和每个 Candidate 的 Relation 数量；
Session 必须再次检查 batch、Relation 和合并后 Trace 容量。任何超限、非法引用或 malformed
history 都在上游 LLM/Tool 副作用发生前失败，且不提交部分原始 Event。

allow/log 原子提交整个独立 Event 批次；任一 Event 导致 block 时，批次中的所有原始 Event 都不
进入 Trace，只提交一个脱敏 Decision Event。Decision 继续绑定完整 pending Event ID 集合。

### 8. 兼容迁移不得污染新生产路径

| 现有能力 | 第一阶段处理 |
|---|---|
| `ChatMessage` / `ModelRequest` / `ModelResponse` | 保留为协议 DTO |
| `MODEL_REQUEST` / `MODEL_RESPONSE` EventKind | 保留为直接 API、单 Event 入口和旧测试的兼容输入；不进入 Gateway 新规范化批次 |
| `GuardrailContext` 与 Engine/Runtime `evaluate` | 按 ADR-0007 保留为直接 `/v1/evaluate` 和测试兼容桥 |
| `EnforcementSession.evaluate` | 保留并委托批次主路径；真实 Tool 边界继续使用 |
| Rule 对聚合 request/response payload 的分支 | 暂保留给兼容输入；新生产路径必须增加独立 Event 分支 |
| `infer_source_event_ids` 的 DTO 匹配 | 暂保留给单 Event 兼容路径；新批次只使用 Normalizer 的显式 Candidate Relation |
| `source_event_ids` 便利参数 | 按 ADR-0007 暂保留；新批次使用类型化 Candidate Relation |

Rule 的独立 Event 支持必须先于 Gateway 新批次启用完成，或与 Gateway 切换作为同一个不可分割的
发布单元。任何提交都不得出现“Gateway 已只发送独立 Event、Rule 却仍只查询聚合 payload”的漏检
窗口。新生产批次不包含聚合 Event，因此兼容 Rule 分支也不会对同一内容产生双重 Violation。

聚合 EventKind、旧 phase 映射、DTO equality/output text provenance 推断只能在完成生产引用搜索、
兼容 API 退出判断和回归测试后删除。仅标记为遗留候选不构成删除授权。

### 9. 实施顺序固定为可独立验证的迁移切片

1. 修复 `max_violations` 提前终止，并增加“先 LOG、后 BLOCK”的批次回归测试。
2. 增加 Message Event Schema，扩展合法 phase 映射和容量/关系边界，同时保留兼容 Schema。
3. 实现 Input Normalizer，覆盖正常展开、混合文本与 tool calls、重复内容、turn-local ToolResult、
   malformed history、来源和边界测试。
4. 迁移 Built-in Rule 支持独立 Event，同时保留隔离的聚合兼容分支。
5. 将 OpenAI Gateway 的 pre/post LLM 路径切换到原子 Candidate batch，并验证 pre block 时上游调用
   为零、post block 时原始响应不返回。
6. 搜索生产和测试引用，清理已无职责的旧路径，并同步 README、architecture、专项设计和 roadmap。

步骤 4 和 5 可以在同一变更中完成，但 Gateway 不得先于 Rule 单独启用。

## 结果

优点：

- Policy 以一等 Message/ToolCall/ToolResult 查询输入，不再长期解析聚合 Provider DTO。
- 全量历史的低信任语义和显式增量的高信任条件分开，不需要危险的内容去重。
- Normalizer、Session、Core 和 Adapter 的职责明确，Provider payload 不能借规范化过程提升信任。
- 兼容 API 可以继续工作，同时生产路径不会混用两种表示造成重复命中。
- `max_violations` 不会因批次中较早的低严重度结果掩盖后续 BLOCK。

代价：

- 聚合 Rule 分支和 EventKind 在兼容期内仍需维护。
- Gateway 请求级 Trace 无法证明历史中的 ToolCall/ToolResult 曾由本服务执行。
- Framework Adapter 必须提供真实增量合同，不能直接复用 Gateway 快照语义。
- malformed tool history 将比旧 DTO Adapter 更严格地被拒绝。

## 验收

- Gateway 请求历史全部是 `client_asserted`，响应独立 Event 是 `observed`，payload 不能覆盖来源。
- 同内容、同角色的重复消息产生不同 Event，不进行隐式去重。
- assistant 文本/tool calls 和 tool role 依据本 ADR 确定性展开。
- ToolResult 只关联当前有效 tool-call group；孤立、重复或跨轮次引用在上游调用前失败。
- 新 Gateway 批次不包含 `MODEL_REQUEST`/`MODEL_RESPONSE` Event。
- Rule 同时覆盖独立生产 Event 和聚合兼容输入，且同一生产内容只产生一组语义命中。
- 达到 `max_violations` 后仍评估后续 Event/Rule；后出现的 BLOCK 决定最终 Action。
- batch/Relation/Trace 超限 fail-closed，block 不提交任何原始 pending Event。
- Inline 和 Tool Wrapper 的现有副作用顺序、共享 Session 与兼容行为不回归。

## 本 ADR 明确不做

- 不实现跨请求稳定 Message ID、TraceStore、客户端可写 Canonical Event 或可信历史恢复。
- 不实现内容相似度去重、隐式顺序 dataflow 或“最近 ToolCall”回退。
- 不增加 `contained_by`、`responds_to`、`result_of` 等 RelationKind。
- 不实现多模态 Content 下载、Streaming、表达式 Policy、Transformation 或远程 Core。
- 不在本 ADR 中立即删除任何兼容 API、聚合 EventKind 或旧 Rule 分支。
