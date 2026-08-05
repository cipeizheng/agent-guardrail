# ADR-0006：一等 Event Relation

- 状态：Accepted（明确不做的演进范围被 ADR-0007 部分替代）
- 日期：2026-08-05
- 补充：ADR-0003 的 Canonical Event Model 与 ADR-0004 的 EnforcementSession 提交语义
- 替代范围：类型化 Relation 和显式来源图不变量继续有效；独立 Message、候选事件批次和受限
  表达式策略不再属于长期非目标

## 背景

项目已经需要表达 `ModelRequest → ModelResponse`、`ToolCall → ToolResult` 以及跨模型/工具边界的
可信来源关系。最初的纵向切片把来源 ID 放在保留的 `metadata["source_event_ids"]` 中，能够验证
关系规则，但存在三个长期问题：

- metadata 没有类型化关系语义，Schema 和调用方难以区分来源边与普通标签。
- 以后增加 Message、Content 或其他关系类型时，会继续扩张保留 metadata 协议。
- Rule 依赖一个通用扩展字段来做安全判断，不利于模型版本化和输入边界审计。

时间先后与来源关系必须继续分离。更早发生的 Event 不能自动成为后续 Event 的数据来源。

## 决策

### 1. Event 使用类型化关系字段

Canonical Model 新增：

```python
class RelationKind(StrEnum):
    DERIVED_FROM = "derived_from"


class EventRelation(CanonicalModel):
    source_event_id: str
    kind: RelationKind = RelationKind.DERIVED_FROM


class Event(CanonicalModel):
    relations: tuple[EventRelation, ...] = ()
```

当前只开放 `derived_from`，表示目标 Event 的内容或动作由来源 Event 直接派生。没有真实策略需求前，
不增加含义模糊的 `caused_by`，也不把简单时间顺序编码成 Relation。

### 2. 来源不再保存在 metadata

- `metadata["source_event_ids"]` 不再是 Canonical 来源表示，Event 和 Session 都拒绝该键。
- `Event.source_event_ids` 保留为从 `relations` 计算的只读便捷属性，供现有 Rule 查询使用。
- `EnforcementSession.evaluate(..., source_event_ids=...)` 暂时保留为可信 Enforcement API；Session
  将 ID 转换为 `derived_from` Relation，而不是写入 metadata。
- 以后如需让可信 Enforcement 明确提交多种关系，必须先扩展类型化 Session API，不能恢复
  metadata 后门。

### 3. Trace 维护图不变量

每条 Relation 必须：

- 指向同一 Trace 中更早、已经提交的 Event。
- 不指向当前 Event 自身或 `guardrail_decision` Event。
- `source_event_id + kind` 在目标 Event 内唯一。

Trace 的 `sources_of`、`ancestors_of` 和 `find(source_event_id=...)` 只查询显式 Relation。没有边时，
不得使用 sequence 或 timestamp 补推来源。

### 4. 信任边界保持不变

Inline/Gateway 的可信 Wrapper 和 Session 可以记录服务端实际观察到的边。直接 `/v1/evaluate` 的
调用方提交的是完整 Canonical Context，Core 只能判断该 Context，不能把其中的 Relation 宣称为
Gateway 观察事实。

`block` 的候选 Event 仍不得进入 Trace；只提交脱敏 Decision Event。Relation 不改变任何 pre/post
副作用顺序。

## 结果

优点：

- 来源关系进入公共 Schema，可类型检查、序列化和版本化。
- metadata 回到非安全关键的扩展信息用途。
- 后续独立 Message/Event Graph 演进不需要继续增加保留 metadata 键。
- 保留现有 Rule 查询接口，迁移范围可控。

代价：

- 关系夹具需要从 metadata 迁移到 `EventRelation`。
- 当前仍只有单一来源关系类型，不是通用图查询语言或污点引擎。
- Gateway 请求级 Trace 不会因此获得跨请求历史。

## 明确不做

- 不在本 ADR 中增加独立 Message Event、候选事件批量提交或多模态 Content。
- 不增加 TraceStore、MCP 协议 Session 或跨请求可信关系。
- 不引入 CEL、Invariant Policy Language 或其他动态表达式执行。
- 不根据事件时间顺序自动生成 provenance。
