# Runtime 与 Enforcement 详细设计

本文是 ADR-0004/0005/0006/0007 的实现合同及当前实现说明。Runtime、Session、Inline Wrapper、
OpenAI Gateway 和 MCP Gateway 均已实现；若本文与 Accepted ADR 冲突，以 ADR 为准。

## 1. 目标

建立一条被 Inline、LLM Gateway 和 MCP Gateway 共用的最小流水线：

```text
Enforcement Point（使用 Protocol Adapter 完成转换）
   → EnforcementSession
   → PendingTrace
   → PolicyAnalyzer
   → GuardrailRuntime
   → GuardrailEngine
   → Decision
```

Runtime 判断，Session 管理检查历史，Enforcement Point 控制副作用。三者不能合并成一个大类。

## 2. 公共协议

### 2.1 PolicyAnalyzer

```python
class PolicyAnalyzer(Protocol):
    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
```

要求：

- `analyze_pending` 不执行 LLM、Tool、HTTP 或 Audit 副作用。
- 相同 Policy 与 PendingTrace 必须产生相同动作语义。
- 实现必须支持多个请求并发调用。
- Runtime 不可用时抛出类型明确且不含输入原文的异常，不能返回 allow。
- Decision v2 必须精确绑定 primary Event、完整 pending Event ID 集合和 Phase；Violation 必须绑定
  至少一个 pending Event。

`GuardrailEngine.evaluate(GuardrailContext)` 和 `GuardrailRuntime.evaluate(GuardrailContext)` 仍用于
直接 `/v1/evaluate` 兼容边界，但它们只是构造单 Event PendingTrace 的桥。Session 和新的生产集成
不得依赖该旧主入口。

### 2.2 LLMClient 与 ToolExecutor

```python
class LLMClient(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class ToolExecutor(Protocol):
    async def execute(self, call: ToolCall) -> ToolResult: ...
```

`GuardedLLMClient` 和 `GuardedToolExecutor` 必须满足与 inner 相同的 Protocol，因此调用方无需
知道是否安装护栏。

### 2.3 AuditSink

```python
class AuditSink(Protocol):
    async def record(self, decision: Decision) -> None: ...
```

AuditSink 只接收已经脱敏的 Decision。当前 Session 记录所有包含 Violation 的 Decision；没有
Violation 的普通 allow 不逐条持久化。Audit 写入失败默认 fail-open，并把不含原文的异常类型
保存在 Session 的 `audit_failure_types`。

## 3. GuardrailRuntime

### 3.1 职责

```python
class GuardrailRuntime:
    @classmethod
    def from_policy_file(
        cls,
        path: str | Path,
        *,
        rule_registry: RuleRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> GuardrailRuntime: ...

    @classmethod
    def from_policy_yaml(
        cls,
        source: str,
        *,
        rule_registry: RuleRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> GuardrailRuntime: ...

    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
    async def evaluate(self, context: GuardrailContext) -> Decision: ...

    @property
    def ready(self) -> bool: ...

    @property
    def state(self) -> RuntimeState: ...

    @property
    def policy_info(self) -> PolicyInfo: ...
```

具体要求：

- `from_policy_file`/`from_policy_yaml` 使用默认 built-in Registry，除非受信任的应用组装代码或测试
  显式注入 Registry；普通 YAML 不能指定 Python Rule。
- 每次构建创建独立 Registry，不使用可变全局单例。
- 构造只在 Policy 完整校验后成功，不能部分启用规则。
- ready 状态下重复 `start` 幂等，任意状态重复 `close` 幂等，并支持 `async with`；closed Runtime
  不能重新启动。
- `evaluate` 只能在 ready 状态调用，否则抛出 `RuntimeNotReadyError`。
- `PolicyInfo` 只包含 version/hash，不回显 Policy YAML 或 Rule Secret 配置。
- Runtime 可被多个 Session 并发复用；单个 Session 不跨租户共享。

MVP 不实现热加载。未来热加载只能用“构建新 Engine → 完整验证 → 原子交换”的方式，正在执行
的请求继续使用它开始时捕获的旧 Engine snapshot。

### 3.2 与 GuardrailEngine 的关系

```text
GuardrailRuntime
  ├─ lifecycle/readiness
  ├─ PolicyInfo
  └─ active GuardrailEngine
       ├─ immutable PolicySet
       └─ DetectorRegistry
```

Engine 保持可以直接在单元测试中构造。生产 Inline/Gateway 默认使用 Runtime，不各自调用
Config Loader 和 Registry。

## 4. EnforcementSession

### 4.1 构造

```python
session = EnforcementSession(
    analyzer=runtime,
    trace=Trace(id=trace_id),
    audit=JsonlAuditSink(...),
    attributes={"tenant_id": "..."},
    clock=clock,
    id_factory=id_factory,
)
```

Session 独占一个 Trace。`attributes` 在构造时会复制，当前 Adapter 不会用 Provider payload
覆盖可信 tenant/user 属性。当前对象仍暴露普通 `dict`，调用方必须把它视为只读；若未来需要
硬性不可变保证，应调整公共类型并补兼容性测试。

### 4.2 检查 API

单 Candidate 便利 API：

```python
decision = await session.evaluate(
    kind=EventKind.TOOL_CALL,
    phase=Phase.PRE_TOOL,
    payload=call.model_dump(mode="json"),
    metadata={"adapter": "inline"},
    source_event_ids=(source_event.id,),
)
```

它必须委托批次主入口：

```python
decision = await session.evaluate_candidates(
    (
        CandidateEvent(
            key="response",
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=response_payload,
            origin=EventOrigin.OBSERVED,
        ),
        CandidateEvent(
            key="tool-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.POST_LLM,
            payload=tool_call_payload,
            origin=EventOrigin.DERIVED,
            relations=(CandidateRelation(source_candidate_key="response"),),
        ),
    ),
    primary_key="response",
)
```

当前 OpenAI/MCP/Inline Adapter 仍使用单 Candidate 入口；批次 API 和内部原子语义已经交付，独立
Message/Input Normalizer 尚未接入。

Session 必须校验合法映射：

- `MODEL_REQUEST` 只能是 `PRE_LLM`。
- `MODEL_RESPONSE` 只能是 `POST_LLM`。
- `TOOL_CALL` 只能是 `PRE_TOOL`。
- `TOOL_RESULT` 只能是 `POST_TOOL`。
- Adapter 不能用 `GUARDRAIL_DECISION` 调用 evaluate。

批次入口还允许 `post_llm` 中的派生 ToolCall Candidate。所有 Candidate 必须使用同一 Phase，key
唯一，primary key 必须存在，合并后的 Event 数不能超过 Trace 上限。

`source_event_ids` 是可信 Enforcement 代码专用参数；Session 将它转换为类型化
`EventRelation(kind="derived_from")`。`metadata["source_event_ids"]` 会被拒绝，防止客户端或
通用 Adapter metadata 冒充来源。每个来源必须是同一 Trace 中更早、已提交且不是
`guardrail_decision` 的 Event；空白、重复、未知和跨 Trace ID 都会在评估前失败。

### 4.3 来源推导与关系查询

Session 会对两种 Canonical 结构做保守推导：历史 ModelResponse 中完全相同的 ToolCall 可以作为
当前 ToolCall 的来源；历史 ToolResult 与 ModelRequest 中 Tool message 的 `tool_call_id` 和规范化
内容都精确一致时，可以作为该 ModelRequest 的来源。Wrapper/Gateway 还会显式记录同一副作用边界
的 `ModelRequest → ModelResponse` 和 `ToolCall → ToolResult`。无法精确对应时不建边。

Trace 提供 `by_id`、`find`、`events_since`、`sources_of` 和 `ancestors_of`。来源只能指向更早事件，
因此图保持无环；`sources_of` 返回直接来源，`ancestors_of` 返回按 Trace 顺序排列的传递祖先。
`previous`/`count` 继续用于纯历史查询。关系只在当前 Session 内可信，不能跨 Gateway HTTP 请求。

### 4.4 原子批次分析与提交

单个 Session 内使用异步锁串行化“构造 pending snapshot → analyze → commit”，以支持并行 Tool 调用
而不破坏 Trace 顺序。锁不能覆盖真正的 LLM/Tool 副作用。

```text
lock
  → validate Candidate keys/origin/references/capacity
  → allocate IDs/sequences/timestamps and build typed relations
  → PendingTrace(committed snapshot + pending events)
  → analyzer.analyze_pending(pending)
  → validate Decision identity and Violation event bindings
  → allow/log: append every pending Event atomically
  → block: append one sanitized guardrail_decision Event
  → unlock
  → Enforcement Point decides whether to perform/release side effect
```

block Event 只能包含：

- action、phase。
- primary event_id 和本批次 pending_event_ids。
- rule_id 与 violation code。
- Policy version/hash。

不得包含 Violation evidence、message、原始 payload 或 Provider response。

### 4.5 错误语义

| 错误 | Session/Enforcement 行为 |
|---|---|
| Rule/Detector 已知错误 | Engine 转换为系统 Violation，按 Policy 聚合 |
| Runtime 未 ready | 抛 `GuardrailUnavailable`，不执行/不释放副作用 |
| Analyzer 未知异常 | 抛 `GuardrailUnavailable`，不执行/不释放副作用 |
| Analyzer 修改 PendingTrace snapshot | 拒绝 Decision 并 fail-closed，不提交任何原始 pending Event |
| AuditSink 失败 | Decision 保持有效，默认继续；发出脱敏错误信号 |
| Trace 容量不足以容纳整个 pending batch | 分析前 fail-closed，不覆盖或删除旧 Event |
| 来源 ID 非法 | 评估前拒绝，不执行/不释放副作用 |

`GuardrailBlocked` 和 `GuardrailUnavailable` 的异常字符串只能包含 trace ID、phase 和错误类别。
结构化 Decision 可以作为 `GuardrailBlocked.decision` 提供，但不得额外附带 candidate Event。

## 5. Inline Wrapper

### 5.1 GuardedLLMClient

```text
ModelRequest
  → session.evaluate(model_request, pre_llm；精确匹配历史 ToolResult 来源)
  → block: raise GuardrailBlocked，inner.complete count = 0
  → inner.complete
  → session.evaluate(model_response, post_llm；来源为本次 ModelRequest)
  → block: raise GuardrailBlocked，不返回原 ModelResponse
  → return ModelResponse
```

### 5.2 GuardedToolExecutor

```text
ToolCall
  → session.evaluate(tool_call, pre_tool；精确匹配历史 ModelResponse 来源)
  → block: raise GuardrailBlocked，inner.execute count = 0
  → inner.execute
  → session.evaluate(tool_result, post_tool；来源为本次 ToolCall)
  → block: raise GuardrailBlocked，不返回原 ToolResult
  → return ToolResult
```

Wrapper 不直接访问 `GuardrailEngine`、Policy、Trace 或 AuditSink；这些只通过 Session 使用。

## 6. HTTP 与 MCP EnforcementSession 生命周期

| 接入 | Session 生命周期 | 历史保证 |
|---|---|---|
| Inline | 一次 Agent task/run | 提供同任务事件历史、计数查询和来源关系；内置调用次数/审批规则尚未实现 |
| LLM Gateway v0.1 | 一次 HTTP request | 只保证本次 request/response；messages 不作为可信历史 |
| MCP Gateway `2026-07-28` | 一个 `tools/call` HTTP request | 只跟踪该调用及其 ToolResult；无协议 Session |

LLM 与 MCP Gateway 即使使用相同外部 correlation ID，MVP 也不合并内存 Trace。跨 Gateway 的
统一 Agent Trace 需要认证后的 Session Store，属于后续 ADR。现代 MCP 不再提供可直接作为该
Store 主键的 `Mcp-Session-Id`，不能从旧协议语义推断可信历史。

## 7. 已完成的目录迁移

```text
models/chat.py                    # provider-neutral Chat Models
enforcement/protocols.py          # LLM/Tool/Audit Protocol
enforcement/inline_tools.py       # pre_tool/post_tool
enforcement/inline_llm.py         # pre_llm/post_llm
enforcement/session.py            # shared Trace/evaluate/commit
testing/fakes.py                  # ScriptedLLM/FakeToolExecutor
testing/simulated_agent.py        # protocol-only Agent loop
runtime/
  ├─ protocols.py                 # PolicyAnalyzer
  ├─ runtime.py                   # GuardrailRuntime
  └─ bootstrap.py                 # built-in registry composition
```

旧 `integrations/` 已移除。生产模块不导入 testing；当前 Gateway 只依赖 Runtime、Session 和
协议 Adapter，没有重新实现 Rule 判断。

## 8. 最小测试矩阵

Runtime：

- Policy 成功/失败构建。
- start/close 幂等。
- 未 ready evaluate 失败且不返回 allow。
- 并发 evaluate 不共享请求级 Detector Cache。

Session：

- allow/log 原子提交整个 candidate batch。
- block 不提交任何原始 pending Event，只提交一个脱敏 Decision Event。
- 并发检查保持严格递增 sequence。
- Trace 满时 fail-closed。
- Audit 失败不泄露原文。
- provenance 只能进入类型化 Relation，不能由普通 metadata 注入。
- 未知/重复/未来/Decision 来源被拒绝，直接与传递关系查询保持顺序。
- Event 默认 `client_asserted`，只有 Enforcement 代码显式标记 `observed/derived`。
- Analyzer 失败或 Decision 的 primary/pending identity 不一致时不提交原始 Event。

Inline：

- pre block 时 inner 调用为零。
- allow/log 时 inner 调用恰好一次。
- post block 时调用发生一次，但原结果不返回且不进入 Trace。
- LLM 与 Tool Wrapper 共享一个 Trace。
- 精确的完整 Agent loop 自动形成 request/response/call/result 来源链。
- 只有时间先后、没有来源边时，关系 Rule 不得命中。

Testing：

- SimulatedAgent 只依赖 Protocol。
- 所有场景无网络、无 API Key、无时间随机性。
- Secret 不出现在异常、Audit 和 block Trace Event。
