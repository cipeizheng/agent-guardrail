# Runtime 与 Enforcement 详细设计

本文是 ADR-0004/0005 的实现合同及当前实现说明。Runtime、Session、Inline Wrapper、OpenAI
Gateway 和 MCP Gateway 均已实现；若本文与 Accepted ADR 冲突，以 ADR 为准。

## 1. 目标

建立一条被 Inline、LLM Gateway 和 MCP Gateway 共用的最小流水线：

```text
Enforcement Point / Protocol Adapter
   → EnforcementSession
   → DecisionEvaluator
   → GuardrailRuntime
   → GuardrailEngine
   → Decision
```

Runtime 判断，Session 管理检查历史，Enforcement Point 控制副作用。三者不能合并成一个大类。

## 2. 公共协议

### 2.1 DecisionEvaluator

```python
class DecisionEvaluator(Protocol):
    async def evaluate(self, context: GuardrailContext) -> Decision: ...
```

要求：

- `evaluate` 不执行 LLM、Tool、HTTP 或 Audit 副作用。
- 相同 Policy 与 Context 必须产生相同动作语义。
- 实现必须支持多个请求并发调用。
- Runtime 不可用时抛出类型明确且不含输入原文的异常，不能返回 allow。

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
        path: Path,
        *,
        rule_registry: RuleRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> GuardrailRuntime: ...

    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def evaluate(self, context: GuardrailContext) -> Decision: ...

    @property
    def ready(self) -> bool: ...

    @property
    def policy_info(self) -> PolicyInfo: ...
```

具体要求：

- `from_policy_file` 使用默认 built-in Registry，除非测试显式注入。
- 每次构建创建独立 Registry，不使用可变全局单例。
- 构造只在 Policy 完整校验后成功，不能部分启用规则。
- `start`/`close` 幂等，并支持 `async with`。
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
    evaluator=runtime,
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

当前 API：

```python
decision = await session.evaluate(
    kind=EventKind.TOOL_CALL,
    phase=Phase.PRE_TOOL,
    payload=call.model_dump(mode="json"),
    metadata={"adapter": "inline"},
)
```

Session 必须校验合法映射：

- `MODEL_REQUEST` 只能是 `PRE_LLM`。
- `MODEL_RESPONSE` 只能是 `POST_LLM`。
- `TOOL_CALL` 只能是 `PRE_TOOL`。
- `TOOL_RESULT` 只能是 `POST_TOOL`。
- Adapter 不能用 `GUARDRAIL_DECISION` 调用 evaluate。

### 4.3 原子评估与提交

单个 Session 内使用异步锁串行化“分配 sequence → evaluate → commit”，以支持并行 Tool 调用
而不破坏 Trace 顺序。锁不能覆盖真正的 LLM/Tool 副作用。

```text
lock
  → create candidate Event(sequence=trace.next_sequence)
  → evaluator.evaluate(current Event + committed Trace)
  → allow/log: append candidate Event
  → block: append sanitized guardrail_decision Event
  → unlock
  → Enforcement Point decides whether to perform/release side effect
```

block Event 只能包含：

- action、phase。
- 被检查的 event_id。
- rule_id 与 violation code。
- Policy version/hash。

不得包含 Violation evidence、message、原始 payload 或 Provider response。

### 4.4 错误语义

| 错误 | Session/Enforcement 行为 |
|---|---|
| Rule/Detector 已知错误 | Engine 转换为系统 Violation，按 Policy 聚合 |
| Runtime 未 ready | 抛 `GuardrailUnavailable`，不执行/不释放副作用 |
| Evaluator 未知异常 | 抛 `GuardrailUnavailable`，不执行/不释放副作用 |
| AuditSink 失败 | Decision 保持有效，默认继续；发出脱敏错误信号 |
| Trace 达到上限 | fail-closed，不覆盖或删除旧 Event |

`GuardrailBlocked` 和 `GuardrailUnavailable` 的异常字符串只能包含 trace ID、phase 和错误类别。
结构化 Decision 可以作为 `GuardrailBlocked.decision` 提供，但不得额外附带 candidate Event。

## 5. Inline Wrapper

### 5.1 GuardedLLMClient

```text
ModelRequest
  → session.evaluate(model_request, pre_llm)
  → block: raise GuardrailBlocked，inner.complete count = 0
  → inner.complete
  → session.evaluate(model_response, post_llm)
  → block: raise GuardrailBlocked，不返回原 ModelResponse
  → return ModelResponse
```

### 5.2 GuardedToolExecutor

```text
ToolCall
  → session.evaluate(tool_call, pre_tool)
  → block: raise GuardrailBlocked，inner.execute count = 0
  → inner.execute
  → session.evaluate(tool_result, post_tool)
  → block: raise GuardrailBlocked，不返回原 ToolResult
  → return ToolResult
```

Wrapper 不直接访问 `GuardrailEngine`、Policy、Trace 或 AuditSink；这些只通过 Session 使用。

## 6. HTTP 与 MCP EnforcementSession 生命周期

| 接入 | Session 生命周期 | 历史保证 |
|---|---|---|
| Inline | 一次 Agent task/run | 可执行同任务调用次数、来源与审批规则 |
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
  ├─ protocols.py                 # DecisionEvaluator
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

- allow/log 提交 candidate Event。
- block 只提交脱敏 Decision Event。
- 并发检查保持严格递增 sequence。
- Trace 满时 fail-closed。
- Audit 失败不泄露原文。

Inline：

- pre block 时 inner 调用为零。
- allow/log 时 inner 调用恰好一次。
- post block 时调用发生一次，但原结果不返回且不进入 Trace。
- LLM 与 Tool Wrapper 共享一个 Trace。

Testing：

- SimulatedAgent 只依赖 Protocol。
- 所有场景无网络、无 API Key、无时间随机性。
- Secret 不出现在异常、Audit 和 block Trace Event。
