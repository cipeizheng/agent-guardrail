# Runtime 与 Enforcement

## 1. 当前调用链

```text
GuardrailRuntime
  └─ MatchPolicyAnalyzer
       ├─ CompiledPolicy v3
       └─ SnapshotMatcher

EnforcementSession
  → PendingTrace
  → runtime.analyze_pending(...)
  → AnalysisReport
  → Decision
  → atomic commit / sanitized block event
```

Runtime 只管理已完整验证的 analyzer 生命周期。它不解析 Provider 协议、不执行 LLM/Tool，也不拥有
请求级 Trace。`PolicyAnalyzer` 主协议固定为：

```python
class PolicyAnalyzer(Protocol):
    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
```

`GuardrailRuntime.evaluate(GuardrailContext)` 只为直接 `/v1/evaluate` 单 Event API 构造
`PendingTrace.from_context`；Session 不依赖该桥。

## 2. 构造与生命周期

```python
runtime = GuardrailRuntime.from_policy_file(
    "policy.yaml",
    predicate_registry=predicates,
    detector_registry=detectors,
)

async with runtime:
    decision = await runtime.analyze_pending(pending)
```

默认构造使用新的空 Predicate Registry 和内置 `secrets/pii` Detector Registry。YAML 只接受 v3；
Loader 先编译 MatchPlan，再原子链接全部 capability，最后构造 `MatchPolicyAnalyzer`。任何错误都会阻止
Runtime 创建。

状态为 `created → ready → closed`。未 ready 或已经 closed 的 Runtime 拒绝分析；closed 不能重新启动。

## 3. Session 原子性

`EnforcementSession` 持有一个请求/任务级 Trace、AuditSink、可信 attributes、时钟和 ID factory。一次
`evaluate_candidates`：

1. 验证 batch 非空、有界、同 Phase、key 唯一；
2. 解析只指向同 Trace 更早 Event 或更早 Candidate 的 relation；
3. 分配连续 ID/sequence/time，构造 immutable PendingTrace；
4. 在 Session lock 内调用 Analyzer；
5. 验证 Analyzer 未修改输入，且 Decision identity 精确绑定 trace/primary/pending/phase；
6. allow/log 原子提交所有 Event；block 丢弃所有原始 Event，只提交脱敏 Decision Event；
7. 在锁外记录脱敏 Audit。

Trace 容量不足、Analyzer 异常、输入被修改或 Decision identity 错误都变成
`GuardrailUnavailable`；候选原文不提交。

聚合 `MODEL_REQUEST/MODEL_RESPONSE` 只能作为单 Candidate 显式桥，不能与独立 Event 混批，也不能成为
MatchPlan binding。普通批次使用 Message/ToolCall/ToolResult。

## 4. Inline LLM

`GuardedLLMClient.complete` 的顺序：

```text
first request snapshot → InputNormalizer → independent pre_llm batch
repeated full snapshot → explicit aggregate ModelRequest bridge
pre Decision allow
→ inner.complete
→ InputNormalizer response → independent observed post_llm batch
→ post Decision allow
→ return response
```

每个 observed response Event 显式引用该轮 request primary Event。首次请求已经使用独立事件；重复全量
history 在缺少 Framework stable message identity 时不得按内容静默去重，所以仍使用显式聚合桥。
可证明 identity 的增量 Framework Normalizer 是后续规划。

`pre_llm` block 时上游调用次数必须为零；`post_llm` block 时原响应不返回、不提交。

## 5. Inline Tool

`GuardedToolExecutor.execute`：

```text
observed ToolCall → pre_tool Decision
→ allow 才执行 inner tool
→ observed ToolResult → post_tool Decision
→ allow 才返回结果
```

Session 会在精确 payload 相等时把 observed `post_llm ToolCall` 关联到实际 `pre_tool ToolCall`；ToolResult
显式引用实际 ToolCall。这样多 Event MatchPlan 可以查询 request→response→execution→result 来源链，
而不把时间顺序冒充 provenance。

`pre_tool` block 时工具执行次数必须为零；`post_tool` block 时工具已经执行，但原结果不得进入 Trace
或返回 Agent。

## 6. Gateway

OpenAI Chat Completions 与 MCP 每个 HTTP 请求创建独立 Session。OpenAI Gateway 的 request/response
均经 InputNormalizer 生成独立 Event 批次，并将 response Event 关联到 request primary Event。
MCP `tools/call` 完整经过 pre_tool/post_tool；discover、ping、tools/list 不伪造工具执行边界。

Runtime/Analyzer 不知道 HTTP、OpenAI 或 MCP。Gateway/Enforcement 不解释 MatchPlan 条件，只消费
Decision。

## 7. Decision 与 Audit

MatchPolicyAnalyzer 把 Finding 和 AnalysisError 映射为 Violation：

- action 来自 v3 Policy Rule；
- pending subject 成为 Violation Event ID；
- Detector evidence 只含类型、版本、位置、mask、fingerprint 和 confidence；
- Detector timeout 使用专用失败动作，其他错误使用通用分析错误动作；
- `max_violations` 不提前终止 Matcher。

AuditSink 只接收 Decision，不接收 Event payload。JSONL Audit 仅记录时间、trace、phase、action、Rule ID、
code、Policy version/hash。Audit 失败对 block Decision 仍 fail-closed；log/allow 的具体审计失败处理保持
现有 Session 合同。

## 8. 当前遗留与后续

仍保留且有真实消费者：`GuardrailContext`/`PendingTrace.from_context` 的直接 `/v1/evaluate` 桥，
`MODEL_REQUEST` 重复全量 Inline 快照桥，以及 ModelRequest/ModelResponse Provider-neutral DTO。
这些都不是旧 Policy/Rule 引擎。

尚未实现：Framework stable identity 增量提交、跨请求 Session Store、Policy 热加载、Streaming、
多模态 Content 和远程 Core。
