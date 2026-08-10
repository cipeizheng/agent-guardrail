# Finding 与 AnalysisReport 公共模型

> 状态：公共 Schema、identity v1、MatchPlan、SnapshotMatcher/MatchMonitor、严格作者编译器和
> Gateway/Decision 接入已实现。
> 架构依据：[ADR-0010](adr/0010-invariant-aligned-policy-monitor.md)。

## 1. 本切片解决什么

`src/agent_guardrail/models/analysis.py` 固化通用分析层的输出合同，让后续无状态 Policy、增量 Monitor
和 Enforcement 适配可以共享同一种结果，而不提前选择 MatchPlan 语法或搜索算法。

当前新增的公共类型包括：

- `Finding`：一次规则匹配及其稳定身份、subject、脱敏 binding、位置和 evidence；
- `FindingLocation`：Canonical Event 内的有界字段路径和可选半开区间；
- `FindingBinding`：binding 名称、不可逆的结构身份 key，以及可选 Event/位置引用；
- `FindingEvidence`：Matcher、Predicate 或 Detector 产生的脱敏证据；
- `AnalysisError`：不含输入原文和异常堆栈的稳定错误分类；
- `AnalysisReport`：一次 snapshot 或 pending 分析看到的 Event ID 集合、findings 和 errors。

这些模型是封闭、不可变、可 JSON 序列化的 Pydantic 模型。它们不持有 Event payload，不执行 Rule、
Detector、LLM、Tool 或任何 Enforcement 动作。

## 2. Finding identity v1

`Finding.create(...)` 是生产方推荐构造入口。它按下列 canonical JSON 计算 SHA-256，并加
`fnd_` 前缀：

```json
{
  "finding_identity_version": 1,
  "policy_hash": "...",
  "rule_id": "...",
  "code": "...",
  "subject_event_ids": ["按字典序排序"],
  "bindings": [["binding_name", "binding_key"], "按二元组排序"]
}
```

identity v1 有以下语义：

- subject 的输入顺序和 binding 的输入顺序不影响 ID；
- Policy hash、rule ID、code、subject Event 集合或 binding key 改变时，ID 改变；
- `message`、位置、masked evidence、confidence 和错误文本不进入身份，避免文案、本地化或 Detector
  解释升级把同一个 match 误认为新 finding；
- 同一 binding 的不同集合元素或派生项必须使用不同的结构 key，不能只复用变量名；
- Event ID 只保证 Trace 内唯一，因此 finding 的去重命名空间是 `(trace_id, finding.id)`，不能跨 Trace
  单独把 `finding.id` 当成全局主键。

反序列化 `Finding` 时会重新计算并校验 ID；调用方不能通过填写任意合法形状的 `fnd_...` 绕过身份
合同。

### 2.1 binding key

`compute_binding_key(namespace, coordinate)` 对 canonical JSON 结构坐标计算 SHA-256。SnapshotMatcher
只传入稳定坐标，例如 Event ID、公开字段路径、集合下标、父坐标或声明式参数名；不得传入
Message 内容、Tool 参数值、Secret、原始 PII 或原始 Detector 输出。

`FindingBinding` 只保存 hash key，不保存 coordinate。Schema 能阻止原值出现在结果字段中，但不能
判断受信任生产方传给 hash helper 的字符串在业务上是不是 Secret；这一点属于 Matcher/Predicate/
Detector 实现的安全合同，后续实现和 review 必须检查。低熵敏感值的普通 hash 仍可能被离线枚举，不能
把“已 hash”误写成“可以安全输入原值”。

## 3. 引用与位置约束

`Finding.subject_event_ids` 定义该 finding 负责的 Event，至少一个且不重复。binding 可以引用 subject，
也可以引用参与匹配的历史 Event。Finding 自身位置和 evidence 位置只能指向 subject 或已绑定 Event；
位于 binding 内的位置必须与该 binding 的 `event_id` 一致。

路径是最多 16 段的 `str | int` tuple：字符串必须非空、去除首尾空白且不超过 64 字符；整数必须是
非负严格整数，布尔值不能冒充 `0/1`。`start/end` 必须同时存在，并表示 `0 <= start < end` 的半开
区间。位置只描述坐标，不携带该位置的原始字段值。

Detector evidence 必须声明已注册的 capability。`Finding.message` 必须是编译期静态文案，不能插值
Event 或 Detector 原值；`masked_evidence` 和 `AnalysisError.message` 也仍由受信任生产方负责脱敏。
模型只限制字段集合与长度，不会尝试从任意字符串推断它是否含 PII。

## 4. AnalysisReport 语义

`AnalysisReport` 保存有序 `event_ids`，并按分析模式区分：

| scope | `pending_event_ids` | finding 约束 | 预期生产方 |
| --- | --- | --- | --- |
| `snapshot` | 必须为空 | 所有引用都在 snapshot 内 | 无状态 Policy，通常 `emission=all` |
| `pending` | 非空且为 `event_ids` 子集 | 每条 finding 至少一个 subject 属于 pending | Matcher/Monitor，Monitor 使用 `emission=new` |

报告还会校验：Event ID 不重复；finding ID 不重复；report/finding Policy hash 一致；finding、binding、
location、evidence 和 error 的所有 Event 引用均属于本次 snapshot。这样 past-only match 不能被包装成
当前 pending finding。

`AnalysisErrorCode` 当前只提供稳定、脱敏的资源耗尽、Detector timeout、参数、输入、capability 和内部
错误分类。Report 可以同时带 findings 与 errors，未来 Policy/Monitor 或 Enforcement 适配必须按
Policy 的失败动作决定是否 fail-closed，不能因为已有部分 finding 就忽略错误。

## 5. 硬上限

当前 Schema 上限是：每个 Finding 最多 64 个 subject、128 个 binding、64 个位置、64 条 evidence；
每个 Report 最多 1,000 个 finding、100 个 error，snapshot Event 数继续受 Canonical
`MAX_TRACE_EVENTS=1,000` 限制。这些只是输出和引用上限，不是 Matcher 的搜索预算。MatchPlan v1 已在
[分项成本合同](match-plan-model.md)中分别定义 binding combination、量词、collection、派生字节、
Relation hop、Detector 调用和 condition step；当前 SnapshotMatcher 已对结构节点的实际路径消费账本，
capability 维度由 descriptor compiler 和 Matcher 验证。

## 6. 当前接入边界

- `MatchPolicyAnalyzer` 已将 pending AnalysisReport 映射为 Decision；
- `GuardrailRuntime`、EnforcementSession、OpenAI Gateway、MCP Gateway 和 Inline Wrapper 已使用该路径；
- `MatchMonitor` 的 dedupe 只在进程内存中有界保存，不持久化或跨进程共享；
- 独立 `load_match_plan_yaml` 仍只构造纯 MatchPlan；生产 `load_policy_yaml` 构造带 action/failure mapping
  和已链接 capability 的 CompiledPolicy。
