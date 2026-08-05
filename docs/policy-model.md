# 规则与策略模型

## 1. 决策

当前版本尚未实现 DSL，也不使用 Rego。已交付规则使用受信任的 Python 类；YAML 只负责选择
Registry 中的规则、配置参数、阶段和动作。ADR-0007 已接受双轨 Policy 方向：Event/Analyzer 稳定
后增加受限表达式策略，但不得生成 Python 或获得 I/O 能力。

当前实现状态（2026-08-06）：公共模型、Rule/Detector Protocol、显式 Registry、严格 YAML
Loader、Engine 聚合、错误/超时策略、Detector Cache、Secret Detector、基础 PII Detector、
`secret_exfiltration`、`pii_exfiltration`、`tool_access` 和 `tool_result_flow` Rule 已实现。
前三个 Rule 都支持 `post_llm` 检查模型生成的 ToolCall 和 `pre_tool` 检查实际工具执行；
`tool_result_flow` 在 `pre_tool` 查询可信来源边。其余内置规则仍按路线图逐步增加。

Core 主边界现为：

```python
class PolicyAnalyzer(Protocol):
    async def analyze_pending(self, pending: PendingTrace) -> Decision: ...
```

`GuardrailEngine` 和 `GuardrailRuntime` 都实现该语义。Decision v2 同时绑定 primary Event 与完整
`pending_event_ids`；Violation 绑定实际命中的 pending Event。只匹配 committed past 的条件不能
作为当前新增违规重复报告。

```text
Python Rule implementation
          ▲
          │ registry lookup
          │
Validated YAML Policy
```

## 2. 核心协议

当前 Built-in Python Rule 协议：

```python
class Rule(Protocol):
    id: str
    phases: frozenset[Phase]

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]: ...
```

`RuleServices` 当前只提供带超时和单次批次分析缓存的 Detector 调用。Engine 为每个 pending Event
建立 `GuardrailContext` Rule 视图；其中 Trace 包含 committed past 和同批次更早的 Event。Rule
通过 `by_id`、`find`、`previous`、`count`、`events_since`、`sources_of` 和 `ancestors_of` 查询历史
及关系，不接触 Gateway 或 Tool Executor。Detector evidence 可能包含 event identity，因此缓存虽然
在批次中共享，key 仍包含 Event ID/Phase，不能跨 Event 错配证据。

## 3. 配置模型

示例：

```yaml
version: 1

engine:
  default_timeout_ms: 1000
  on_rule_error: block

rules:
  - id: prevent-secret-email
    type: secret_exfiltration
    enabled: true
    action: block
    phases: [post_llm, pre_tool]
    config:
      tools: [send_email]
      text_arguments: [subject, body]
```

配置加载规则：

1. 使用 Pydantic 严格校验，未知字段报错。
2. `type` 必须存在于本地 Rule Registry。
3. 每种 Rule 拥有独立的 Config Model。
4. 外部配置不能提供 Python 模块路径或 import 字符串。
5. Policy 只有在完整校验并构造所有 Rule 后才返回，不能部分加载；当前尚无运行时替换/热加载。
6. 加载结果包含 policy version 和内容哈希。

## 4. Action 与聚合

MVP Action：

- `allow`：继续执行；通常表示没有违规，也允许显式配置为仅产生 Violation 而不阻断。
- `log`：记录 Violation，继续执行。
- `block`：拒绝当前副作用。

一次 pending batch 可以在多个 Event 上命中多条规则。最终动作按严重度聚合：

```text
block > log > allow
```

所有 Violation 都返回，不能只保留第一条；但应设置最大数量避免恶意输入造成响应膨胀。

未来的 `redact` 不属于普通 Decision Action。它需要可验证的 Transformation Pipeline，
不能简单加入严重度枚举。

## 5. Detector 协议

```python
class Detector(Protocol):
    name: str
    version: str

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]: ...
```

Detection 当前 Schema 包含：

- `type`
- 可选的 `start/end` 和对象路径；当前内置文本 Detector 设置 span，RuleServices 可附加 path
- `confidence`
- 脱敏证据
- Detector 版本

同一检查中，相同 Detector + 相同内容哈希必须复用结果。

## 6. 内置规则现状与路线

当前已实现：

- Tool Allowlist / Denylist：`tool_access`。
- Secret 外发阻断：`secret_exfiltration`。
- 基础 PII 外发阻断：`pii_exfiltration`。
- ToolResult 来源流向限制：`tool_result_flow`。
- Secret 检测：`secrets`。
- 基础 PII 检测：`pii`。

`tool_access` 使用一个明确模式，不能同时配置 allowlist 和 denylist：

```yaml
- id: restrict-tools
  type: tool_access
  enabled: true
  action: block
  phases: [post_llm, pre_tool]
  config:
    mode: allowlist
    tools: [get_weather, search_docs]
```

`allowlist` 阻止列表之外的 Tool；`denylist` 阻止列表中的 Tool。`tools` 必须非空、名称唯一且
不得包含首尾空白。Violation 只记录 Tool 名称指纹和模式，不记录原始 Tool 名称或参数。

`tool_result_flow` 使用来源 Tool 和目标 Tool 两个显式集合：

```yaml
- id: prevent-private-file-email
  type: tool_result_flow
  enabled: true
  action: block
  phases: [pre_tool]
  config:
    source_tools: [read_private_file]
    destination_tools: [send_email]
```

它只在当前 ToolCall 的直接或传递祖先中存在配置的 ToolResult，且该 ToolResult 直接引用一个
`call_id`/名称一致的来源 ToolCall 时命中。更早出现过同名 ToolResult 但没有来源边时必须允许；
这条 Rule 限制来源路径，不检查两个 payload 是否包含相同字节，也不是通用 taint engine。
Violation 只保存匹配的 Event ID 和 Tool 名称指纹。

`pii_exfiltration` 显式选择目标 Tool、参数和实体类型：

```yaml
- id: prevent-selected-pii-email
  type: pii_exfiltration
  enabled: true
  action: block
  phases: [post_llm, pre_tool]
  config:
    tools: [send_email]
    text_arguments: [subject, body]
    entities:
      - email_address
      - phone_number
      - us_ssn
      - credit_card
      - cn_resident_id
      - cn_mobile_phone
```

当前 `pii` Detector 是零额外依赖的本地确定性基线，只支持上述六类实体：

- `email_address`：结构化 ASCII 邮箱形状。
- `phone_number`：常见北美分隔格式。
- `us_ssn`：带一致空格或连字符、排除明显非法分组的美国 SSN。
- `credit_card`：13～19 位并通过 Luhn 的卡号形状。
- `cn_resident_id`：18 位中国大陆居民身份证号；校验大陆省级地址码、真实日历日期和
  [GB 11643-1999](https://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D75D5FD3A7E05397BE0A0AB82A)
  MOD 11-2 校验码。
- `cn_mobile_phone`：可带 `+86`/`86`，支持连续 11 位或一致空格/连字符分组的大陆手机号形状；
  国家码和号码结构参考工信部[《电信网编号计划（2017年版）》](https://www.miit.gov.cn/jgsj/xgj/wjfb/art/2020/art_eb0adf5b6e7148cbb70802b264878b1e.html)。

`cn_resident_id` 不查询真实签发状态，也不维护完整县级历史行政区划；`cn_mobile_phone` 使用较宽的
`1[3-9]` 前缀以避免把会变化的运营商号段硬编码成事实，不查询当前分配或号码归属。Detector 不会
检测姓名、地址、护照、医疗信息或依赖上下文的标识符，不能作为完整 PII 合规产品。Detection 中
不保存原始值，也不对低熵原值直接做可枚举哈希；其 fingerprint 由
trace/event/phase/type/span 生成，只用于定位同一事件中的 detection occurrence。

这一拆分与本地参考实现的业界模式一致：Invariant 的 `pii` predicate 通过可选 Presidio Detector
返回实体类型和范围，再由 Policy 判断；NeMo Guardrails 提供 Presidio/GLiNER 等 PII Rail，并将
检测/掩码应用到 input、output 或 retrieval。当前项目只借鉴 Detector 与 Policy 分离、实体过滤和
边界短路，不复制 DSL、动态 Action 加载、模型/远程依赖或自动掩码 Transformation。

### v0.1

- Tool Allowlist / Denylist（已实现）
- Tool 参数长度与数值范围（未实现）
- 外部域名限制（未实现）
- 单任务 Tool 调用次数限制（未实现）
- Secret 外发阻断（已实现）
- 基础 PII 外发阻断（已实现）
- 单 Session ToolResult 来源流向限制（已实现）

### v0.2

- 文件路径访问限制
- Shell 危险命令
- 用户确认要求
- 工具输出 Secret/PII 进入下一轮模型前阻断
- Prompt Injection 信号与高风险 Tool 的组合规则

### v0.3+

- 租户/用户属性规则
- 预算与速率规则
- MCP 工具来源约束
- 受控 Expression Policy（CEL 与安全改造 Invariant Interpreter 待真实样例验证）

## 7. 当前 Trace 查询与未来表达式边界

当前版本不提供 `a -> b` 文本语法。Built-in Rule 通过受控 API 查询历史：

```python
context.trace.previous(kind=EventKind.TOOL_RESULT)
context.trace.count(tool_name="send_email")
context.trace.find(kind=EventKind.TOOL_CALL, source_event_id="evt-123")
context.trace.events_since("evt-123")
context.trace.sources_of(context.event)
context.trace.ancestors_of(context.event, kind=EventKind.TOOL_RESULT)
```

`by_id` 返回一个 Event 或 `None`；`find` 与其他集合查询保持原 Trace 顺序；`events_since` 对未知
ID 报错；`sources_of` 只解析直接边，`ancestors_of` 解析传递祖先。`has_user_confirmation` 和独立
任务边界当前没有实现，不能在 Rule 中假设存在。

当前来源保存在类型化 Relation：

```python
event.relations == (EventRelation(source_event_id="evt-123", kind=RelationKind.DERIVED_FROM),)
```

`Event.source_event_ids` 从 Relation 计算，只用于兼容现有查询。Enforcement 调用方必须使用
`EnforcementSession.evaluate(..., source_event_ids=(...))`；Session 把可信 ID 转换为
`derived_from` Relation，并拒绝普通 metadata 中的 `source_event_ids` 键。每个 ID 必须指向同一
Trace 中更早、已提交且不是 `guardrail_decision` 的 Event。Trace 构造和 append 也执行相同的
向后引用约束，因此来源图无环。直接调用 Core `/v1/evaluate` 的调用方本来就提交完整 Canonical
Context，该接口只能评估调用方提供的关系，不能把它提升为服务端观察到的 Enforcement 事实。

当前自动记录的关系是：

- Inline 与 OpenAI Gateway：同一边界的 `ModelRequest → ModelResponse`。
- Inline 与 MCP Gateway：同一边界的 `ToolCall → ToolResult`。
- 共享 Inline Session：只有 ModelResponse 中存在完全相同的 Canonical ToolCall 时，才记录
  `ModelResponse → ToolCall`。
- 共享 Inline Session：只有 Tool 消息的 `tool_call_id` 和规范化内容都与历史 ToolResult 精确
  一致时，才记录 `ToolResult → ModelRequest`。

匹配不完整或格式不同会选择不建边，避免伪造因果关系。来源关系目前只在单个内存 Session 内有效；
LLM/MCP Gateway 不跨 HTTP 请求合并 Trace。它也不是内容哈希污点传播，不能仅凭时间先后声称精确
数据流。

`CandidateEvent` 可以通过 `CandidateRelation` 引用已提交 Event 或同批次更早 Candidate；Session
解析为真实 Event ID 后再构造 `PendingTrace`。关系不能引用未来 Candidate、未知 Event 或 Decision
Event。Sequence 仍只表示顺序，表达式引擎也不得把它自动解释成 provenance。

## 8. 策略错误语义

配置支持：

```yaml
engine:
  on_rule_error: block
  on_detector_timeout: block
```

当前错误动作是 Policy 全局配置，不支持按 Phase 分别设置；默认值如下：

| 情况 | 当前默认策略 |
|---|---|
| Rule 异常或超时 | `on_rule_error: block` |
| Detector 超时 | `on_detector_timeout: block` |
| AuditSink 异常 | fail-open；Session 记录安全的异常类型 |

错误必须形成系统 Violation，不能伪装成普通业务规则命中。

## 9. 策略生命周期

```text
读取 YAML
  → Schema 校验
  → Registry 解析
  → Rule Config 校验
  → 构建不可变 PolicySet
  → 计算 version/hash
  → 返回完整 PolicySet
  → 构造 GuardrailEngine/GuardrailRuntime
```

未来策略热加载必须保留最近一个有效版本，并在新版本失败时继续使用旧版本并告警。

## 10. 表达式引擎选择门槛

ADR-0007 已确认需要 Sandboxed Expression Policy，但尚未确认 CEL 是最终实现。开始实现前必须：

- 固定独立 Message/ToolCall/ToolResult 和 PendingTrace Schema。
- 收集覆盖事件量化、变量绑定、Relation 遍历和 Detector 调用的真实 Invariant 风格策略样例。
- 验证 CEL 是否能直接表达这些语义，而不是把主要策略隐藏进复杂 Python 宿主函数。
- 对比安全改造 Invariant Parser/AST/Interpreter 的许可证、维护面和错误定位能力。
- 定义 AST 深度、求值步数、图遍历节点数、超时、输出数量与 fail-closed 语义。
- 覆盖未知字段/函数、类型错误、资源耗尽和恶意表达式测试。

在表达式轨道交付前，现有 YAML + Built-in Python Rule 继续作为功能完整的可信底层轨道；不要再为
每个仅由已有事件查询与 Detector 组合而成的业务条件无限增加专用 Rule，优先把样例纳入表达式
技术验证集。
