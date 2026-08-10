# MatchPlan 可读策略作者格式

> 状态：严格 YAML / 类型化 Python 作者模型与 `MatchPlan v1` 编译器已实现；v3 生产 Policy 复用同一
> 作者 Schema 和编译器，并额外保存 action/failure mapping。
> 架构依据：[ADR-0010](adr/0010-invariant-aligned-policy-monitor.md)和
> [ADR-0011](adr/0011-matchplan-production-cutover.md)。

## 1. 两种表示，一个执行语义

作者格式负责可读性，`MatchPlan` 负责执行。`load_match_plan_yaml()` 的固定流水线是：

```text
strict YAML
  -> AuthorPolicy Schema
  -> predicate 引用/环与参数检查
  -> 编译期 predicate 展开
  -> immutable MatchPlan v1
  -> 部署方显式 Registry capability 编译（Plan 含能力节点时）
  -> SnapshotMatcher / MatchMonitor
```

YAML 不会直接被解释，也不会生成 Python。类型化 Python API 构造相同的 `AuthorPolicy` 对象，并调用
相同的 `compile_author_policy()`；它不是绕过 Schema、静态引用检查或 MatchPlan 预算的第二套执行器。

纯分析作者格式与生产 Policy 是两个入口、一个 IR：

| 入口 | 输出 | 当前用途 |
| --- | --- | --- |
| `load_policy_yaml(..., detectors=..., predicates=...)` | `CompiledPolicy` | 当前 v3 Gateway Enforcement |
| `load_match_plan_yaml(...)` | `MatchPlan` | 通用 snapshot/Monitor 低层分析 |

生产根版本是 `3`，纯作者格式版本是 `1`；二者不会互相降级解析。

## 2. 完整示例

下面的规则没有 mandatory anchor。`output` 和 `call` 是两个平等的命名 Event binding；关系、工具名称
和 Detector 都是显式条件：

```yaml
version: 1
scopes: [snapshot, pending]

predicates:
  is_website_output:
    parameters: [event]
    where:
      tool: {binding: event, name: get_website}

rules:
  - id: website_injection_to_email
    events:
      output: {kind: tool_result, domain: past}
      call: {kind: tool_call, domain: pending}

    where:
      all:
        - use:
            name: is_website_output
            arguments:
              event: {binding: output}
        - relation:
            source: output
            target: call
            operator: derived_from_ancestor
        - detector:
            id: injection
            capability: prompt_injection
            inputs:
              - value: {field: [output, payload, output]}
                encoding: canonical_json
            types_any: [prompt_injection]
        - tool: {binding: call, name: send_email}

    finding:
      code: website_injection_to_email
      message: Do not send website-derived content by email
      subjects: [call]
      evidence:
        - {source: detector, id: injection}
```

编译结果中的 `use` 和 predicate 定义已经消失，只剩封闭的 MatchPlan 条件树。部署方必须再用显式
Registry 调用 `compile_match_plan_capabilities()`；未注册 `prompt_injection` 会在该步原子拒绝，不会被
解释成不匹配。若直接把未编译的纯 Plan 交给 Matcher，则返回固定的 `capability_error`。

## 3. 顶层与 Rule

顶层字段全部封闭：

- `version: 1`：必填的作者格式版本；
- `scopes`：`snapshot`、`pending` 或二者，默认 `[snapshot]`；
- `limits`：MatchPlan 的分析级分项预算；
- `parameters`：可信调用方提供的只读、严格标量参数；
- `predicates`：只由本格式条件组成的可复用声明式 predicate；
- `rules`：零到 100 条 Rule。

每条 Rule 包含：

- `events`：1–8 个命名 Event binding；支持独立 `message/tool_call/tool_result`，以及
  `visible/past/pending` domain、合法 Phase 和 origin 过滤；
- `derive`：当前只允许白名单纯操作 `split_lines`；
- `collections`：从字段或派生值有界展开数组；
- `where`：一个封闭条件树；
- `finding`：静态、默认脱敏的输出模板；
- `limits`：只能降低顶层预算，不能提高。

`events` 和 `collections` 的命名本身就是 Rule 的 top-level binding 声明，不再需要 `anchor` 或单独的
`bindings` 样板：

```yaml
events:
  source: {kind: tool_result, domain: past}
  destination: {kind: tool_call, domain: pending}
```

Matcher 对多个 Event binding 枚举有方向的命名笛卡尔积。不同对象、顺序和来源都必须写进 `where`，
不能从变量排列或 YAML 顺序中推断。

## 4. 值、条件和语法糖

一个值引用只能有一种来源：

```yaml
{field: [message, payload, content, text]} # 首段是 binding，之后是静态安全路径
{binding: outgoing_mail}                  # 整个 Event 或 collection item
{derived: lines}                          # 已声明的派生值
{parameter: principal}                    # 可信 Policy 参数
{literal: blocked}                        # 严格标量、标量数组或 null
```

`where` 每个节点也只能有一种操作：

- `all`、`any`、`not`；
- `compare`：`equals/not_equals/in/not_in/contains/not_contains`；
- `present`：显式区分字段不存在与 `null`；
- `relation`：`precedes/immediately_precedes/may_influence` 或
  `derived_from_direct/derived_from_ancestor`；
- `tool`：可读语法糖，编译为 `binding.payload.name == literal`；
- `predicate` / `detector`：可信 Registry capability 节点；
- `use`：调用声明式 predicate，只在编译期存在；
- `quantify`：对一个局部 Event 或 collection binding 执行有界 `exists/forall/count`。

`precedes` 只描述 snapshot 顺序，`may_influence` 只描述“可能可见”；二者都不会创建或证明 provenance。
精确数据来源只能查询 Canonical `Event.relations` 中已经存在的 `derived_from` 边。

## 5. 声明式 predicate

声明式 predicate 是条件树的具名宏，不是可上传代码：

```yaml
predicates:
  contains_text:
    parameters: [message, needle]
    where:
      compare:
        left: {field: [message, payload, content, text]}
        operator: contains
        right: {binding: needle}

rules:
  - id: example
    events:
      message: {kind: message}
    where:
      use:
        name: contains_text
        arguments:
          message: {binding: message}
          needle: {literal: blocked}
    finding:
      code: blocked_text
      message: Message contains blocked text
      subjects: [message]
```

predicate 参数是词法占位符：可以作为 `{binding: parameter_name}` 使用，也可以作为 field 路径的首段。
编译器要求实参与形参精确一致，验证全部定义（包括没有被 Rule 使用的定义），拒绝未知引用、直接/间接
递归、参数错配和量词遮蔽，然后递归内联。MatchPlan 中不存在用户定义函数、动态调用栈或 predicate
callback，因此该能力不会增加运行时可执行权限。

需要代码的算法不是声明式 predicate。它必须由部署所有者实现为受信任 capability，经过 descriptor
编译合同限制输入编码、成本、timeout 和脱敏输出；YAML 只能选择 descriptor 公布的名字。

## 6. Finding 与 evidence

`finding.message` 是静态文案，不能插入 Event、参数或 Detector 原值。`subjects` 只能引用 top-level
Event binding。编译器自动把全部 top-level Event 和 collection binding 投影进 Finding；可选
`finding.bindings` 只列额外的派生值或 Policy 参数，不能重复自动项。

`compare.id`、`predicate.id` 和 `detector.id` 创建命名、类型化的 evidence source；`finding.evidence`
必须以相同的 `source + id` 引用。Matcher 的字符串 range evidence 可以选择固定
`masked_evidence`。原始匹配文本不会进入 Finding。

## 7. Python 作者 API

应用代码可以直接构造严格类型对象：

```python
from agent_guardrail.core.authoring import (
    AuthorComparison,
    AuthorCondition,
    AuthorEventSpec,
    AuthorFinding,
    AuthorPolicy,
    AuthorRule,
    AuthorValue,
    compile_author_policy,
)
from agent_guardrail.core.match_plan import ComparisonOperator
from agent_guardrail.models import EventKind

policy = AuthorPolicy(
    version=1,
    rules=(
        AuthorRule(
            id="blocked_message",
            events={"message": AuthorEventSpec(kind=EventKind.MESSAGE)},
            where=AuthorCondition(
                compare=AuthorComparison(
                    left=AuthorValue(field=("message", "payload", "content", "text")),
                    operator=ComparisonOperator.CONTAINS,
                    right=AuthorValue(literal="blocked"),
                )
            ),
            finding=AuthorFinding(
                code="blocked_text",
                message="Message contains blocked text",
                subjects=("message",),
            ),
        ),
    ),
)
plan = compile_author_policy(policy)
```

Python 作者 API 可以使用应用自身的普通代码决定组装哪些严格对象，但编译后的 Rule 仍只能包含
MatchPlan 白名单节点；对象模型没有 callback、module path、import、I/O 或 handler 字段。

## 8. 加载与安全边界

```python
from agent_guardrail.config import load_match_plan_file, load_match_plan_yaml

plan = load_match_plan_file("policy.match.yaml")
plan = load_match_plan_yaml(source)
```

Loader 在返回任何 Plan 前原子执行以下检查：

1. 拒绝 duplicate mapping key、YAML anchor/alias 和显式 tag；
2. 拒绝非 mapping 根、缺失/未知版本、未知字段和宽松类型转换；
3. 验证符号唯一性、字段路径、Event/Phase、作用域和 Finding 引用；
4. 验证 predicate 调用图并内联；
5. 由 `MatchPlan` 再验证条件深度/数量、量词深度、预算降额和全部静态引用。

错误消息不包含 YAML 输入值。整个文件通过后才产生一个不可变 MatchPlan；没有部分 Rule 激活。

当前仍未实现：

- 高层 Policy/Monitor 门面自动计算 Policy hash、持有参数和生命周期；
- Finding → Decision/failure action 适配与 Gateway 接入；
- Built-in Rule 迁移、双轨引用审计和遗留清理。

在这些步骤完成前，不能让同一生产策略同时经过旧解释器和 MatchPlan 产生重复 Decision。
