# Policy 作者指南

> 适合谁：编写生产 v3 Policy 或可信 Python AuthorPolicy 的人。
> 解决什么：Rule、binding、条件、Finding、action、参数和加载边界。
> 不包含什么：Matcher 内部枚举和 capability 实现细节。

## 1. 一种执行语义

生产入口：

```text
strict version: 3 YAML
  → PolicyDocument
  → AuthorPolicy
  → immutable MatchPlan
  → capability linking
  → CompiledPolicy
```

独立 SDK 还可用 `version: 1` 作者 YAML 或类型化 Python `AuthorPolicy` 生成 action-free MatchPlan。所有入口
复用同一个 `compile_author_policy()`；Python API 不能绕过 Schema、引用校验或预算。

## 2. 完整生产示例

```yaml
version: 3

engine:
  max_violations: 100
  on_analysis_error: block
  on_detector_timeout: block

scopes: [pending]

rules:
  - id: prevent-secret-email
    action: block
    events:
      call:
        kind: tool_call
        domain: pending
        phases: [post_llm, pre_tool]
    where:
      all:
        - tool: {binding: call, name: send_email}
        - detector:
            id: secret_scan
            capability: secrets
            inputs:
              - value: {field: [call, payload, arguments]}
                encoding: canonical_json
    finding:
      code: secret_exfiltration
      message: The tool call contains secret material.
      subjects: [call]
      evidence:
        - {source: detector, id: secret_scan}
```

Rule 的 Event 名称都是普通 binding，没有保留 `anchor`。多个 binding 平等选择 `visible/past/pending`，
不同对象、顺序和来源必须在 `where` 中显式表达。

## 3. 顶层与 Rule

生产顶层字段：

- `version: 3`；
- `engine`：最大 Violation 和分析/Detector timeout 失败动作；
- `scopes`：生产必须包含 `pending`；
- `parameters`：可信只读参数声明；
- `predicates`：编译期内联的声明式 predicate；
- `limits`：分析级分项预算；
- `rules`：Event、derive、collection、条件、Finding、action 和可降低预算。

每条 Rule 最多声明有限数量的：

- `events`：`message/tool_call/tool_result` 与 phase/origin/domain filter；
- `derive`：当前白名单纯操作只有 `split_lines`；
- `collections`：从字段或派生结果展开有界数组；
- `where`：封闭条件树；
- `finding`：静态输出模板；
- `action`：生产 `allow/log/block`；
- `limits`：只能降低顶层预算。

## 4. 值与条件

值引用只能有一个来源：

```yaml
{field: [message, payload, content, text]}
{binding: outgoing_mail}
{derived: lines}
{parameter: principal}
{literal: blocked}
```

条件节点包括：

- `all/any/not`；
- `compare`：`equals/not_equals/in/not_in/contains/not_contains`；
- `present`：区分字段缺失和存在但为 null；
- `relation`：顺序、保守影响或 direct/ancestor 精确来源；
- `tool`：工具名比较语法糖；
- `predicate/detector`：可信 Registry capability；
- `use`：只在编译期存在的声明式 predicate 调用；
- `quantify`：有界 `exists/forall/count` 与 lexical local binding。

缺失字段和不适用类型不是 Python 异常，也不会因为外层 `not` 自动变成命中。需要区分缺失时必须使用
`present`。

## 5. 声明式 predicate

声明式 predicate 是条件宏，不是代码：

```yaml
predicates:
  contains_text:
    parameters: [message, needle]
    where:
      compare:
        left: {field: [message, payload, content, text]}
        operator: contains
        right: {binding: needle}
```

编译器验证未知引用、实参、递归、环和词法遮蔽，再完全内联；MatchPlan 中不会残留动态调用。

## 6. Finding、action 与错误

Finding 的 `code/message` 必须是静态文本。subject 必须引用顶层 Event binding；evidence 只能投影已声明
comparison、Predicate 或 Detector 的安全结果。Event 原值、参数值和 Detector 原文不能进入 Finding。

MatchPlan 不保存 action。生产 `CompiledPolicy` 单独保存 Rule action，Analyzer 在完整匹配后聚合
`block > log > allow`。`max_violations` 只截断报告，不提前停止 Matcher，因此较晚的 block 不会被较早
log 掩盖。

`detector_timeout` 使用 `on_detector_timeout`，其他 AnalysisError 使用 `on_analysis_error`。错误没有具体
Event 时绑定整个 pending batch；错误文本不得包含输入或实现异常原文。

## 7. 安全参数

生产只允许下面五个保留参数读取 `FlowSecurityContext`：

```text
security_trust_class
security_sensitivity
security_owner_scope
security_destination
security_authorization
```

使用时必须声明 `type: string, required: false, default: unknown`。值只来自 Session 专用安全通道；普通
attributes、metadata、HTTP 或 Provider payload 不能覆盖。生产其他参数必须有默认值，因为 Gateway 不接受
客户端注入部署参数。

## 8. 加载与安全边界

Loader 原子拒绝 duplicate key、YAML anchor/alias、显式 tag、未知字段、宽松类型、旧版本、错误引用和
未发布 capability。整个文件通过后才返回不可变 Plan/Policy，不会激活部分 Rule。

Policy 不能声明 Python module/callable、正则代码、handler 或 I/O。新增算法先实现并审查 capability，再由
部署代码注册；外部 YAML 只能引用公开 descriptor 名称。

执行语义见[分析引擎参考](../reference/analysis-engine.md)，capability 参数见
[Capability 参考](../reference/capabilities.md)，安全语境见[安全模型](../security-model.md)。
