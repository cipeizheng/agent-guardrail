# 规则编写指南

> 本文说明如何编写 version-3 YAML 规则，并说明规则如何变成代码中的检查计划、命中结果和放行/记录/拦截决定。
> 相关参考：[分析引擎参考](../reference/analysis-engine.md)、[检测能力参考](../reference/capabilities.md)。

## 1. 规则从文件到运行时

生产入口：

```text
strict version: 3 YAML
  → PolicyDocument（校验后的规则文件）
  → AuthorPolicy（用于编译的规则模型）
  → MatchPlan（不可变的检查计划）
  → 能力连接（capability linking：连接已注册的检测能力）
  → CompiledPolicy（规则、动作和能力的完整运行对象）
```

YAML 规则先由 `PolicyDocument` 校验，再由 `compile_author_policy()` 编译为 `MatchPlan`，最后连接部署方提供的检测能力，形成 `CompiledPolicy`。类型化 Python `AuthorPolicy` 也使用同一编译器；它不携带动作，也不能绕过 Schema、引用校验或预算。

## 2. 完整规则示例

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
      message: 工具调用参数包含敏感凭据。
      subjects: [call]
      evidence:
        - {source: detector, id: secret_scan}
```

规则中的事件名称只是本条规则使用的变量名；多个变量可以从 `visible/past/pending` 事件集合中选择对象，不同对象、先后和来源关系都要在 `where` 中明确写出。YAML 不选择模型或工具的执行位置；执行位置由 SDK 调用方或 Gateway 适配器决定。

## 3. 顶层字段和规则

生产顶层字段：

- `version: 3`；
- `engine`：最大违规数，以及分析或检测超时时采用的动作；
- `scopes`：生产必须包含 `pending`；
- `parameters`：可信只读参数声明；
- `predicates`：编译期内联的声明式 predicate；
- `limits`：分析级分项预算；
- `rules`：事件、派生值、集合、条件、命中结果、动作和可降低的预算。

每条规则最多声明有限数量的：

- `events`：`message/model_call/tool_call_proposal/tool_call/tool_result`，以及来源和事件范围筛选；
- `derive`：当前允许的纯操作只有 `split_lines`；
- `collections`：从字段或派生结果展开有界数组；
- `where`：封闭的条件树；
- `finding`：静态的命中结果模板；
- `action`：生产环境中的 `allow/log/block`；
- `limits`：只能降低顶层预算。

## 4. 值引用与条件

值引用只能有一个来源：

```yaml
{field: [message, payload, content, text]}
{binding: outgoing_mail}
{derived: lines}
{parameter: risk_tier}
{literal: blocked}
```

条件节点包括：

- `all/any/not`；
- `compare`：`equals/not_equals/in/not_in/contains/not_contains`；
- `present`：区分字段缺失和存在但为 null；
- `relation`：事件先后，以及显式 `linked_by` 或 direct/ancestor `derived_from` 关系；
- `tool`：工具名比较语法糖；
- `predicate/detector`：可信 Registry capability；
- `use`：只在编译期存在的声明式 predicate 调用；
- `quantify`：有界 `exists/forall/count` 与 lexical local binding。

缺失字段和不适用类型按安全的 false/unknown 语义处理；外层 `not` 不会把它们转换为命中。需要区分缺失时使用 `present`。

规则只能读取事件安全外壳中的 `id/sequence/kind/origin/payload/security_facts`。其中，事件来源可信度可以这样读取：

```yaml
{field: [source, security_facts, trust_class]}
```

它必须与显式 `linked_by/derived_from` 关系组合，才能说明该 source 影响了某个 sink；sequence 先后不能替代 Relation。`trust_authority` 可查询，但 Schema 已先校验非 unknown trust 的 authority，Policy 不应把 authority 名称当作身份或授权凭证。

## 5. 可复用的条件

声明式 predicate 是可以重复使用的条件组合，不是可执行代码：

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

## 6. 命中结果、动作与错误

命中结果的 `code/message` 必须是静态文本。`subject` 必须引用顶层事件变量；`evidence` 只能投影已声明比较、条件判断或检测器的安全结果。事件原值、参数值和检测器原文不能进入命中结果。

`MatchPlan` 不保存动作。生产 `CompiledPolicy` 单独保存规则动作，分析器在完整匹配后按 `block > log > allow` 汇总。`max_violations` 只限制报告中的违规数，不提前停止匹配，因此较晚出现的 block 不会被较早的 log 覆盖。

`detector_timeout` 使用 `on_detector_timeout`，其他 AnalysisError 使用 `on_analysis_error`。错误没有具体 Event 时绑定整个 pending batch；错误文本不得包含输入或实现异常原文。

## 7. 受信安全参数

生产只允许下面四个保留参数读取 `FlowSecurityContext`：

```text
security_trust_class
security_sensitivity
security_destination
security_authorization
```

使用时必须声明 `type: string, required: false, default: unknown`。值只来自 Session 专用安全通道；普通 attributes、metadata、HTTP 或 Provider payload 不能覆盖。生产其他参数必须有默认值，因为 Gateway 不接受客户端注入部署参数。

## 8. 加载校验与安全边界

生产 Loader 原子拒绝 duplicate key、YAML anchor/alias、显式 tag、未知字段、宽松类型、非 `version: 3`、错误引用和未发布 capability。整个文件通过后才返回不可变 CompiledPolicy，不会激活部分 Rule。

Policy 不能声明 Python module/callable、正则代码、handler 或 I/O。新增算法先实现并审查 capability，再由部署代码注册；外部 YAML 只能引用公开 descriptor 名称。

执行语义见[分析引擎参考](../reference/analysis-engine.md)，检测能力参数见[检测能力参考](../reference/capabilities.md)，安全语境见[安全模型](../security-model.md)。
