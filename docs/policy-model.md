# Policy 与 Rule 模型

## 1. 当前生产合同

生产 Policy 只有 ADR-0011 的 `version: 3` 格式。Loader 完整执行：

```text
strict YAML
  → PolicyDocument v3
  → action-free AuthorPolicy
  → immutable MatchPlan v1
  → trusted capability linking
  → CompiledPolicy
```

任一步失败都不返回部分 Policy。YAML duplicate key、anchor/alias、显式 tag、未知字段、旧版本、动态
Python 字段和不可用 capability 全部拒绝。内容哈希来自补齐默认值后的规范化 v3 文档。

旧 Python Rule/Rule Registry、Structured RulePlan、mandatory anchor、v1/v2 Loader 和 Safe Profile
迁移桥已经删除。

## 2. v3 YAML

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

Rule 的 Event 名称都是普通 binding；没有 `anchor` 保留字。多个 binding 可以平等地选择 past、pending
或全部 visible Event，并通过显式 relation、顺序、字段和 capability 约束组合。

## 3. 作者层与 MatchPlan

作者 YAML 支持：

- typed Event binding 与 `visible/past/pending` domain；
- nested field、presence、严格比较、`all/any/not`；
- `precedes`、`immediately_precedes`、`may_influence`；
- `derived_from_direct/derived_from_ancestor`；
- `split_lines` derive、collection binding、`exists/forall/count`；
- typed parameter 与编译期内联的声明式 predicate；
- descriptor 约束的 Predicate/Detector；
- 静态 Finding、pending subject、binding 和脱敏 evidence；
- 全局 MatchLimits 与只允许降低的 Rule limits。

作者格式编译为唯一可执行 IR `MatchPlan`。Interpreter 不读取作者 Pydantic 对象，也不执行 YAML 中的
字符串表达式。

## 4. Finding 与 action 分离

MatchPlan 内只有 Finding template，不含 Enforcement action。生产 `PolicyRule.action` 单独保存在
`CompiledPolicy.actions`，由 `MatchPolicyAnalyzer` 在 `AnalysisReport → Decision` 时映射。

这样同一个 MatchPlan 可用于：

- `SnapshotMatcher.analyze`：无状态 snapshot 全量 Finding；
- `SnapshotMatcher.analyze_pending`：whole-pending Finding；
- `MatchMonitor`：committed snapshot 的稳定 identity 去重；
- Enforcement：将 pending Finding 投影为 allow/log/block Decision。

## 5. Decision 聚合

Action 严重度固定为：

```text
block > log > allow
```

Matcher 先完整执行所有 Rule，再由 Analyzer 转换结果。`max_violations` 只限制 Decision 报告数量，不
停止 MatchPlan 求值；截断时优先保留高严重度并保持原始稳定顺序，所以较晚出现的 block 不会被较早
log 掩盖。

Finding 只有 pending subject 能成为 Violation `event_ids`。历史 binding 可以帮助解释匹配，但不会
冒充本次待提交 Event。`block` 时整个 pending batch 原始 Event 都不提交。

## 6. 错误模型

Matcher 返回封闭 `AnalysisErrorCode`：resource exhausted、detector timeout、parameter/input、capability
或 internal error。生产映射：

- `detector_timeout` → `engine.on_detector_timeout`；
- 其他错误 → `engine.on_analysis_error`；
- error 没有具体 Event ID 时绑定整个 pending batch；
- 错误消息和元数据不得包含原始 payload。

生产 parameter 必须定义默认值，因为 Gateway 当前不接受客户端覆盖部署参数。通用 SDK 的独立
`load_match_plan_yaml` 仍可生成带 required parameter 的纯 MatchPlan，由可信调用方在分析时显式提供。

## 7. capability

### Detector

默认 Registry 发布：

- `secrets`：常见 Secret/API key 形状；
- `pii`：邮箱、北美电话、美国 SSN、Luhn 卡号、中国大陆身份证和手机号形状。

Descriptor 固定允许编码、检测类型、单次输入字节、deadline、最大结果数和 evidence 策略。Detector
只返回脱敏 Detection fact，不决定 action。

### Predicate

Predicate 是部署方注册的纯、类型化、无 I/O 布尔能力。Descriptor 固定参数类型、输入预算、deadline
和静态 evidence 策略。默认 Predicate Registry 当前为空。

Policy 不能声明 module path 或任意函数调用。需要新算法时，先实现并审查 capability，再由部署代码
显式注册；外部 YAML 只能引用 descriptor 名称。

## 8. 关系语义

`precedes` 只表示可信 sequence 顺序；`may_influence` 是保守可见性；二者都不能证明数据来源。
`derived_from_*` 只查询 Enforcement/Adapter 已写入的类型化 `Event.relations`。

多 Event Rule 示例见 [examples/policies/tool-result-flow.yaml](../examples/policies/tool-result-flow.yaml)。
它同时绑定 source ToolCall、ToolResult 和 destination ToolCall，并要求两条明确来源链；时间顺序本身
不会命中。

## 9. 安全边界与规划

当前不支持 CEL、IPL、Rego、Python Rule 上传、动态 callback、任意正则/反射/I/O 或由 Policy 生成
Violation 文本。新增节点必须具备封闭 Schema、静态类型、成本维度、失败代码、脱敏方案和 I01–I14
相邻样例。

后续规则集包括参数 JSON Schema/范围、外部域名、调用次数、Prompt Injection、URL 和危险命令；它们
应优先用现有 MatchPlan 组合，只有不可表达的算法才增加受信任 capability。
