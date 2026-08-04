# 规则与策略模型

## 1. 决策

MVP 不设计 DSL，也不使用 Rego。规则使用受信任的 Python 类实现；YAML 只负责选择
Registry 中的规则、配置参数、阶段和动作。

当前实现状态（2026-08-04）：公共模型、Rule/Detector Protocol、显式 Registry、严格 YAML
Loader、Engine 聚合、错误/超时策略、Detector Cache、Secret Detector 和
`secret_exfiltration` Rule 已实现。该规则同时支持 `post_llm` 检查模型生成的 ToolCall 和
`pre_tool` 检查实际工具执行。其余内置规则仍按路线图逐步增加。

```text
Python Rule implementation
          ▲
          │ registry lookup
          │
Validated YAML Policy
```

## 2. 核心协议

当前公共协议：

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

`RuleServices` 当前只提供带超时和单次评估缓存的 Detector 调用。Rule 通过
`GuardrailContext.trace` 使用现有 `previous`/`count` 查询历史；不会接触 Gateway 或 Tool
Executor。

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

一次检查可以命中多条规则。最终动作按严重度聚合：

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

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]: ...
```

Detection 至少包含：

- `type`
- `start/end` 或对象路径
- `confidence`
- 脱敏证据
- Detector 版本

同一检查中，相同 Detector + 相同内容哈希必须复用结果。

## 6. 内置规则现状与路线

当前已实现：

- Secret 外发阻断：`secret_exfiltration`。
- Secret 检测：`secrets`。

### v0.1

- Tool Allowlist / Denylist（未实现）
- Tool 参数长度与数值范围（未实现）
- 外部域名限制（未实现）
- 单任务 Tool 调用次数限制（未实现）
- Secret 外发阻断（已实现）
- 基础 PII 外发阻断（未实现）

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
- 受控 CEL 表达式（仅在真实需求满足 ADR 条件时）

## 7. Trace 查询而非数据流 DSL

不提供 `a -> b` 语法。Rule 通过受控 API 查询历史：

```python
context.trace.previous(kind=EventKind.TOOL_RESULT)
context.trace.count(tool_name="send_email")
```

`has_user_confirmation`、`events_since` 和独立任务边界当前没有实现；需要时先扩展 Canonical Model
和测试，不能在 Rule 中假设这些 API 已存在。

如果需要“内容是否从 A 流到 B”，MVP 只支持明确来源标签：

```python
event.metadata["source_event_ids"] = ["evt-123"]
```

不能仅凭时间先后声称精确数据流。

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

## 10. 何时引入 CEL

同时满足以下条件时再评估 CEL：

- 非开发人员确实需要动态条件。
- Python 规则发布周期成为瓶颈。
- 必须安全执行非可信策略表达式。
- Event Model 已稳定。
- 有覆盖表达式兼容性和资源限制的测试。

在此之前，新增需求通过 Python Rule + YAML Config 实现。
