# ADR-0001：Python Rule + YAML Config

- 状态：Superseded（由 ADR-0011 完全替代）
- 日期：2026-08-04
- 替代范围：受信任 Python Rule 与严格 YAML 配置继续有效；“动态表达式继续暂缓”由 ADR-0007
  的双轨 Policy 决策替代

## 背景

项目需要可配置 Guardrail，但团队不应承担自定义 DSL 的 Parser、AST、解释器、安全沙箱、
错误定位和工具链成本。OPA/Rego 对 MVP 过重，而直接执行外部 Python 不安全。

## 决策

- Rule 由仓库内受信任 Python 类实现。
- Rule 通过显式 Registry 注册。
- YAML 只能选择已注册 Rule，并设置 phases、action 和经过严格校验的 config。
- 不允许 YAML 提供 Python module/class path。
- 不使用 `eval` 或 `exec`。
- 只有出现真实的非可信动态表达式需求后，才通过新 ADR 评估 CEL。

## 结果

优点：

- 使用成熟 Python 工具链。
- 易测试、调试和类型检查。
- 不构建 DSL。
- 外部配置能力受到明确限制。

代价：

- 新 Rule 需要发布代码。
- 非开发人员只能配置已有 Rule。
- 复杂动态条件需要后续表达式方案。
