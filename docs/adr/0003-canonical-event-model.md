# ADR-0003：Canonical Event Model

- 状态：Accepted
- 日期：2026-08-04

## 背景

OpenAI、Anthropic、Agent Framework 和 MCP 的消息、工具调用结构不同。如果 Rule 直接依赖
供应商格式，规则将无法复用，Gateway 与 Inline Adapter 也会产生不同判断。

## 决策

- 所有输入在进入 Engine 前转换为 Canonical Event。
- Core Rule 只能依赖 Canonical Model。
- Provider/Framework Adapter 负责双向转换。
- Canonical phases 固定为 pre_llm、post_llm、pre_tool、post_tool。
- 原始 Provider 数据只能放在受限 metadata 中，Rule 不应默认读取。
- Event、Decision 与 Violation 模型版本化。

## 结果

优点：

- 同一 Policy 可跨 Inline、Gateway 和 MCP 使用。
- Rule 测试不需要真实 Provider。
- 格式兼容问题集中在 Adapter。

代价：

- 转换可能丢失 Provider 特有字段。
- Canonical Model 的早期设计需要谨慎演进。
- Adapter 需要契约 fixture。
