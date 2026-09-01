# 文档导航

项目公开介绍：[English](../README.md) | [简体中文](../README.zh-CN.md)。贡献代码前请先阅读[公开贡献指南](../CONTRIBUTING.md)。

文档按使用场景组织；当前实现以[当前架构合同](current-architecture-contract.md)和代码为准，能力交付状态以[状态矩阵](capability-status.yaml)为准。

## 了解系统

```text
当前架构合同 → 架构概览 → 安全模型
```

- [当前架构合同](current-architecture-contract.md)：当前事实和不可破坏约束。
- [架构概览](overview.md)：从规则文件到检查决定的完整流程，并说明对应代码对象。
- [安全模型](security-model.md)：保护对象、信任边界、T01–T10，以及 Guardrail 与沙箱的责任分工。

## 编写规则

```text
规则编写指南 → 检测能力参考
```

- [规则编写指南](guides/policy-authoring.md)：version-3 YAML 规则、条件、命中结果和安全参数。
- [检测能力参考](reference/capabilities.md)：内置检测和条件判断，以及注册和执行边界。
- [检测能力状态矩阵](capability-status.yaml)：各项能力的唯一交付状态来源。

## 接入与运行

```text
应用接入指南 → Gateway 协议 / 运行指南
```

- [应用接入指南](guides/integration.md)：在 Python 应用中提交检查内容、事件和工具调用。
- [Gateway 协议参考](reference/gateway-protocol.md)：模型服务和 MCP 工具的 HTTP 接口、请求流程和错误。
- [Gateway 运行指南](guides/operations.md)：启动服务、配置检测能力、管理凭据和部署安全边界。
- [Core 与 Gateway 独立部署设计](design/remote-core-deployment.md)：分析服务和 Gateway 的职责、协议与失败处理。
- [提示注入检测效果评估](../evals/prompt_injection/README.md)：固定语料上的检测指标和阈值评估。
- [第三方语料生成环境](../evals/corpus/README.md)：固定 AgentDojo 版本并生成提示注入攻击载荷。

## 修改规则分析代码

```text
当前架构合同 → 分析引擎参考 → 开发与代码阅读指南
```

- [分析引擎参考](reference/analysis-engine.md)：规则检查计划、匹配器、命中结果和预算。
- [开发与代码阅读指南](contributing.md)：代码地图、测试、review 和质量门。
- [Invariant 规则语义对照](design/invariant-alignment.md)：I01–I14 语义对照和生产测试边界。
- [Invariant 检测能力对照](design/invariant-detector-alignment.md)：算法对照、固定后端和脱敏边界。

## 规划与维护

- [开发路线图](roadmap.md)：后续工作顺序和产品范围。
- [当前架构合同](current-architecture-contract.md)：当前架构事实、不可破坏约束和文档治理规则。
