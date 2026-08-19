# 文档导航

项目公开介绍：[English](../README.md) | [简体中文](../README.zh-CN.md)。贡献代码前请先阅读
[公开贡献指南](../CONTRIBUTING.md)。

不要顺序阅读整个目录。先选一条路径，读到能完成当前任务就停止。

## 第一次了解项目

```text
当前架构合同 → 架构概览 → 安全模型
```

- [当前架构合同](current-architecture-contract.md)：当前事实和不可破坏约束。
- [架构概览](overview.md)：从 Event、Policy 到 Enforcement 的完整主线。
- [安全模型](security-model.md)：资产、信任边界、T01–T10，以及 Guardrail/Sandbox 责任矩阵。

## 编写 Policy

```text
Policy 作者指南 → Capability 参考
```

- [Policy 作者指南](guides/policy-authoring.md)：v3 YAML、Rule、Finding、action 和安全参数。
- [Capability 参考](reference/capabilities.md)：内置 Predicate/Detector 与可信执行边界。
- [Capability 状态矩阵](capability-status.yaml)：唯一交付状态来源。

## 接入和运行

```text
接入指南 → Gateway 协议 / 运行指南
```

- [Agent 与 Enforcement 接入](guides/integration.md)：直接 Detector SDK、Event/Policy SDK、Runtime、Session、
  Inline、Model Provider/Streaming 和 MCP。
- [Gateway 协议参考](reference/gateway-protocol.md)：端点、映射、生命周期和错误。
- [Gateway 运行指南](guides/operations.md)：启动、Agent Sandbox 部署边界、环境变量、Secret、Audit 和 Health。
- [Remote Core 双容器设计](design/remote-core-deployment.md)：Core/Gateway 责任、协议与失败边界。
- [Prompt injection Detector 评测](../evals/prompt_injection/README.md)：不调用 Agent/LLM 的锁定公开数据回归。
- [策略决策点 detection 评测](../evals/detection/README.md)：按能力轴 replay trace，对 Policy 输出分轴混淆矩阵。
- [第三方语料生成环境](../evals/corpus/README.md)：固定 agentdojo 版本，再生成 release 轴的外部注入语料与
  full_deberta 剖面运行环境。

## 修改 Core

```text
当前架构合同 → 分析引擎参考 → 开发指南
```

- [分析引擎参考](reference/analysis-engine.md)：MatchPlan、Matcher、Monitor、Finding 和预算。
- [开发与代码阅读指南](contributing.md)：代码地图、测试、review 和质量门。
- [Invariant 对齐基线](design/invariant-alignment.md)：I01–I14 映射和有意差异。
- [Invariant Detector 对齐合同](design/invariant-detector-alignment.md)：算法映射、固定 backend 和脱敏边界。

## 治理与规划

- [Roadmap](roadmap.md)：唯一未来工作清单。
- [当前架构合同](current-architecture-contract.md)：唯一架构事实与文档治理规则；历史变更只通过 Git 追溯。
