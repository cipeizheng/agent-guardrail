# 开发路线图

> 本页只记录后续工作顺序和产品范围。当前实现以[当前架构合同](current-architecture-contract.md)为准，能力名称与交付状态以[能力状态矩阵](capability-status.yaml)为准。

## 当前版本已具备的能力

- version-3 YAML 规则会由 `AuthorPolicy` 编译为不可变的 `MatchPlan`，再由 `SnapshotMatcher` 和 `MatchPolicyAnalyzer` 生成决定。
- `GuardrailRun`、OpenAI/Anthropic Gateway 和 MCP Gateway 共用 Event、Trace 与 Enforcement 合同；`DetectorRunner` 与规则匹配器共用 Registry 和检测器执行合同。
- Gateway 为每个模型请求和 MCP `tools/call` 建立独立的请求级 Trace，并限制每条 Trace 的事件数量。
- 流式输出按累计的内部统一格式前缀逐窗口检查；Remote Core 使用版本化 v4 分析协议。

## 后续工作顺序

### P4：长任务与性能

- 增加历史索引、增量 Matcher 和可安全复用的分析结果，降低长任务与流式输出的重复扫描。
- 为长会话和长流建立固定内存、延迟、吞吐和失败边界目标。
- 优化完整请求历史的规范化与重复检测，同时保持 Gateway 请求之间相互隔离。
- 扩展 [Agentic API downstream fork](https://github.com/cipeizheng/agentic-api) 作为 Responses 外部 state owner 的集成测试：当前已有 `Agentic API → Guardrail Gateway → Provider` 的本地跨进程 harness，覆盖 SQLite 重启恢复、完整历史送入 Gateway、function call 续接、SSE 终态续接和 Provider 错误映射；后续测试包括具体 Provider wire compatibility 和容器网络。

### P5：部署工程

- Policy 热加载、原子版本切换和回滚。
- SBOM、镜像签名、发布流水线和集群编排。
- 脱敏 metrics/tracing、SLO、流终止原因和容量可观测性。
- Provider Adapter 的版本/兼容矩阵与真实上游 smoke。

### 安全能力扩展

- 目的地 Registry、一次性授权凭证、Tool approval 和完整 Sandbox 协同。
- `TransformationPlan`：可审计的 redact/replace，绑定 Policy version、输入/输出 fingerprint 和变换 span。
- content/compliance、moderation、copyright、多模态 Content、受控下载和 OCR/媒体 Detector。
- 常见 Framework 的生命周期 recipe/hook，以及完整 Web UI 和分布式控制平面。

这些方向改变当前架构合同中的执行或信任边界时，需要先更新合同、专项设计和行为测试。

## 产品范围

当前服务面向单用户部署。Agent 的 Shell、代码执行、直接网络访问、宿主文件/进程访问、凭据隔离、资源配额和 Sandbox 逃逸防护由部署环境的 Sandbox、网络代理、OS 权限和 Secret 管理提供；服务加固配置见[运行指南](guides/operations.md)。

多用户身份、租户隔离、数据所有权、跨用户共享和按用户授权属于独立产品范围，设计时需要单独建立身份与隔离合同。

## 检测能力维护

稳定 ID、运行时名称（runtime name）、部署配置（profile）、入口、威胁路径、证据和状态集中维护在 `capability-status.yaml`。矩阵中的状态词表达实现成熟度和标准部署可达性；它们与 P4/P5 产品阶段相互独立。
