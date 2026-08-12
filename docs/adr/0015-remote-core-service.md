# ADR-0015：固定 Policy 的远程 Core 服务

- 状态：Accepted
- 日期：2026-08-12
- 补充范围：ADR-0014 与当前架构合同的本地 Runtime 边界
- 专项细节：[`remote-core-deployment.md`](../design/remote-core-deployment.md)

## 背景

源码发行需要同时提供可独立构建的 Core 与 Gateway 容器。当前 Gateway 在进程内创建
`GuardrailRuntime`，不能让协议代理与模型 Detector 独立部署、隔离凭据和按资源需求扩缩。

## 决策

1. Core MUST 继续使用唯一的 v3 YAML → MatchPlan → AnalysisReport → Decision 执行链；远程部署不得引入
   第二套解释器或规则执行器。
2. Core MUST 在启动时从只读部署文件加载固定 Policy 和 Detector profile；请求不得上传 Policy、模型、
   规则、路径、命令或 endpoint。
3. 远程协议 MUST 版本化，输入只能是完整、封闭的 `PendingTrace`，输出只能是脱敏 `Decision`。
4. Core 首版 MUST 是无跨请求状态的分析服务；Gateway 继续拥有请求级 Trace、提交顺序、Audit 和全部受保护
   副作用。
5. Gateway MUST 在 pre Decision 明确允许前禁止上游调用，并在 post Decision 明确允许前禁止释放原始结果。
   Core 不可达、timeout、认证失败、协议错误、超限或非法 Decision MUST 失败关闭。
6. Core 与 Gateway MUST 使用独立服务凭据。Core 不持有 LLM/MCP 上游凭据；Gateway 不挂载 Policy、Detector
   模型或规则文件。
7. 同一 EnforcementSession 内的 Decision MUST 使用相同 Policy version/hash；中途变化按 Core 不可用处理。
8. 现有嵌入式 Runtime MUST 保留，供 Inline SDK、测试和单进程开发使用。

## 安全与兼容性

- `PendingTrace` 可能包含敏感 payload，只允许经受限内部网络传输；双方不得记录请求体或原始响应体。
- Core 响应仍由 Gateway 校验 trace、pending event、phase、Policy identity 和封闭 Schema，不能仅信任 HTTP
  成功状态。
- 现有 Policy v3、Canonical Event、Relation、Finding、Decision 和 Detector 合同不变。
- 远程协议的破坏性升级需要新版本路径或新 ADR；不得静默复用旧版本号。

## 后果

- Gateway 镜像保持轻量，模型、Semgrep、YARA 和 GPU 只存在于 Core 镜像。
- 每次 pre/post 分析增加一次内部网络往返，并新增服务认证、可用性和部署配置成本。
- Policy 热加载、跨请求 Session Store、远程 Policy 上传、原始内容取证和多租户控制平面仍不交付。
