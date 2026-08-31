# Remote Core 双容器设计

> 当前实现：固定 Policy 的无状态 Core HTTP 服务与可选择 embedded/remote Decision backend 的 Gateway。
> 不包含：Policy 热加载、持久化/分布式 Session Store、远程 Policy 上传或第二执行器。产品明确只支持
> 单用户，不设计多用户/多租户控制平面。单进程 task-session state 只存在于 Gateway，不改变 Core 无状态性。

## 1. 责任边界

| 组件 | 持有 | 不持有 |
| --- | --- | --- |
| Core | Policy、MatchPlan、Detector profile、模型、规则、Decision | Provider Key、Gateway Client Key、Agent 副作用、Audit payload |
| Gateway | Provider/MCP 配置与 Key、请求级/任务级 Trace、Enforcement、脱敏 Audit | Policy 文件、Detector 模型、规则文件 |

编程式 SDK 和 Inline Wrapper 继续把 `GuardrailRuntime` 直接注入 `EnforcementSession`。远程 Gateway 注入
`RemoteGuardrailRuntime`；两者实现同一 `PolicyAnalyzer.analyze_pending` 边界。

## 2. Core HTTP

- `POST /v1/analyze`：Bearer 服务认证；请求 `protocol_version=4` 与一个 phase-free `PendingTrace`，响应
  `protocol_version=4` 与一个 phase-free `Decision`。
- `GET /v1/policies/current`：Bearer 服务认证；返回协议版本、Policy version 和 content hash。
- `GET /health/live`：只证明进程存活。
- `GET /health/ready`：只有固定 Policy、Registry 和可选模型完成加载且 Runtime ready 时返回 200。

请求、响应、deadline 和并发使用部署固定上限。错误只返回稳定 type/code/message，不回显请求、Policy、
Detector 输出或下游异常。协议版本是封闭 Schema 的一部分，非 v4 请求或响应一律拒绝；不得记录请求体或
原始响应体。破坏性 wire Schema 变化必须更换协议版本，不能静默复用现有版本号。

Core 启动时只从只读部署文件加载固定 Policy 与 Detector profile；请求不能上传 Policy、模型、规则、路径、
命令或 endpoint。Core 与 Gateway 使用独立服务凭据；Core 不持有 Provider/MCP 上游凭据，Gateway 不挂载
Policy、Detector 模型或规则文件。

## 3. 失败与一致性

Gateway 启动时必须读取 Core readiness 和 Policy identity。运行中任何网络错误、非 200、超限响应、非法 JSON、
非法 Schema 或 Decision identity 不匹配都转换为 `GuardrailUnavailable`。Gateway 还必须校验 Decision 的
trace、pending Event 和 Policy identity，不能只信任 HTTP 成功状态。调用前失败时上游调用数为 0；输出释放
前失败时不释放已经取得的原始上游结果。

Core 首版不保存 Trace。Gateway 每次发送 `past_events + pending_events` 的完整有界快照，并在 allow 后本地
提交；block 只提交脱敏 Decision Event。同一 Session 的首次 Decision 固定 Policy identity，后续变化失败。

## 4. 容器拓扑

Compose 私有网络只连接 Core 与 Gateway。Core 不发布宿主端口；Gateway 同时连接私有网络和上游网络，只发布
8080。Policy 只读挂载到 Core；Audit volume 只挂载到 Gateway。Core 镜像包含固定 `full_deberta` 资产，
Gateway 镜像不包含模型或扫描工具。两个镜像均使用非 root 用户、只读根文件系统、`/tmp` tmpfs 和 HTTP
healthcheck。
