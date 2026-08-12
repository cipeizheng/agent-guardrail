# Remote Core 双容器设计

> 当前实现：固定 Policy 的无状态 Core HTTP 服务与可选择 embedded/remote Decision backend 的 Gateway。
> 不包含：Policy 热加载、跨请求 Session Store、多租户控制平面、远程 Policy 上传或第二执行器。

## 1. 责任边界

| 组件 | 持有 | 不持有 |
| --- | --- | --- |
| Core | Policy、MatchPlan、Detector profile、模型、规则、Decision | Provider Key、Gateway Client Key、Agent 副作用、Audit payload |
| Gateway | Provider/MCP 配置与 Key、请求级 Trace、Enforcement、脱敏 Audit | Policy 文件、Detector 模型、规则文件 |

Inline SDK 继续把 `GuardrailRuntime` 直接注入 `EnforcementSession`。远程 Gateway 注入
`RemoteGuardrailRuntime`；两者实现同一 `PolicyAnalyzer.analyze_pending` 边界。

## 2. Core HTTP v1

- `POST /v1/analyze`：Bearer 服务认证；请求 `protocol_version=1` 与一个 `PendingTrace`，响应
  `protocol_version=1` 与一个 `Decision`。
- `GET /v1/policies/current`：Bearer 服务认证；返回协议版本、Policy version 和 content hash。
- `GET /health/live`：只证明进程存活。
- `GET /health/ready`：只有固定 Policy、Registry 和可选模型完成加载且 Runtime ready 时返回 200。

请求、响应、deadline 和并发使用部署固定上限。错误只返回稳定 type/code/message，不回显请求、Policy、
Detector 输出或下游异常。

## 3. 失败与一致性

Gateway 启动时必须读取 Core readiness 和 Policy identity。运行中任何网络错误、非 200、超限响应、非法 JSON、
非法 Schema 或 Decision identity 不匹配都转换为 `GuardrailUnavailable`。pre 失败时上游调用数为 0；post 失败
时不释放已经取得的原始上游结果。

Core 首版不保存 Trace。Gateway 每次发送 `past_events + pending_events` 的完整有界快照，并在 allow 后本地
提交；block 只提交脱敏 Decision Event。同一 Session 的首次 Decision 固定 Policy identity，后续变化失败。

## 4. 容器拓扑

Compose 私有网络只连接 Core 与 Gateway。Core 不发布宿主端口；Gateway 同时连接私有网络和上游网络，只发布
8080。Policy 只读挂载到 Core；Audit volume 只挂载到 Gateway。Core 镜像包含固定 `full_local_v1` 资产，
Gateway 镜像不包含模型或扫描工具。两个镜像均使用非 root 用户、只读根文件系统、`/tmp` tmpfs 和 HTTP
healthcheck。
