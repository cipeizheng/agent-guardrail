# Core 与 Gateway 的独立部署设计

> 本文说明把规则分析服务（Core）与请求入口（Gateway）分开部署时，两个服务各自负责什么，以及请求和错误如何流转。
> 当前实现使用固定 Policy 的无状态 Core HTTP 服务；Gateway 保存每个请求的执行上下文。规则热加载和多用户控制平面属于后续规划。

## 1. 服务职责

| 组件 | 责任与持有对象 |
| --- | --- | --- |
| Core | 规则、检查计划、检测配置和模型；接收一批事件并返回 `Decision`，自身不保存任务状态 |
| Gateway | 模型服务/MCP 配置与密钥、请求级 `Trace`、执行检查和脱敏审计；负责副作用顺序 |

编程式 SDK 把 `GuardrailRuntime` 作为分析器传给 `GuardrailRun` 或 `EnforcementSession`。远程 Gateway 使用 `RemoteGuardrailRuntime`；两条路径实现同一 `PolicyAnalyzer.analyze_pending` 边界。

## 2. Core HTTP 接口

- `POST /v1/analyze`：Bearer 服务认证；请求 `protocol_version=4` 和一批完整的 `PendingTrace`，响应 `protocol_version=4` 和一个 `Decision`。请求和响应都不携带执行阶段字段。
- `GET /v1/policies/current`：Bearer 服务认证；返回协议版本、Policy version 和 content hash。
- `GET /health/live`：只证明进程存活。
- `GET /health/ready`：只有固定 Policy、Registry 和可选模型完成加载且 Runtime ready 时返回 200。

请求、响应、deadline 和并发使用部署固定上限。错误只返回稳定 type/code/message，不回显请求、Policy、Detector 输出或下游异常。协议版本是封闭 Schema 的一部分，非 v4 请求或响应一律拒绝；不得记录请求体或原始响应体。破坏性对外协议 Schema 变化必须更换协议版本，不能静默复用现有版本号。

Core 启动时从只读部署文件加载固定 Policy 与检测配置（Detector profile），HTTP 请求面只接受完整、有界的分析数据。Core 与 Gateway 使用独立服务凭据；Provider/MCP 上游凭据由 Gateway 管理，Policy、Detector 模型和规则文件由 Core 侧部署管理。

## 3. 失败处理与一致性

Gateway 启动时必须读取 Core readiness 和 Policy identity。运行中任何网络错误、非 200、超限响应、非法 JSON、非法 Schema 或 Decision identity 不匹配都转换为 `GuardrailUnavailable`。Gateway 还必须校验 Decision 的 trace、pending Event 和 Policy identity，不能只信任 HTTP 成功状态。调用前失败时上游调用数为 0；输出释放前失败时不释放已经取得的原始上游结果。

Core 保持无状态。Gateway 每次发送 `past_events + pending_events` 的完整有界快照，并在 allow 后本地提交；block 只提交脱敏 Decision Event。同一 Session 的首次 Decision 固定 Policy identity，后续变化进入失败关闭路径。

## 4. 容器部署结构

Compose 私有网络只连接 Core 与 Gateway。Core 不发布宿主端口；Gateway 同时连接私有网络和上游网络，只发布 8080。Policy 只读挂载到 Core；Audit volume 只挂载到 Gateway。Core 镜像包含固定 `full_deberta` 资产，Gateway 镜像不包含模型或扫描工具。两个镜像均使用非 root 用户、只读根文件系统、`/tmp` tmpfs 和 HTTP healthcheck。
