# Gateway 运行指南

> 适合谁：启动和运维当前单进程 Gateway 的人。
> 解决什么：安装、环境变量、Secret、Audit 和健康检查。
> 不包含什么：未交付的 Docker/Compose 或多服务假想配置。

## 1. 启动

```bash
uv sync --frozen --extra gateway --no-dev
uv run python -m agent_guardrail.gateway
```

进程内包含 FastAPI Gateway、一个 GuardrailRuntime、固定 OpenAI/MCP 上游客户端和可选 JSONL AuditSink。
当前不依赖数据库、远程 Core 或跨请求 Session Store。

## 2. 环境变量

字段、默认值和校验以 `GatewaySettings` 为事实来源：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_GUARDRAIL_HOST` | `127.0.0.1` | 监听地址 |
| `AGENT_GUARDRAIL_PORT` | `8080` | 监听端口 |
| `AGENT_GUARDRAIL_POLICY_FILE` | 必填 | v3 YAML Policy |
| `AGENT_GUARDRAIL_UPSTREAM_BASE_URL` | LLM 模式必填 | 固定 OpenAI-compatible 上游 |
| `AGENT_GUARDRAIL_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON host allowlist |
| `AGENT_GUARDRAIL_UPSTREAM_AUTH_MODE` | `server_managed` | `server_managed/pass_through` |
| `AGENT_GUARDRAIL_UPSTREAM_API_KEY` | server-managed 时必填 | OpenAI 上游 Key |
| `AGENT_GUARDRAIL_GATEWAY_API_KEYS` | 空 | JSON 客户端 Key；生产应配置 |
| `AGENT_GUARDRAIL_AUDIT_PATH` | 空 | 设置后启用 JSONL Audit |
| `AGENT_GUARDRAIL_LOG_LEVEL` | `info` | Uvicorn 日志级别 |
| `AGENT_GUARDRAIL_MAX_REQUEST_BYTES` | `1048576` | 请求体上限 |
| `AGENT_GUARDRAIL_MAX_UPSTREAM_RESPONSE_BYTES` | `4194304` | OpenAI 响应体上限 |
| `AGENT_GUARDRAIL_MAX_TRACE_EVENTS` | `16` | 请求级 Trace Event 上限 |
| `AGENT_GUARDRAIL_UPSTREAM_TIMEOUT_SECONDS` | `60` | OpenAI 上游总超时 |
| `AGENT_GUARDRAIL_EVALUATE_ENDPOINT_ENABLED` | `false` | 是否启用直接 Decision API |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_URL` | MCP 模式必填 | 固定 MCP endpoint |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON MCP host allowlist |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_AUTH_MODE` | `none` | `none/server_managed/pass_through` |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_API_KEY` | MCP server-managed 时必填 | MCP 上游 Key |
| `AGENT_GUARDRAIL_MCP_ALLOWED_ORIGINS` | 空 | JSON Origin allowlist |
| `AGENT_GUARDRAIL_MCP_TIMEOUT_SECONDS` | `60` | MCP 上游总超时 |
| `AGENT_GUARDRAIL_MCP_MAX_RESPONSE_BYTES` | `4194304` | MCP 响应体上限 |

至少配置一个 LLM 或 MCP 上游。固定 URL 不能含凭据、query 或 fragment；配置非空 host allowlist 时
hostname 必须匹配。

## 3. Secret

- 示例只写变量名，不含真实值。
- 开发可使用已 gitignore 的 `.env`；生产使用部署平台 Secret。
- Key 不进入 Trace、Finding、Violation、Audit、异常或访问日志。
- `server_managed` 使用服务端 Key；`pass_through` 才转发客户端 Authorization。

## 4. Audit

设置 `AGENT_GUARDRAIL_AUDIT_PATH` 后，append-only JSONL 只保存含 Violation 的 Decision 摘要；普通 allow
不逐条持久化。它不接收 Event payload、完整 prompt、Tool arguments 或 Detector 原文。

当前没有内容取证模式。保存原始敏感内容必须先改变架构合同并定义访问权限、脱敏和保留期。

## 5. Health 与可观测性

- `GET /health/live`：进程和事件循环存活。
- `GET /health/ready`：只报告 Runtime ready。

Policy 编译、capability linking 和 Settings 在应用构造阶段失败会阻止启动。Readiness 不探测上游网络，
也不验证 Audit 路径可写性。

当前只有 Uvicorn 日志级别和可选 JSONL Audit，没有结构化应用日志、Metrics 或 OpenTelemetry。Docker、
只读 Policy mount、非 root 镜像、SBOM、热加载和多服务部署只在[roadmap](../roadmap.md)安排。
