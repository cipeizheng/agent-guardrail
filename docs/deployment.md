# Docker 与部署设计

当前状态（2026-08-04）：Gateway 进程和环境配置已实现，可通过
`python -m agent_guardrail.gateway` 启动；Dockerfile/Compose 仍属于下一阶段。

## 1. 部署目标

- 一条 `docker compose up` 命令启动本地 Gateway。
- 镜像内使用与 `uv.lock` 一致的 Python 3.12 环境。
- 默认单容器、内嵌 GuardrailRuntime、无外部数据库。
- 策略通过只读 Volume 或镜像内默认文件加载。
- 容器以非 root 用户运行。
- Health/Readiness 可供 Compose、Kubernetes 和负载均衡器使用。

## 2. MVP Compose

计划结构：

```yaml
services:
  gateway:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "8080:8080"
    env_file:
      - .env
    environment:
      AGENT_GUARDRAIL_HOST: 0.0.0.0
      AGENT_GUARDRAIL_POLICY_FILE: /app/policies/default.yaml
      AGENT_GUARDRAIL_AUDIT_PATH: /data/audit.jsonl
    volumes:
      - ./policies:/app/policies:ro
      - guardrail-data:/data

volumes:
  guardrail-data:
```

该 Compose 目前只作为未来设计合同，仓库中还没有 `docker/Dockerfile`、Compose 文件或容器专用
healthcheck 命令，不能直接执行。`.env` 还必须提供至少一个 OpenAI/MCP 固定上游配置。

## 3. Dockerfile

采用多阶段构建：

```text
builder
  ├─ 固定 uv 版本
  ├─ 复制 pyproject.toml + uv.lock
  ├─ uv sync --frozen --no-dev --extra gateway
  └─ 复制并安装项目

runtime
  ├─ Python 3.12 slim
  ├─ 非 root 用户
  ├─ 复制 /app/.venv
  ├─ 复制默认 policies
  └─ 启动 uvicorn
```

要求：

- 构建必须使用 `uv sync --frozen`。
- 不在 runtime 容器中运行 pip install。
- 先复制 lock 文件以利用 Docker layer cache。
- 基础镜像固定到明确 minor/digest，升级通过依赖任务完成。
- 不把 `.env`、测试缓存或 Git 数据复制进镜像。

## 4. 配置

计划环境变量：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_GUARDRAIL_HOST` | `127.0.0.1` | 监听地址；容器映射端口时显式设为 `0.0.0.0` |
| `AGENT_GUARDRAIL_PORT` | `8080` | 监听端口 |
| `AGENT_GUARDRAIL_POLICY_FILE` | 必填 | YAML Policy |
| `AGENT_GUARDRAIL_UPSTREAM_BASE_URL` | LLM 模式必填 | 固定 OpenAI-compatible HTTP(S) 上游 |
| `AGENT_GUARDRAIL_UPSTREAM_ALLOWED_HOSTS` | 空 | 可选 JSON host allowlist |
| `AGENT_GUARDRAIL_UPSTREAM_AUTH_MODE` | `server_managed` | `server_managed/pass_through` |
| `AGENT_GUARDRAIL_UPSTREAM_API_KEY` | server-managed 时必填 | 上游 Key |
| `AGENT_GUARDRAIL_GATEWAY_API_KEYS` | 空 | JSON 客户端 Key 列表；生产应配置 |
| `AGENT_GUARDRAIL_AUDIT_PATH` | 空 | 设置后启用 JSONL Audit |
| `AGENT_GUARDRAIL_LOG_LEVEL` | `info` | Uvicorn 日志级别 |
| `AGENT_GUARDRAIL_MAX_REQUEST_BYTES` | `1048576` | 请求体上限 |
| `AGENT_GUARDRAIL_MAX_UPSTREAM_RESPONSE_BYTES` | `4194304` | 响应体上限 |
| `AGENT_GUARDRAIL_MAX_TRACE_EVENTS` | `16` | 每个 Gateway 请求的 Trace Event 上限 |
| `AGENT_GUARDRAIL_UPSTREAM_TIMEOUT_SECONDS` | `60` | 上游总超时 |
| `AGENT_GUARDRAIL_EVALUATE_ENDPOINT_ENABLED` | `false` | 是否启用直接 Decision API |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_URL` | MCP 模式必填 | 固定 MCP `2026-07-28` Streamable HTTP endpoint |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_ALLOWED_HOSTS` | 空 | 可选 JSON MCP host allowlist |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_AUTH_MODE` | `none` | `none/server_managed/pass_through` |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_API_KEY` | MCP server-managed 时必填 | MCP 上游 Key |
| `AGENT_GUARDRAIL_MCP_ALLOWED_ORIGINS` | 空 | JSON Origin allowlist；空时拒绝所有带 Origin 请求 |
| `AGENT_GUARDRAIL_MCP_TIMEOUT_SECONDS` | `60` | MCP 上游总超时 |
| `AGENT_GUARDRAIL_MCP_MAX_RESPONSE_BYTES` | `4194304` | MCP 响应体上限 |

每个变量必须有 Pydantic Settings 校验，禁止散落的 `os.getenv`。

## 5. Secret 管理

- 示例文件只提供变量名，不包含真实值。
- Compose 开发环境可用本地 `.env`，且已 gitignore。
- 生产使用 Docker/Kubernetes Secret 或云 Secret Manager。
- API Key 不写入 Trace、Violation、异常字符串或访问日志。
- Header 日志使用 allowlist，而不是先记录再过滤。

## 6. Audit 数据

MVP 使用 append-only JSONL：

```json
{
  "timestamp": "...",
  "trace_id": "trc_...",
  "phase": "pre_tool",
  "action": "block",
  "rule_ids": ["secret-exfiltration"],
  "codes": ["secret_exfiltration"],
  "policy_version": 1,
  "policy_hash": "..."
}
```

当前不提供保存完整 prompt、tool arguments 或 detector 原文的开关。未来若需要内容取证，必须
先通过 ADR 设计显式开关、脱敏、权限和保留周期。

当需要查询、多实例写入或长期审计时，再引入 SQLite/PostgreSQL Adapter，不让存储逻辑进入
Engine。

## 7. 健康检查

Liveness 只检查事件循环和进程。

当前 `GET /health/ready` 只报告 `GuardrailRuntime.ready`。Policy、Registry 和固定上游配置在应用
构造/Settings 校验阶段失败时会阻止进程成功启动；当前 Readiness 不主动探测上游网络，也不验证
Audit 路径可写性。

未来 Policy 热加载失败时应保留上一个有效 Policy，并让 Readiness/Metric 反映配置错误；热加载
当前尚未实现。
Gateway 进程只创建一个 Runtime；每个 HTTP 请求创建独立 EnforcementSession，Session 不作为
全局单例复用。

## 8. 可观测性

结构化日志字段：

- trace_id
- request_id
- phase
- decision
- rule_id
- policy_version
- duration_ms
- detector duration
- error category

计划指标：

- guardrail_decisions_total
- guardrail_blocks_total
- rule_evaluation_duration_seconds
- detector_duration_seconds
- policy_reload_total
- upstream_requests_total
- upstream_request_duration_seconds

第一版可以只提供日志，指标接口在 Gateway 稳定后加入。

## 9. 发布与兼容性

- Semantic Versioning。
- `uv.lock` 必须提交。
- CI 构建 wheel 和 Docker image。
- 镜像标签至少包含版本和 Git SHA。
- Policy YAML 带 `version: 1`。
- Canonical Event 与 Decision API 的破坏性变更必须升级 API version。

## 10. 后续多服务部署

只有满足以下任一条件才拆分 Core：

- 多个 Gateway 需要共享 Policy 与 Detector。
- Detector 需要 GPU/独立扩缩容。
- 非 Python Gateway 需要远程 Decision API。
- 策略管理和审计需要独立权限边界。

拆分后 Compose 可演进为：

```text
gateway
core
postgres (optional)
otel-collector (optional)
```

但本地开发仍必须保留单进程模式。
