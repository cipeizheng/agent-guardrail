# Gateway 与 Core 运行指南

> 适合谁：启动和运维 embedded Gateway 或 Core/Gateway 双容器的人。
> 解决什么：安装、容器、环境变量、Secret、Audit 和健康检查。
> 不包含什么：集群编排、Policy 热加载或跨请求 Session Store。

## 1. Embedded 启动

```bash
uv sync --frozen --extra gateway --no-dev
uv run python -m agent_guardrail.gateway
```

进程内包含 FastAPI Gateway、一个 GuardrailRuntime、固定 OpenAI/MCP 上游客户端和可选 JSONL AuditSink。
该 embedded 模式不依赖数据库、远程 Core 或跨请求 Session Store。

### 完整本地 Detector profile

默认 `local` profile 不加载可选模型。启用已真实验证的 `full_local_v1`：

```bash
uv sync --frozen --extra gateway --extra detectors --no-dev
uv tool install semgrep==1.170.0
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-detectors
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_local_v1
export AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE=cpu
uv run python -m agent_guardrail.gateway
```

有可用 CUDA 设备时可把最后一个设备值改为 `cuda`。Presidio/spaCy 继续运行在 CPU；CUDA 只用于固定的
提示注入模型。Semgrep 独立安装是有意的：Semgrep 1.170.0 锁定 MCP 1.x，而 Gateway 使用 MCP 2.x，隔离
工具环境避免依赖冲突。

资产预取固定模型 repository、commit、文件集合、字节数和 SHA-256；写入只在单个文件完整校验后原子完成。
Runtime 构造 profile 时再次逐项校验，且强制 Transformers 离线读取该目录。运行时不下载模型，也不从
Policy 接受模型、规则、路径、命令或 device。缺失或不匹配会阻止启动。

真实 profile 评估命令：

```bash
AGENT_GUARDRAIL_RUN_REAL_DETECTOR_EVAL=1 \
AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE=cuda \
uv run --extra detectors pytest -vv tests/integration/test_full_local_detector_profile.py
```

该命令复用 `AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR`，并要求 `semgrep` 在 `PATH` 中且版本严格匹配。

### 可选 `is_similar` encoder profile

`is_similar` 不在默认 profile 中隐式联网。需要该能力时，可信启动代码构造 embedding client，并把 backend
与 profile 一起注入 Registry：

```python
from agent_guardrail.config import create_deployment_detector_registry
from agent_guardrail.detectors import (
    EmbeddingProfile,
    OpenAIEmbeddingBackend,
)

detectors = create_deployment_detector_registry(
    "local",
    embedding_backend=OpenAIEmbeddingBackend(
        openai_compatible_client,
        backend_version="reviewed-client-v1",
    ),
    embedding_profile=EmbeddingProfile(
        profile_id="production-semantic-v1",
        profile_version="1",
        model="text-embedding-3-large",
    ),
)
```

`openai_compatible_client` 必须提供异步 `embeddings.create`；其 endpoint/凭据由部署启动层创建，不进入
Policy、Trace、Finding 或 Audit。
backend 与 profile 必须同时提供；模型、profile identity 或资源上限变化会改变 Detector version。当前 CLI
没有 embedding 凭据环境变量，使用该可选 adapter 的部署应在组合根显式注入上述 Registry。真实服务尚未纳入
仓库可重复评测，因此能力矩阵保持 `adapter_only`。

启用远程 backend 会把参与比较的 `data` 和 `target` 发送到该固定 endpoint；它不是本地零泄露能力。部署方
必须把该 endpoint 作为获准的数据接收方并配置传输、保留和租户边界，或者注入本地 `EmbeddingBackend`。
Policy 不能借此改写 endpoint/model/凭据，但这一限制不能替代部署侧的数据授权。

## 2. 双容器启动

仓库只定义两个运行服务：`core` 持有 Policy、完整 Detector 资产和分析 Runtime；`gateway` 持有 Provider/
MCP 配置、请求级 Trace、Audit 和副作用顺序。CPU/CUDA 是 Core 的运行配置，不会创建第三个服务。

```bash
cp .env.example .env
# 编辑 .env 中的 Core 服务 Key、Gateway 客户端 Key 和 Provider 配置
docker compose build
docker compose up -d
curl --fail http://127.0.0.1:8080/health/ready
```

Core 构建会安装 `full_local_v1` 的 Presidio/spaCy、固定 DeBERTa checkpoint、Semgrep 和 YARA，并在构建期
下载后校验约 750 MB 的模型资产，因此首次构建较慢且镜像较大。运行时为离线模式。Compose 只发布 Gateway
的 8080；Core 8090 只连接内部网络。Policy 只读挂载到 Core，Audit volume 只挂载到 Gateway，两个容器均
non-root、只读 root filesystem、drop capabilities 并使用 `/tmp` tmpfs。

Compose 私网内使用 HTTP。若 Core 与 Gateway 跨主机或跨非受控网络部署，必须在其间增加 TLS/mTLS 或等价
的可信传输层；Bearer Key 不能替代链路机密性。

默认用 CPU。CUDA 部署把 `AGENT_GUARDRAIL_CORE_PROMPT_MODEL_DEVICE=cuda`，并通过部署平台/NVIDIA
Container Toolkit 只给现有 `core` 服务授予 GPU（例如 Compose override 中设置 `gpus: all`）；Gateway
不需要 GPU。所用 PyTorch 构建和宿主驱动仍须支持目标 CUDA 环境，否则 Core 会失败启动。

停止服务：

```bash
docker compose down
```

命名 Audit volume 会保留；上述命令不删除它。只有明确希望删除 Audit 时才另行执行带 `--volumes` 的清理。

## 3. 环境变量

字段、默认值和校验以 `GatewaySettings` 为事实来源：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AGENT_GUARDRAIL_DECISION_BACKEND` | `embedded` | `embedded/remote` |
| `AGENT_GUARDRAIL_HOST` | `127.0.0.1` | 监听地址 |
| `AGENT_GUARDRAIL_PORT` | `8080` | 监听端口 |
| `AGENT_GUARDRAIL_POLICY_FILE` | embedded 必填 | v3 YAML Policy；remote 模式禁止 |
| `AGENT_GUARDRAIL_CORE_URL` | remote 必填 | 固定 Core HTTP base URL |
| `AGENT_GUARDRAIL_CORE_API_KEY` | remote 必填 | Gateway→Core 专用 Bearer Key |
| `AGENT_GUARDRAIL_CORE_TIMEOUT_SECONDS` | `10` | 单次 Core 请求 timeout |
| `AGENT_GUARDRAIL_CORE_MAX_REQUEST_BYTES` | `8388608` | 发往 Core 的 body 上限 |
| `AGENT_GUARDRAIL_CORE_MAX_RESPONSE_BYTES` | `1048576` | Core 响应 body 上限 |
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
| `AGENT_GUARDRAIL_DETECTOR_PROFILE` | `local` | `local/full_local_v1` 固定部署 profile |
| `AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR` | 空 | `full_local_v1` 必填的已校验模型资产根目录 |
| `AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE` | `cpu` | `full_local_v1` 的 `cpu/cuda` 推理设备 |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_URL` | MCP 模式必填 | 固定 MCP endpoint |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON MCP host allowlist |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_AUTH_MODE` | `none` | `none/server_managed/pass_through` |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_API_KEY` | MCP server-managed 时必填 | MCP 上游 Key |
| `AGENT_GUARDRAIL_MCP_ALLOWED_ORIGINS` | 空 | JSON Origin allowlist |
| `AGENT_GUARDRAIL_MCP_TIMEOUT_SECONDS` | `60` | MCP 上游总超时 |
| `AGENT_GUARDRAIL_MCP_MAX_RESPONSE_BYTES` | `4194304` | MCP 响应体上限 |

至少配置一个 LLM 或 MCP 上游。固定 URL 不能含凭据、query 或 fragment；配置非空 host allowlist 时
hostname 必须匹配。

Core 使用独立前缀：`AGENT_GUARDRAIL_CORE_POLICY_FILE` 与
`AGENT_GUARDRAIL_CORE_API_KEY` 必填；`AGENT_GUARDRAIL_CORE_DETECTOR_PROFILE` 默认 `local`，双容器镜像
默认覆盖为 `full_local_v1`；另有 `..._DETECTOR_ASSETS_DIR`、`..._PROMPT_MODEL_DEVICE`、
`..._MAX_REQUEST_BYTES`、`..._HOST`、`..._PORT` 和 `..._LOG_LEVEL`。事实来源是 `CoreSettings`。

## 4. Secret

- 示例只写变量名，不含真实值。
- 开发可使用已 gitignore 的 `.env`；生产使用部署平台 Secret。
- Key 不进入 Trace、Finding、Violation、Audit、异常或访问日志。
- `server_managed` 使用服务端 Key；`pass_through` 才转发客户端 Authorization。
- Gateway→Core Key 必须与 Provider、MCP 和 Gateway Client Key 分离；Core 不配置任何上游 Key。

## 5. Audit

设置 `AGENT_GUARDRAIL_AUDIT_PATH` 后，append-only JSONL 只保存含 Violation 的 Decision 摘要；普通 allow
不逐条持久化。它不接收 Event payload、完整 prompt、Tool arguments 或 Detector 原文。

当前没有内容取证模式。保存原始敏感内容必须先改变架构合同并定义访问权限、脱敏和保留期。

## 6. Health 与可观测性

- `GET /health/live`：进程和事件循环存活。
- Gateway `GET /health/ready`：embedded 报告本地 Runtime；remote 同时验证 Core readiness 与启动时固定的
  Policy identity。
- Core `GET /health/ready`：报告固定 Policy、Registry、模型 warm-up 和 Runtime ready。

Policy 编译、capability linking、Settings 和可选 Detector profile 在应用构造阶段失败会阻止启动。
`full_local_v1` 构造会验证固定资产与 Semgrep 版本，并对模型做一次本地 warm-up。Readiness 不探测
Provider/MCP 上游网络，也不验证 Audit 路径可写性。

当前只有 Uvicorn 日志级别和可选 JSONL Audit，没有结构化应用日志、Metrics、OpenTelemetry、SBOM、镜像
签名、热加载或集群编排；这些仍在[roadmap](../roadmap.md)安排。
