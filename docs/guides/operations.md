# Gateway 与 Core 运行指南

> 本文说明如何启动 Gateway、选择检测能力、配置凭据、运行审计记录，以及如何部署 Core/Gateway 双容器。
> 相关参考：[当前架构合同](../current-architecture-contract.md)、[Gateway 协议](../reference/gateway-protocol.md)。

## 1. 单进程启动

```bash
uv sync --frozen --extra gateway --no-dev
uv run python -m agent_guardrail.gateway
```

该进程包含 HTTP Gateway、一个 `GuardrailRuntime`、固定的模型服务/MCP 上游客户端和可选的 JSONL 审计记录写入器。单进程模式不依赖数据库或远程 Core；每个受保护请求只在处理期间维护自己的 Trace。

### 完整本地检测配置

默认 `local` 配置使用本地确定性检测。需要完整的 `full_deberta` 配置时：

```bash
uv sync --frozen --extra gateway --extra detectors --no-dev
uv tool install semgrep==1.170.0
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-detectors
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_deberta
export AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE=cpu
uv run python -m agent_guardrail.gateway
```

有可用 CUDA 设备时可把最后一个设备值改为 `cuda`。Presidio/spaCy 继续运行在 CPU；CUDA 只用于固定的提示注入模型。Semgrep 独立安装是有意的：Semgrep 1.170.0 锁定 MCP 1.x，而 Gateway 使用 MCP 2.x，隔离工具环境避免依赖冲突。

资产预取固定模型仓库（repository）、commit、文件集合、字节数和 SHA-256；写入只在单个文件完整校验后原子完成。Runtime 构造检测配置（profile）时再次逐项校验，且强制 Transformers 离线读取该目录。运行时不下载模型，也不从 Policy 接受模型、规则、路径、命令或 device。缺失或不匹配会阻止启动。

### PromptGuard 2 检测配置

`full_promptguard2` 与 `full_deberta` 使用相同的 Presidio/spaCy、Semgrep 和 YARA 检测配置，只把 DeBERTa 提示注入分类器换成 Meta PromptGuard 2 86M；`promptguard2` 只加载本地启发式检测和 PromptGuard 2，适合单独评估分类器。两者的部署默认阈值都是 0.9。

```bash
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-promptguard2
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_promptguard2
```

**许可证说明**：PromptGuard 2 权重适用 Llama 4 Community License（含月活 7 亿上限条款，再分发需遵守协议并附 "Built with Llama" 署名），因此两个配置需要显式启用；`full_deberta`（MIT 栈 + Apache-2.0/Protect AI DeBERTa）是默认完整配置。原始权重位于人工审批 gate 的 `meta-llama/Llama-Prompt-Guard-2-86M`，本项目 pin `gravitee-io` 镜像中字节一致的 `model.safetensors`，来源记录在 `config/deployment.py` 的 pin 常量注释中。资产校验与 `full_deberta` 相同（逐文件 size + SHA-256）。

### 按组件配置检测能力

preset 之外，可以按组件逐个开关（与 `AGENT_GUARDRAIL_DETECTOR_PROFILE` 互斥，非 `local` preset 与任一组件变量同时设置会拒绝启动）：

| 环境变量 | 取值 | 说明 |
|---|---|---|
| `AGENT_GUARDRAIL_DETECTOR_PII` | `none`/`presidio` | Presidio/spaCy NER 检测后端 |
| `AGENT_GUARDRAIL_DETECTOR_SEMGREP` | `none`/`python_rules` | 外部 Semgrep CLI + 包内 ruleset |
| `AGENT_GUARDRAIL_DETECTOR_YARA` | `none`/`injection_rules` | yara-python + 包内 ruleset |
| `AGENT_GUARDRAIL_DETECTOR_PROMPT_MODEL` | `none`/`deberta_v2`/`promptguard2` | PI 分类器（单槽位，二选一）|
| `AGENT_GUARDRAIL_PROMPT_MODEL_THRESHOLD` | `(0, 1]` | 缺省：deberta_v2 0.85 / promptguard2 0.9 |

```bash
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
export AGENT_GUARDRAIL_DETECTOR_PII=presidio
export AGENT_GUARDRAIL_DETECTOR_PROMPT_MODEL=promptguard2
```

**按组件组合时的边界**：每个组件分别通过单元与集成验证；模型组件、Semgrep 版本、CUDA 可用性和资产哈希中任一项不符合要求时，服务会阻止启动。`full_deberta` 是标准完整配置；其他组合只继承各组件的验证范围，组合级安全与效用由部署方评估。Core 侧使用 `AGENT_GUARDRAIL_CORE_` 前缀的同名变量。

真实检测配置的评估命令：

```bash
AGENT_GUARDRAIL_RUN_REAL_DETECTOR_EVAL=1 \
AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE=cuda \
uv run --extra detectors pytest -vv tests/integration/test_full_local_detector_profile.py
```

该命令复用 `AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR`，并要求 `semgrep` 在 `PATH` 中且版本严格匹配。

### 可选的相似度检测

`is_similar` 不会在默认配置中自动连接网络。需要该能力时，可信启动代码构造 embedding client，并把外部实现和配置一起注入 Registry：

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

`openai_compatible_client` 必须提供异步 `embeddings.create`；它的地址和凭据由部署启动层创建，不进入 Policy、Trace、Finding 或 Audit。外部实现和配置必须同时提供；模型、配置身份或资源上限变化会改变检测器版本。当前 CLI 的 embedding 凭据由组合根负责注入 Registry；能力矩阵将该可选适配器标记为 `adapter_only`，真实服务评测由部署方按工作负载执行。

启用远程实现会把参与比较的 `data` 和 `target` 发送到固定地址；部署方必须把该地址作为获准的数据接收方，并配置传输、保留和数据隔离边界；也可以注入本地 `EmbeddingBackend`。Policy 不能改写地址、模型或凭据，数据授权仍由部署侧负责。

### 实验性的模型评审检测

`prompt_injection_judge` 使用通用大模型对输入文本给出提示注入风险分数。当前接入方式是可信应用代码构造自定义 Registry，DeepSeek 的真实后端实现位于 `evals/prompt_injection/judge.py`。能力矩阵将其标记为 `experimental`；后续标准部署配置需要固定模型服务、独立凭据、Prompt 身份、超时与失败关闭、规则执行、受保护副作用断言和发送给 Judge 的数据目的地授权。

## 2. 双容器部署

仓库定义两个运行服务：`core` 保存 Policy、检测资产和分析 Runtime；`gateway` 保存模型服务/MCP 配置和审计记录，在请求期间维护 Trace 并控制副作用顺序。CPU/CUDA 是 Core 的运行配置，不会创建第三个服务。

```bash
cp .env.example .env
# 编辑 .env 中的 Core 服务 Key、Gateway 客户端 Key 和 Provider 配置
docker compose build
docker compose up -d
curl --fail http://127.0.0.1:8080/health/ready
```

Core 构建会安装 `full_deberta` 的 Presidio/spaCy、固定 DeBERTa checkpoint、Semgrep 和 YARA，并在构建期下载后校验约 750 MB 的模型资产，因此首次构建较慢且镜像较大。运行时为离线模式。Compose 只发布 Gateway 的 8080；Core 8090 只连接内部网络。Policy 只读挂载到 Core，Audit volume 只挂载到 Gateway，两个容器均 non-root、只读 root filesystem、drop capabilities 并使用 `/tmp` tmpfs。Core 镜像把 `HOME` 与 `XDG_*` 缓存重定向到 `/tmp`：只读 rootfs 下若沿用默认 `$HOME`，`semgrep --version` 等 Tool 在 `$HOME/.semgrep` 建日志目录会直接失败并使 `full_deberta` 无法启动——preset 换装时不得移除这两个 ENV 的重定向。

Compose 私网内使用 HTTP。若 Core 与 Gateway 跨主机或跨非受控网络部署，必须在其间增加 TLS/mTLS 或等价的可信传输层；Bearer Key 不能替代链路机密性。

默认用 CPU。CUDA 部署把 `AGENT_GUARDRAIL_CORE_PROMPT_MODEL_DEVICE=cuda`，并通过部署平台/NVIDIA Container Toolkit 只给现有 `core` 服务授予 GPU（例如 Compose override 中设置 `gpus: all`）；Gateway 不需要 GPU。所用 PyTorch 构建和宿主驱动仍须支持目标 CUDA 环境，否则 Core 会失败启动。

停止服务：

```bash
docker compose down
```

命名 Audit volume 会保留；上述命令不删除它。只有明确希望删除 Audit 时才另行执行带 `--volumes` 的清理。

## 3. Agent 隔离与部署边界

本仓库的 Compose 只运行可信的 Core 和 Gateway，不启动或隔离 Agent。容器的非 root 用户、只读根文件系统、权限削减和 Core 私网用于加固 Guardrail 服务本身，不能证明 Agent 的 Shell、原生函数、文件系统或网络请求都经过 Gateway。

如果 Agent 可以执行代码或 Shell，生产部署应把它放入独立的不可信 Sandbox，并把 Guardrail、真实 Tool Broker 和凭据留在 Sandbox 外。最低部署合同是：

- Agent egress 默认拒绝，只允许固定 Guardrail Gateway/Tool Broker；禁止直连 Provider、MCP Server、数据库、邮件/云 API，并覆盖 DNS、IPv4/IPv6、loopback、Unix socket 和云 metadata 路径；
- Sandbox 不含 Provider、MCP、数据库或其他生产凭据；凭据只由外部服务持有并按用户授权使用；
- 不使用 privileged、host network/PID/IPC，不挂载 Docker/container runtime socket、宿主敏感目录或多余设备；
- 文件系统默认只读或按任务临时创建，只挂载完成任务所需的最小目录，不允许后台进程跨任务存活；
- 设置 CPU、内存、PID、磁盘、文件描述符和 wall-clock 上限，并能在超限时终止整个 Sandbox；
- Sandbox 内的 Agent 不能修改 Policy、Gateway/Core 配置、Detector 资产或 Audit；应用内检查代码失效也不能扩大 Sandbox 的网络或主机权限。

仅把代码/Shell 工具放进 Sandbox 也可以：此时 Agent 与 Guardrail 位于外部，`before_tool_call` allow 后才调用 Sandbox Executor，`before_tool_output_release` allow 后才释放结果。该 Executor 仍应无生产凭据、无任意公网 egress，并按任务销毁。

`url_host_allowed`、命令/代码 Detector 或 Provider/MCP host allowlist 都是已中介流量上的策略或纵深防御；OS/网络强制由部署侧负责。完整的责任矩阵见[安全模型](../security-model.md#8-guardrail-与沙箱的责任边界)。

## 4. 环境变量

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
| `AGENT_GUARDRAIL_UPSTREAM_BASE_URL` | LLM 模式必填 | 固定 Model Provider base URL |
| `AGENT_GUARDRAIL_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON host allowlist |
| `AGENT_GUARDRAIL_UPSTREAM_AUTH_MODE` | `server_managed` | `server_managed/pass_through` |
| `AGENT_GUARDRAIL_UPSTREAM_API_KEY` | server-managed 时必填 | Model Provider 上游 Key |
| `AGENT_GUARDRAIL_ANTHROPIC_UPSTREAM_BASE_URL` | 空 | 固定 Anthropic base URL，如 `https://api.anthropic.com` |
| `AGENT_GUARDRAIL_ANTHROPIC_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON Anthropic host allowlist |
| `AGENT_GUARDRAIL_ANTHROPIC_UPSTREAM_API_KEY` | Anthropic 模式必填 | 独立 Anthropic Provider Key |
| `AGENT_GUARDRAIL_GATEWAY_API_KEYS` | 空 | JSON 客户端 Key；生产应配置 |
| `AGENT_GUARDRAIL_AUDIT_PATH` | 空 | 设置后启用 JSONL Audit |
| `AGENT_GUARDRAIL_LOG_LEVEL` | `info` | Uvicorn 日志级别 |
| `AGENT_GUARDRAIL_MAX_REQUEST_BYTES` | `1048576` | 请求体上限 |
| `AGENT_GUARDRAIL_MAX_UPSTREAM_RESPONSE_BYTES` | `4194304` | 非流式响应或完整 SSE 流字节上限 |
| `AGENT_GUARDRAIL_MAX_TRACE_EVENTS` | `16` | 请求级 Trace Event 上限 |
| `AGENT_GUARDRAIL_UPSTREAM_TIMEOUT_SECONDS` | `60` | 非流式网络 timeout；完整 SSE 流 wall-clock 上限 |
| `AGENT_GUARDRAIL_DETECTOR_PROFILE` | `local` | `local/full_deberta/full_promptguard2/promptguard2` 部署 preset（与组件变量互斥）|
| `AGENT_GUARDRAIL_DETECTOR_PII` | 空 | 逐组件配置：`none/presidio`（见"逐组件 Detector 配置"）|
| `AGENT_GUARDRAIL_DETECTOR_SEMGREP` | 空 | 逐组件配置：`none/python_rules` |
| `AGENT_GUARDRAIL_DETECTOR_YARA` | 空 | 逐组件配置：`none/injection_rules` |
| `AGENT_GUARDRAIL_DETECTOR_PROMPT_MODEL` | 空 | 逐组件配置：`none/deberta_v2/promptguard2` |
| `AGENT_GUARDRAIL_PROMPT_MODEL_THRESHOLD` | 空 | PI 分类器操作点；缺省 deberta_v2 0.85 / promptguard2 0.9 |
| `AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR` | 空 | 模型组件/preset 必填的已校验模型资产根目录 |
| `AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE` | `cpu` | 模型组件/preset 的 `cpu/cuda` 推理设备 |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_URL` | MCP 模式必填 | 固定 MCP endpoint |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_ALLOWED_HOSTS` | 空 | JSON MCP host allowlist |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_AUTH_MODE` | `none` | `none/server_managed/pass_through` |
| `AGENT_GUARDRAIL_MCP_UPSTREAM_API_KEY` | MCP server-managed 时必填 | MCP 上游 Key |
| `AGENT_GUARDRAIL_MCP_ALLOWED_ORIGINS` | 空 | JSON Origin allowlist |
| `AGENT_GUARDRAIL_MCP_TIMEOUT_SECONDS` | `60` | MCP 上游总超时 |
| `AGENT_GUARDRAIL_MCP_MAX_RESPONSE_BYTES` | `4194304` | MCP 响应体上限 |

至少配置通用/OpenAI、Anthropic 或 MCP 三类上游之一。固定 URL 不能含凭据、query 或 fragment；配置非空 host allowlist 时 hostname 必须匹配。Anthropic 当前只有 server-managed 模式，Gateway 固定使用 `x-api-key` 与稳定 API version header；入站 SDK Key 不能当成上游 Key 转发。

Core 使用独立前缀：`AGENT_GUARDRAIL_CORE_POLICY_FILE` 与 `AGENT_GUARDRAIL_CORE_API_KEY` 必填；`AGENT_GUARDRAIL_CORE_DETECTOR_PROFILE` 默认 `local`，双容器镜像默认覆盖为 `full_deberta`；另有 `..._DETECTOR_ASSETS_DIR`、`..._PROMPT_MODEL_DEVICE`、`..._MAX_REQUEST_BYTES`、`..._HOST`、`..._PORT` 和 `..._LOG_LEVEL`。事实来源是 `CoreSettings`。

## 5. 凭据

- 示例只写变量名，不含真实值。
- 开发可使用已 gitignore 的 `.env`；生产使用部署平台 Secret。
- Key 不进入 Trace、Finding、Violation、Audit、异常或访问日志。
- `server_managed` 使用服务端 Key；`pass_through` 才转发客户端 Authorization。
- Gateway→Core Key 必须与 Provider、MCP 和 Gateway Client Key 分离；Core 不配置任何上游 Key。

## 6. 审计记录

设置 `AGENT_GUARDRAIL_AUDIT_PATH` 后，只追加写入的 JSONL 文件保存含 Violation 的脱敏 Decision 摘要；普通 allow 不逐条持久化。Audit 不接收 Event payload、完整 prompt、Tool arguments 或 Detector 原文。若增加内容取证模式，需要在架构合同中定义访问权限、脱敏和保留期。

## 7. 健康检查与可观测性

- `GET /health/live`：进程和事件循环存活。
- Gateway `GET /health/ready`：embedded 报告本地 Runtime；remote 同时验证 Core readiness 与启动时固定的 Policy identity。
- Core `GET /health/ready`：报告固定 Policy、Registry、模型 warm-up 和 Runtime ready。

Policy 编译、检测能力连接、Settings 和可选检测配置在应用构造阶段失败会阻止启动。`full_deberta` 构造会验证固定资产与 Semgrep 版本，并对模型做一次本地 warm-up。Readiness 不探测模型服务/MCP 上游网络，也不验证审计路径是否可写。

当前可观测性包括 Uvicorn 日志级别和可选 JSONL Audit；结构化应用日志、Metrics、OpenTelemetry、SBOM、镜像签名、热加载和集群编排列在[roadmap](../roadmap.md)。
