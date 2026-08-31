# Gateway 与 Core 运行指南

> 适合谁：启动和运维 embedded Gateway 或 Core/Gateway 双容器的人。
> 解决什么：安装、容器、环境变量、Secret、Audit 和健康检查。
> 不包含什么：集群编排、Policy 热加载或跨进程/持久化 Session Store。

## 1. Embedded 启动

```bash
uv sync --frozen --extra gateway --no-dev
uv run python -m agent_guardrail.gateway
```

进程内包含 FastAPI Gateway、一个 GuardrailRuntime、固定 Model Provider/MCP 上游客户端和可选 JSONL
AuditSink。
该 embedded 模式不依赖数据库或远程 Core。可选 task-session Store 只保存在本 Gateway 进程内存中，进程
退出即丢失。

### 完整本地 Detector profile

默认 `local` profile 不加载可选模型。启用已真实验证的 `full_deberta`：

```bash
uv sync --frozen --extra gateway --extra detectors --no-dev
uv tool install semgrep==1.170.0
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-detectors
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_deberta
export AGENT_GUARDRAIL_PROMPT_MODEL_DEVICE=cpu
uv run python -m agent_guardrail.gateway
```

有可用 CUDA 设备时可把最后一个设备值改为 `cuda`。Presidio/spaCy 继续运行在 CPU；CUDA 只用于固定的
提示注入模型。Semgrep 独立安装是有意的：Semgrep 1.170.0 锁定 MCP 1.x，而 Gateway 使用 MCP 2.x，隔离
工具环境避免依赖冲突。

资产预取固定模型 repository、commit、文件集合、字节数和 SHA-256；写入只在单个文件完整校验后原子完成。
Runtime 构造 profile 时再次逐项校验，且强制 Transformers 离线读取该目录。运行时不下载模型，也不从
Policy 接受模型、规则、路径、命令或 device。缺失或不匹配会阻止启动。

### PromptGuard 2 候选 profile（可选，非默认）

`full_promptguard2` 与 `full_deberta` 栈相同（Presidio/spaCy、Semgrep、YARA），仅把 DeBERTa
PI 分类器换成 Meta PromptGuard 2 86M（评分路径对齐 LlamaFirewall：全空白剥离后重分词、截断 512、
MALICIOUS 类概率）；`promptguard2` 只装载本地启发式栈 + PromptGuard 2，不加载 Presidio/Semgrep/YARA，
适合隔离评估分类器贡献。两者部署默认阈值 0.9（LlamaFirewall 拦截阈值，实测 operating point）。

```bash
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-promptguard2
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_promptguard2
```

**License 注意**：PromptGuard 2 权重采用 Llama 4 Community License（非 MIT；含月活 7 亿上限条款，
再分发需遵守协议并附 "Built with Llama" 署名）。因此这两个 profile 是显式 opt-in 的候选 profile，
绝不作为默认部署；`full_deberta`（MIT 栈 + Apache-2.0/Protect AI DeBERTa）保持默认。原始权重位于
人工审批 gate 的 `meta-llama/Llama-Prompt-Guard-2-86M`，本项目 pin 未 gate 的 `gravitee-io` 镜像中
字节一致的 `model.safetensors`（镜像声明 base_model 与 llama4 license），provenance 记录在
`config/deployment.py` 的 pin 常量注释中。资产校验与 `full_deberta` 相同（逐文件 size + SHA-256）。

### 逐组件 Detector 配置（自由组合）

preset 之外，可以按组件逐个开关（与 `AGENT_GUARDRAIL_DETECTOR_PROFILE` 互斥，非 `local`
preset 与任一组件变量同时设置会拒绝启动）：

| 环境变量 | 取值 | 说明 |
|---|---|---|
| `AGENT_GUARDRAIL_DETECTOR_PII` | `none`/`presidio` | Presidio/spaCy NER backend |
| `AGENT_GUARDRAIL_DETECTOR_SEMGREP` | `none`/`python_rules` | 外部 Semgrep CLI + 包内 ruleset |
| `AGENT_GUARDRAIL_DETECTOR_YARA` | `none`/`injection_rules` | yara-python + 包内 ruleset |
| `AGENT_GUARDRAIL_DETECTOR_PROMPT_MODEL` | `none`/`deberta_v2`/`promptguard2` | PI 分类器（单槽位，二选一） |
| `AGENT_GUARDRAIL_PROMPT_MODEL_THRESHOLD` | `(0, 1]` | 缺省：deberta_v2 0.85 / promptguard2 0.9 |

```bash
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
export AGENT_GUARDRAIL_DETECTOR_PII=presidio
export AGENT_GUARDRAIL_DETECTOR_PROMPT_MODEL=promptguard2
```

**自由组合的边界**：每个组件各自通过单元与集成验证，校验规则（模型组件要求 assets_dir、
Semgrep 要求 CLI 严格 1.170.0、CUDA 可用性、资产哈希）逐项 fail-closed；但组件**组合本身**
可能未经端到端一致性验证，风险由部署方评估。已验证姿态仍以 preset 名字标注
（`full_deberta` 为 verified 全栈）；组件组合是它的子集/超集自由拼写，不是新的保证。
Core 侧使用 `AGENT_GUARDRAIL_CORE_` 前缀的同名变量。

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
必须把该 endpoint 作为获准的数据接收方并配置传输、保留和数据隔离边界，或者注入本地
`EmbeddingBackend`。
Policy 不能借此改写 endpoint/model/凭据，但这一限制不能替代部署侧的数据授权。

## 2. 双容器启动

仓库只定义两个运行服务：`core` 持有 Policy、完整 Detector 资产和分析 Runtime；`gateway` 持有 Provider/
MCP 配置、请求级/任务级 Trace、Audit 和副作用顺序。CPU/CUDA 是 Core 的运行配置，不会创建第三个服务。

```bash
cp .env.example .env
# 编辑 .env 中的 Core 服务 Key、Gateway 客户端 Key 和 Provider 配置
docker compose build
docker compose up -d
curl --fail http://127.0.0.1:8080/health/ready
```

Core 构建会安装 `full_deberta` 的 Presidio/spaCy、固定 DeBERTa checkpoint、Semgrep 和 YARA，并在构建期
下载后校验约 750 MB 的模型资产，因此首次构建较慢且镜像较大。运行时为离线模式。Compose 只发布 Gateway
的 8080；Core 8090 只连接内部网络。Policy 只读挂载到 Core，Audit volume 只挂载到 Gateway，两个容器均
non-root、只读 root filesystem、drop capabilities 并使用 `/tmp` tmpfs。Core 镜像把 `HOME` 与 `XDG_*`
缓存重定向到 `/tmp`：只读 rootfs 下若沿用默认 `$HOME`，`semgrep --version` 等 Tool 在 `$HOME/.semgrep`
建日志目录会直接失败并使 `full_deberta` 无法启动——preset 换装时不得移除这两个 ENV 的重定向。

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

## 3. Agent Sandbox 与不可绕过部署边界

本仓库的 Compose 只运行可信的 Core 和 Gateway，**没有启动或隔离 Agent**。容器的 non-root、只读 root
filesystem、drop capabilities 和 Core 私网用于加固 Guardrail 服务本身，不能证明 Agent 的 Shell、原生
函数、文件系统或网络请求都经过 Gateway。

如果 Agent 可以执行代码或 Shell，生产部署应把它放入独立的不可信 Sandbox，并把 Guardrail、真实 Tool
Broker 和凭据留在 Sandbox 外。最低部署合同是：

- Agent egress 默认拒绝，只允许固定 Guardrail Gateway/Tool Broker；禁止直连 Provider、MCP Server、
  数据库、邮件/云 API，并覆盖 DNS、IPv4/IPv6、loopback、Unix socket 和云 metadata 路径；
- Sandbox 不含 Provider、MCP、数据库或其他生产凭据；凭据只由外部服务持有并按用户授权使用；
- 不使用 privileged、host network/PID/IPC，不挂载 Docker/container runtime socket、宿主敏感目录或多余
  设备；
- 文件系统默认只读或按任务临时创建，只挂载完成任务所需的最小目录，不允许后台进程跨任务存活；
- 设置 CPU、内存、PID、磁盘、文件描述符和 wall-clock 上限，并能在超限时终止整个 Sandbox；
- Sandbox 内的 Agent 不能修改 Policy、Gateway/Core 配置、Detector 资产或 Audit；内部 Wrapper/探针失效
  不能扩大 Sandbox 的网络或主机权限。

仅把代码/Shell 工具放进 Sandbox 也可以：此时 Agent 与 Guardrail 位于外部，`before_tool_call` allow 后
才调用 Sandbox Executor，`before_tool_output_release` allow 后才释放结果。该 Executor 仍应无生产凭据、
无任意公网 egress，并按
任务销毁。

`url_host_allowed`、命令/代码 Detector 或 Provider/MCP host allowlist 都是已中介流量上的策略或纵深防御，
不能代替上述 OS/网络强制。完整的责任矩阵见[安全模型](../security-model.md#8-guardrail-无法替代的-sandbox-控制)。

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
| `AGENT_GUARDRAIL_TASK_SESSIONS_REQUIRED` | `false` | 要求 Model 与 MCP `tools/call` 使用任务 Session |
| `AGENT_GUARDRAIL_TASK_SESSION_MAX_SESSIONS` | `128` | 单进程同时保留的任务 Session 上限 |
| `AGENT_GUARDRAIL_TASK_SESSION_TTL_SECONDS` | `1800` | 任务 Session 滑动 TTL |
| `AGENT_GUARDRAIL_TASK_SESSION_MAX_TRACE_EVENTS` | `256` | 每个任务级 Trace Event 上限 |
| `AGENT_GUARDRAIL_UPSTREAM_TIMEOUT_SECONDS` | `60` | 非流式网络 timeout；完整 SSE 流 wall-clock 上限 |
| `AGENT_GUARDRAIL_DETECTOR_PROFILE` | `local` | `local/full_deberta/full_promptguard2/promptguard2` 部署 preset（与组件变量互斥） |
| `AGENT_GUARDRAIL_DETECTOR_PII` | 空 | 逐组件配置：`none/presidio`（见"逐组件 Detector 配置"） |
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

至少配置通用/OpenAI、Anthropic 或 MCP 三类上游之一。固定 URL 不能含凭据、query 或 fragment；配置非空
host allowlist 时 hostname 必须匹配。Anthropic 当前只有 server-managed 模式，Gateway 固定使用
`x-api-key` 与稳定 API version header；入站 SDK Key 不能当成上游 Key 转发。

创建任务级 Trace：

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/guardrail/task-sessions \
  -H "Authorization: Bearer $GATEWAY_CLIENT_KEY"
```

响应中的 `session_token` 应只由可信 Agent Host 保存在控制通道；后续 Model 与 MCP `tools/call` 请求通过
`X-Agent-Guardrail-Session` header 携带。执行模型产生的工具建议时，Host 还应把 provider 返回的 `call_id`
放入 `X-Agent-Guardrail-Proposal-Id`；Gateway 会校验工具名和参数后建立 proposal→实际 ToolCall Relation。
任务结束后用同一 session header 请求 `DELETE /v1/guardrail/task-sessions`。token 不代表用户身份或业务授权，
不得写入 prompt、Audit 或应用日志。生产要依赖跨边界关系时应设置
`AGENT_GUARDRAIL_TASK_SESSIONS_REQUIRED=true`，并让 Agent 只能访问受控 Gateway 上游。

Core 使用独立前缀：`AGENT_GUARDRAIL_CORE_POLICY_FILE` 与
`AGENT_GUARDRAIL_CORE_API_KEY` 必填；`AGENT_GUARDRAIL_CORE_DETECTOR_PROFILE` 默认 `local`，双容器镜像
默认覆盖为 `full_deberta`；另有 `..._DETECTOR_ASSETS_DIR`、`..._PROMPT_MODEL_DEVICE`、
`..._MAX_REQUEST_BYTES`、`..._HOST`、`..._PORT` 和 `..._LOG_LEVEL`。事实来源是 `CoreSettings`。

## 5. Secret

- 示例只写变量名，不含真实值。
- 开发可使用已 gitignore 的 `.env`；生产使用部署平台 Secret。
- Key 不进入 Trace、Finding、Violation、Audit、异常或访问日志。
- `server_managed` 使用服务端 Key；`pass_through` 才转发客户端 Authorization。
- Gateway→Core Key 必须与 Provider、MCP 和 Gateway Client Key 分离；Core 不配置任何上游 Key。

## 6. Audit

设置 `AGENT_GUARDRAIL_AUDIT_PATH` 后，append-only JSONL 只保存含 Violation 的 Decision 摘要；普通 allow
不逐条持久化。它不接收 Event payload、完整 prompt、Tool arguments 或 Detector 原文。

当前没有内容取证模式。保存原始敏感内容必须先改变架构合同并定义访问权限、脱敏和保留期。

## 7. Health 与可观测性

- `GET /health/live`：进程和事件循环存活。
- Gateway `GET /health/ready`：embedded 报告本地 Runtime；remote 同时验证 Core readiness 与启动时固定的
  Policy identity。
- Core `GET /health/ready`：报告固定 Policy、Registry、模型 warm-up 和 Runtime ready。

Policy 编译、capability linking、Settings 和可选 Detector profile 在应用构造阶段失败会阻止启动。
`full_deberta` 构造会验证固定资产与 Semgrep 版本，并对模型做一次本地 warm-up。Readiness 不探测
Provider/MCP 上游网络，也不验证 Audit 路径可写性。

当前只有 Uvicorn 日志级别和可选 JSONL Audit，没有结构化应用日志、Metrics、OpenTelemetry、SBOM、镜像
签名、热加载或集群编排；这些仍在[roadmap](../roadmap.md)安排。
