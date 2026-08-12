# Agent Guardrail

**面向 AI Agent 的可解释 Policy Analyzer 与 Enforcement Gateway。**

[English](README.md) | 简体中文

[![Version](https://img.shields.io/badge/version-0.1.0-3b82f6)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-f59e0b)](docs/roadmap.md)
[![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Agent Guardrail 在 LLM 和 Tool 边界前后执行显式、失败安全的 Policy 检查。它把严格 YAML Policy 编译为
不可变 MatchPlan，分析类型化 Agent Event，并在受保护数据或副作用释放前给出可解释 Decision。

项目聚焦三类资产：**用户数据、用户意图和用户资源**。Detector 命中只是证据，不会单独成为安全结论；
Policy 还需要把这些事实与可信的 source、destination、owner 和 authorization 语境组合。

> **项目状态 — v0.1.0 alpha。** Core Runtime、Inline Wrapper、非流式 OpenAI-compatible Gateway、
> 无状态 MCP Gateway 和远程 Core 路径已经实现并通过测试。当前版本不是完整 Sandbox、流式代理或多租户
> 控制平面。

## 为什么使用 Agent Guardrail？

- **不只检测，还执行约束。** `pre_llm` 阻断时不会请求模型；`pre_tool` 阻断时不会执行工具。
- **唯一、可审计的 Policy 链。** 严格 `version: 3` YAML 进入 `MatchPlan → AnalysisReport → Decision`，
  不存在第二套生产解释器。
- **Policy 不是可执行载荷。** YAML 不能 import Python、注册 callback、选择文件或网络 endpoint，也不能
  获得任意 I/O 权限。
- **类型化 Trace 与显式 Relation。** Message、ToolCall、ToolResult 都是不可变 Event；时间先后不会被
  静默当作 provenance。
- **部署方拥有 capability。** 模型、规则集、进程和凭据由部署选择，Policy 只能看到审查过的 capability
  名称与有界参数。
- **默认脱敏。** Finding、Violation、Error 和可选 Audit 保存结构化遮罩证据，不保存原始 Secret、PII
  或 prompt。

## 架构

```mermaid
flowchart LR
    A[Agent 或 Client] --> B[Inline / OpenAI / MCP Adapter]
    B --> C[EnforcementSession]
    C -->|PendingTrace| D[Embedded Runtime 或 Remote Core]
    D --> E[Policy v3 → MatchPlan → SnapshotMatcher]
    E -->|AnalysisReport| F[Decision Analyzer]
    F -->|allow / log / block| C
    C -->|pre allow / post release| G[LLM 或 Tool 边界]
    C -->|脱敏 Violation| H[(Audit)]
```

四个 Enforcement Point 复用同一套 Policy 语义：

```text
request → pre_llm → LLM → post_llm → Agent → pre_tool → Tool → post_tool → Agent
```

分析始终读取已提交 Trace 加完整 pending Event batch。allow/log 会原子提交整批 Event；block 会丢弃原始
pending Event，只提交脱敏 Decision Event。

## 快速开始

需要 Python 3.12 或更高版本，以及 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/cipeizheng/agent-guardrail.git
cd agent-guardrail
uv sync --frozen --extra gateway --dev
uv run python examples/secret_email_demo.py
```

演示使用确定性的 Fake Model 和 Fake Tool，不需要 API Key。关键输出是：

```text
blocked at: post_llm
llm executions: 1
send_email executions: 0
```

模型提出了包含 Secret 的 ToolCall，但受保护的邮件工具完全没有执行。

## Policy 是数据，不是代码

下面的 Policy 会在 `send_email` 参数包含 Secret 时阻断 ToolCall：

```yaml
version: 3

engine:
  on_analysis_error: block
  on_detector_timeout: block

scopes: [pending]

rules:
  - id: prevent-secret-email
    action: block
    events:
      call:
        kind: tool_call
        domain: pending
        phases: [post_llm, pre_tool]
    where:
      all:
        - tool: {binding: call, name: send_email}
        - detector:
            id: secret_scan
            capability: secrets
            inputs:
              - value: {field: [call, payload, arguments]}
                encoding: canonical_json
    finding:
      code: secret_exfiltration
      message: The tool call contains secret material.
      subjects: [call]
      evidence: [{source: detector, id: secret_scan}]
```

Runtime 激活前，Loader 会拒绝重复键、未知字段、宽松类型、YAML alias/tag、非法引用和不可用 capability。
binding、relation、quantifier、派生值、Finding、预算和可信安全参数见
[Policy 作者指南](docs/guides/policy-authoring.md)。

## 接入方式

| 接入方式 | 适用场景 | 当前保证 |
| --- | --- | --- |
| Inline Wrapper | 可以注入 LLM 与 Tool 接口 | 中介经过共享任务级 Session 的调用 |
| OpenAI-compatible Gateway | Agent 可以修改 OpenAI base URL | 检查完整请求和非流式响应 |
| MCP Gateway | Tool 来自固定 MCP Server | 每个无状态 `tools/call` 都经过执行前后检查 |
| Remote Core | Policy/Detector 资产需要与边缘流量隔离 | Gateway 持有流量和副作用，Core 分析完整 `PendingTrace` |
| Docker Compose | 自托管 Core + Gateway | 只读容器、Core 私网、Provider/Core 凭据隔离 |

OpenAI Client 只需要修改 base URL：

```python
from openai import OpenAI

client = OpenAI(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080/v1/openai",
)
```

MCP Python SDK v2：

```python
from mcp import Client

async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    result = await client.call_tool("send_email", {"to": "outside@example.com"})
```

生命周期和协议细节见[接入指南](docs/guides/integration.md)与
[Gateway 协议参考](docs/reference/gateway-protocol.md)。

## Capability

默认 `local` Registry 不下载模型，发布：

- Detector：`secrets`、`pii`、`prompt_injection`、`unicode_security`、
  `python_ast_ipython`、`hidden_content`。
- 纯 Predicate：`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`。

部署固定的可选能力与默认目录明确分离：

| 可用方式 | Capability | Backend 边界 |
| --- | --- | --- |
| `full_local_v1` | `prompt_injection_model` | 锁定 Protect AI DeBERTa checkpoint，本地 CPU/CUDA 推理 |
| `full_local_v1` | 增强 `pii` | 锁定 Presidio/spaCy 英文 NER，加本地 validator |
| `full_local_v1` | `semgrep` | 隔离且锁定版本的 CLI 与包内 Python ruleset |
| `full_local_v1` | `yara_injection_signatures` | 锁定 yara-python、包内 ruleset 与固定 rule-to-type 映射 |
| 显式注入 | `is_similar` | 部署选择的 `EmbeddingProfile` 和异步 embedding backend |

`is_similar` 当前状态为 `adapter_only`：Schema、预算、timeout、脱敏和 Enforcement 路径已经测试，但真实
外部 embedding 服务尚未达到 verified。所有 capability 的准确、非营销状态只以
[Capability 状态矩阵](docs/capability-status.yaml)为准。

## 部署 Profile

### 默认本地 Profile

默认 profile 轻量且确定性执行，不加载 Transformers、Presidio、Semgrep、YARA 或远程 embedding client。

### 完整本地 Profile

`full_local_v1` 在启动前固定并校验 Detector 依赖和模型资产：

```bash
uv sync --frozen --extra gateway --extra detectors --no-dev
uv tool install semgrep==1.170.0
export AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/var/lib/agent-guardrail/detectors
uv run agent-guardrail-prefetch-detectors
export AGENT_GUARDRAIL_DETECTOR_PROFILE=full_local_v1
```

依赖、版本、checksum 或所选 CUDA 设备不符合 profile 时，Runtime 会拒绝启动。Policy YAML 仍不能替换
这些选择。

### Docker Compose

```bash
cp .env.example .env
# 替换 .env 中的全部占位值。
docker compose build
docker compose up -d
curl --fail http://127.0.0.1:8080/health/ready
```

Core 镜像包含完整 Detector profile，因此体积较大。在本地环境之外部署前请先阅读
[运行指南](docs/guides/operations.md)。

## 当前边界

Agent Guardrail 只能中介实际经过 Wrapper 或 Gateway 的流量。当前不提供：

- 实时 LLM streaming enforcement；
- 跨请求 Session 状态或 Policy 热更新；
- 完整多租户 identity/authorization 控制平面；
- 对直接 Shell、函数、文件系统或任意 HTTP 的 Sandbox/拦截；
- Web 管理界面或分布式 Policy 服务；
- Moderation、copyright 或 OCR capability。

Detector 命中不能证明恶意意图、数据所有权或授权。生产 Rule 应当把 Detector fact 与可信 source/sink
语境组合。权威边界以[当前架构合同](docs/current-architecture-contract.md)和
[安全模型](docs/security-model.md)为准。

## 文档

| 阅读内容 | 适用场景 |
| --- | --- |
| [文档导航](docs/README.md) | 为当前任务选择最短阅读路径 |
| [架构概览](docs/overview.md) | 理解 Event、MatchPlan、Runtime 和 Enforcement |
| [Policy 作者指南](docs/guides/policy-authoring.md) | 编写严格生产 YAML Policy |
| [Capability 参考](docs/reference/capabilities.md) | 使用 Detector、Predicate 与可选 backend |
| [接入指南](docs/guides/integration.md) | 接入 Agent、OpenAI Client 或 MCP Client |
| [运行指南](docs/guides/operations.md) | 配置 Secret、profile、Docker、Audit 和 Health |
| [安全模型](docs/security-model.md) | 审查资产、信任边界和 T01–T10 |
| [Roadmap](docs/roadmap.md) | 查看规划且不与已交付行为混淆 |

## 开发

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
git diff --check
```

欢迎参与贡献。请从 [CONTRIBUTING.md](CONTRIBUTING.md) 开始；架构和安全修改必须继续遵守仓库内已有合同。

## License

Agent Guardrail 使用 [MIT License](LICENSE)。
