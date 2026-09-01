# Agent Guardrail

**面向 AI Agent 的安全控制层。**

[English](README.md) | 简体中文

[![Version](https://img.shields.io/badge/version-0.1.0-3b82f6)](pyproject.toml) [![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](pyproject.toml) [![Status](https://img.shields.io/badge/status-alpha-f59e0b)](docs/roadmap.md) [![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Agent Guardrail 会在模型请求、模型输出、工具调用和工具结果进入下一步前，根据 YAML 规则进行检查，并执行放行、记录或拦截。

它会保留消息、模型调用和工具调用之间的关系，并生成脱敏的检查结果、错误信息和审计记录。

## 项目状态

当前版本为 v0.1.0 alpha。项目提供应用内接入和 HTTP Gateway 接入，支持 OpenAI、Anthropic 和 MCP，并支持将规则分析服务单独部署。Responses 的 `previous_response_id` 可通过 Gateway 显式注入的进程内状态存储，或外部 Agentic API 拓扑使用。当前外部集成使用一个 Agentic API 实例和 SQLite；部署面向单个用户，沙箱、身份管理、持久化和资源隔离由宿主环境负责。

## 快速开始

需要 Python 3.12 或更高版本，以及 [uv](https://docs.astral.sh/uv/)。

```bash
git clone https://github.com/cipeizheng/agent-guardrail.git
cd agent-guardrail
uv sync --frozen --extra gateway --dev
uv run python examples/secret_email_demo.py
```

演示使用本地的模型和工具实现，不需要 API Key。模型调用会执行，邮件工具调用会在执行前被拦截。输出的最后三行如下：

```text
policy decision: block
model executions: 1
send_email executions: 0
```

## 规则配置

项目使用 version-3 YAML 编写安全规则。下面的规则检查 `send_email` 工具调用；当参数包含密钥或其他敏感凭据时，在工具执行前拦截调用。

```yaml
version: 3
scopes: [pending]
rules:
  - id: prevent-secret-email
    action: block
    events:
      call: {kind: tool_call_proposal, domain: pending}
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
      message: 工具调用参数包含敏感凭据。
      subjects: [call]
      evidence: [{source: detector, id: secret_scan}]
```

规则加载时会检查格式、引用、资源限制和可用检测能力。完整语法见[规则编写指南](docs/guides/policy-authoring.md)。

## 内置检测能力

默认的 `local` 配置不需要下载模型或连接外部服务，提供以下本地检测。表中名称用于规则文件：

| 可以检查什么 | 用途 | 规则中的名称 |
| --- | --- | --- |
| 密钥和凭据 | 发现私钥、云服务密钥和 API token 等敏感信息 | `secrets` |
| 个人信息 | 发现邮箱、电话、身份证件和金融账号等固定类型 | `pii` |
| 可疑提示注入 | 发现覆盖指令、系统提示泄露和角色替换等高信号模式 | `prompt_injection` |
| 隐藏或不可见内容 | 发现 Unicode 控制字符、零宽字符和有限脚本混淆 | `unicode_security` |
| Python 代码结构 | 识别 import、危险调用和语法等结构事实 | `python_ast_ipython` |
| 隐藏网页内容 | 发现隐藏 HTML、注释和有限编码内容 | `hidden_content` |
| 数值或长度范围 | 检查数值、文字、数组或对象是否在指定范围 | `number_in_range`、`length_in_range` |
| 网址主机白名单 | 检查 HTTP(S) 地址是否属于允许的主机 | `url_host_allowed` |
| 文字近似匹配 | 在有界编辑距离内查找相近文字 | `fuzzy_contains` |

其他检测能力及其接入方式和状态见[能力状态表](docs/capability-status.yaml)；详细说明见[能力参考](docs/reference/capabilities.md)和[运行指南](docs/guides/operations.md)。

检测结果只是安全信号。生产规则还应结合数据来源、去向、授权状态，以及消息、模型调用和工具调用之间的关系。

## 部署与安全

Guardrail 检查通过 SDK 提交的事件和经过 Gateway 的请求。使用 SDK 时，应用在执行操作前读取返回的决定；Gateway 则按固定顺序检查模型和 MCP 请求。能够执行 Shell、任意代码、直接网络请求或宿主操作的 Agent 还需要独立沙箱，并设置默认拒绝的网络访问、最小化的临时存储和资源上限。Provider 或 Tool 凭据、审计存储应位于沙箱之外。[安全模型](docs/security-model.md)和[运行指南](docs/guides/operations.md)说明双方责任。

当前部署面向单个用户，默认 Compose 只启动 Gateway。[Responses 状态层设计](docs/design/responses-state-layer.md)说明了 Gateway 状态接口，以及使用 vLLM Agentic API 和 SQLite 作为外部状态所有者的接入拓扑。后续工作见[路线图](docs/roadmap.md)；当前行为以[当前架构合同](docs/current-architecture-contract.md)为准。

## 文档

| 阅读内容 | 用途 |
| --- | --- |
| [文档导航](docs/README.md) | 按任务选择最短阅读路径 |
| [架构概览](docs/overview.md) | 理解事件、规则、运行过程和执行控制主线 |
| [规则编写指南](docs/guides/policy-authoring.md) | 编写 version-3 YAML |
| [接入指南](docs/guides/integration.md) | 接入应用代码、模型客户端和 MCP |
| [能力参考](docs/reference/capabilities.md) | 检测器和条件判断的使用边界 |
| [Gateway 协议参考](docs/reference/gateway-protocol.md) | HTTP、流式响应和 MCP 行为 |
| [Responses 状态层设计](docs/design/responses-state-layer.md) | `previous_response_id` 状态接口与外部状态所有者边界 |
| [运行指南](docs/guides/operations.md) | 配置、环境变量、Docker、审计和健康检查 |
| [安全模型](docs/security-model.md) | 资产、信任边界和 T01–T10 |
| [独立分析服务设计](docs/design/remote-core-deployment.md) | 部署独立的规则分析服务 |

## 开发

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
git diff --check
```

开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Agent Guardrail 源码使用 [MIT License](LICENSE)。可选检测模型和依赖保留各自的上游许可证；部署模型配置前请阅读[运行指南](docs/guides/operations.md)。
