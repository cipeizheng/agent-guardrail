# Agent Guardrail

一个面向 AI Agent 的 Invariant 风格、可解释 Policy Analyzer 与 Enforcement Gateway。

项目使用一等 Event、显式 Relation 和 `past + pending` whole-pending 分析。唯一生产 Policy 是严格
`version: 3` YAML，经 AuthorPolicy、MatchPlan、可信 capability linking 和有界 SnapshotMatcher 生成
AnalysisReport，再失败安全地投影为 Decision。YAML 不能执行 Python、import、callback 或 I/O。

核心保护目标是用户的数据、意图和资源。Detector 只产生事实；完整安全判断还必须结合可信
source/sink、owner、destination 和 authorization。当前架构、不变量与未交付边界以
[当前架构合同](docs/current-architecture-contract.md)为准。

## 当前状态

Core v0.1.0 已提供 Inline LLM/Tool、OpenAI-compatible 非流式 Gateway 和 MCP `2026-07-28` 无状态
Gateway。所有接入复用同一 Runtime/EnforcementSession 语义：`pre_llm/pre_tool` 通过前不发生受保护
副作用，非流式 `post_llm/post_tool` 通过前不释放原始结果。

默认 capability 的准确名称、覆盖范围和验证状态分别见[Capability 参考](docs/reference/capabilities.md)
与[状态矩阵](docs/capability-status.yaml)；未来工作只在[roadmap](docs/roadmap.md)维护。

当前默认 Registry 发布 8 个本地 Detector：`secrets`、`pii`、`prompt_injection`、`jailbreak`、
`dangerous_command`、`unicode_security`、`python_ast_ipython`、`hidden_content`；以及 5 个纯 Predicate：
`number_in_range`、`length_in_range`、`url_host_allowed`、`fuzzy_contains`、`embedding_similarity`。
`prompt_injection_model`、带 Presidio/PIIBackend 的 `pii`、`semgrep` 和 `yara_injection_signatures` 只在
部署代码固定 backend/profile 并显式注入后发布；文本 embedding 在 Policy 执行外预计算。项目不把
adapter fake 测试写成真实后端已验证。

## 核心目标

- 在 LLM 调用和工具执行前后提供明确检查点。
- 保证 `pre_tool` 返回 `block` 时工具绝不执行。
- 将 Detector、Finding、Decision 与 Enforcement 分离。
- 使用统一 Event/Trace 模型隔离不同 Agent 和模型供应商格式。
- 使用同一 Trace 内经过校验的来源边表达事件关系，不把时间先后当成数据流。
- 原子分析本次新增的 pending Event，避免只匹配历史 Event 就重复阻断当前操作。
- 同时提供内联 SDK、OpenAI HTTP Gateway 与 MCP HTTP Gateway。
- 默认可完全本地运行，并为后续单容器 Docker 部署保持单进程拓扑。
- Decision 结构可解释、可测试；包含 Violation 的 Decision 可通过可选 AuditSink 脱敏审计。

## 非目标

- 当前版本不交付 CEL 或 Invariant Policy Language。
- 当前版本不支持 Python Rule 或任意 Python 策略上传。
- 当前不支持 LLM 实时流式响应安全拦截；MCP 请求级 SSE 会完整、有界缓冲后再做 `post_tool`。
- 当前不提供完整 Web UI、多租户或分布式控制平面。
- 用 LLM 生成未经验证就直接启用的策略。

## 文档

- [文档导航](docs/README.md)
- [当前架构合同](docs/current-architecture-contract.md)
- [安全模型](docs/security-model.md)
- [Capability 状态矩阵](docs/capability-status.yaml)
- [开发路线图](docs/roadmap.md)

## 本地开发

```bash
cd /home/chenzheng/agent-guardrail
uv sync --extra gateway --dev
uv run pytest
uv run ruff check .
uv run pyright
```

### VS Code / Pylance

仓库已将解释器固定为 `${workspaceFolder}/.venv/bin/python`，并将 `src` 加入 Pylance 和
Pyright 分析路径。首次打开仓库时，如果状态栏仍显示其他 Python：

1. 执行 `Python: Select Interpreter`。
2. 选择项目内 `.venv/bin/python`。
3. 执行 `Developer: Reload Window` 或 `Pylance: Restart Language Server`。

请直接以 `agent-guardrail` 为 VS Code workspace 根目录打开，不要只打开单个 Python 文件。

只安装 Gateway 运行依赖（不安装开发工具）：

```bash
uv sync --frozen --extra gateway --no-dev
```

运行不需要 API Key 的 Secret 外发阻断演示：

```bash
uv run python examples/secret_email_demo.py
```

演示中的模型和 `send_email` 都是确定性的 Fake；最终输出必须显示
`send_email executions: 0`，且 Decision 中只包含 Secret 类型、指纹和遮罩证据。

## 使用方式

内联 Agent：

```python
runtime = GuardrailRuntime.from_policy_file("examples/policies/secret-email.yaml")

async with runtime:
    session = EnforcementSession(analyzer=runtime, trace=Trace(id="task-1"))
    llm = GuardedLLMClient(inner=provider, session=session)
    tools = GuardedToolExecutor(inner=tool_executor, session=session)
    agent = SomeAgent(llm=llm, tools=tools)
    result = await agent.run("Send the report by email")
```

HTTP Gateway：

```python
client = OpenAI(
    api_key=os.environ["GATEWAY_API_KEY"],
    base_url="http://localhost:8080/v1/openai",
)
```

先启动 Gateway：

```bash
export AGENT_GUARDRAIL_POLICY_FILE="$PWD/examples/policies/secret-email.yaml"
export AGENT_GUARDRAIL_UPSTREAM_BASE_URL="https://api.openai.com/v1"
export AGENT_GUARDRAIL_UPSTREAM_API_KEY="your-provider-key"
export AGENT_GUARDRAIL_GATEWAY_API_KEYS='["your-gateway-key"]'
uv run --extra gateway python -m agent_guardrail.gateway
```

Agent 无需导入本项目。低耦合契约由
`tests/blackbox/external_openai_agent.py` 和
`tests/integration/test_external_agent_base_url.py` 验证：外部 Agent 只导入官方 `openai` 包并修改
`base_url`；被阻断的 ToolCall 不会到达 Agent。Inline Wrapper 继续作为可控制进程内依赖注入时的
可选接入方式。

MCP Gateway（当前协议 `2026-07-28`）：

```bash
export AGENT_GUARDRAIL_POLICY_FILE="$PWD/examples/policies/secret-email.yaml"
export AGENT_GUARDRAIL_MCP_UPSTREAM_URL="https://mcp.example.com/mcp"
export AGENT_GUARDRAIL_MCP_UPSTREAM_ALLOWED_HOSTS='["mcp.example.com"]'
uv run --extra gateway python -m agent_guardrail.gateway
```

使用官方 MCP Python SDK v2 时，Agent 侧只改 URL：

```python
from mcp import Client

async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    tools = await client.list_tools()
    result = await client.call_tool("send_email", {"to": "outside@example.com", "body": "..."})
```

当前只接受 `server/discover`、`ping`、`tools/list` 和 `tools/call`。它不实现旧版
`initialize`、`Mcp-Session-Id`、GET SSE stream 或 DELETE session，也不支持订阅和实时 progress；
协议合同见[Gateway 协议参考](docs/reference/gateway-protocol.md)和
[当前架构合同](docs/current-architecture-contract.md)。低耦合契约由
`tests/blackbox/external_mcp_agent.py` 和 `tests/integration/test_mcp_gateway_sdk.py` 使用官方 SDK v2
经真实 HTTP 验证。
