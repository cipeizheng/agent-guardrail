# Agent Guardrail

一个面向 AI Agent 的 Invariant 风格、可解释 Policy Analyzer 与 Enforcement Gateway。

项目采用一等 Event、显式关系、`past_events + pending_events` whole-pending 分析和 Gateway
Enforcement 分层。ADR-0011 已完成破坏性生产切换：唯一生产 Policy 是严格 `version: 3` YAML，经过
作者 Schema、无 mandatory anchor 的 MatchPlan、可信 capability linking 和有界 SnapshotMatcher，
生成 `AnalysisReport` 后由 `MatchPolicyAnalyzer` 失败安全地投影为 `Decision`。

当前没有 Python Rule/Rule Registry、Structured RulePlan、Safe Profile 兼容编译器或 v1/v2 Policy
回退。可信 Python 扩展只允许部署方注册 descriptor 约束的 Predicate/Detector；YAML 不能执行 Python、
import、callback 或 I/O。CEL 与 Invariant DSL 均未实现。

## 当前状态

Core v0.1.0、OpenAI-compatible Gateway 与 MCP `2026-07-28` Streamable HTTP Gateway 已经跑通。
两种 Gateway 在同一进程复用一个 Runtime，并使用相同的 EnforcementSession 机制；每个 OpenAI
Chat Completions 请求和每个 MCP `tools/call` 都创建独立 Session。OpenAI 路径执行
`pre_llm → 固定上游 → post_llm`；MCP 路径在真实 `tools/call` 前后执行
`pre_tool → 固定 MCP Server → post_tool`。MCP Client 和 Agent 只需修改 server URL，不导入
本项目；被 `pre_tool` 阻断的调用不会到达 MCP Server。

当前示例策略包括 Secret、基础 PII、Tool allowlist/denylist，以及根据显式 Trace 来源边限制
ToolResult 流向目标 Tool 的多 Event YAML Rule。Trace 当前支持按 ID/类型/阶段/Tool/直接来源
查询和传递祖先查询；来源边使用类型化 `EventRelation`，Inline 包装器会为能精确对应的模型与工具
事件记录来源。PII 第一版只识别邮箱、
常见北美格式电话、带分隔符的美国 SSN、通过 Luhn 校验的银行卡号、中国大陆 18 位居民身份证号
和大陆手机号形状，不等价于完整 PII 合规扫描。Dockerfile/Compose、Policy 热加载、跨请求
Session Store、LLM 实时 Streaming、MCP 订阅以及具体 Agent Framework Adapter 仍是后续工作。

Core 的主分析边界已经迁移为 `PendingTrace → PolicyAnalyzer.analyze_pending`：一次检查可以包含
多个同 Phase Candidate Event；allow/log 原子提交整个批次，block 丢弃全部原始 pending Event，
只保留一个脱敏 Decision Event。Event 使用 `client_asserted/observed/derived` 区分信任来源，
Decision v2 绑定完整 pending Event ID 集合。独立 `MESSAGE`、封闭 `TextContent`/`Message` Schema、
对应批次 Phase 和 Enforcement `InputNormalizer` 已实现。OpenAI Gateway 现在把每次完整请求快照
展开为 `client_asserted/pre_llm` 独立事件批次，把上游响应展开为 `observed/post_llm` 独立事件批次；
MatchPlan 直接检查独立 ToolCall。Inline 首次请求和模型响应使用独立 Event；在可证明增量 identity
完成前，重复全量请求快照仍通过显式聚合 ModelRequest 单 Event 提交。聚合 Event 不能成为 MatchPlan
binding，也不能与独立 Event 混批。

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
- 第一版不支持 LLM 实时流式响应安全拦截；MCP 请求级 SSE 会完整、有界缓冲后再做 `post_tool`。
- 第一版不提供完整 Web UI、多租户或分布式控制平面。
- 用 LLM 生成未经验证就直接启用的策略。

## 设计文档

1. [总体架构](docs/architecture.md)
2. [架构图与代码阅读地图](docs/code-reading-map.md)
3. [规则与策略模型](docs/policy-model.md)
4. [Agent 接入与模拟 Agent](docs/agent-integration.md)
5. [Runtime 与 Enforcement 详细设计](docs/runtime-and-enforcement.md)
6. [Gateway 设计](docs/gateway.md)
7. [Docker 与部署](docs/deployment.md)
8. [开发路线图](docs/roadmap.md)
9. [AI 辅助开发指南](docs/ai-development-guide.md)
10. [架构决策记录](docs/adr/)
11. [Invariant Policy/Monitor 兼容性基线](docs/invariant-policy-compatibility.md)
12. [Finding 与 AnalysisReport 公共模型](docs/analysis-report-model.md)
13. [MatchPlan IR 与分项成本账本](docs/match-plan-model.md)
14. [SnapshotMatcher 执行合同](docs/snapshot-matcher.md)
15. [MatchMonitor 增量执行合同](docs/match-monitor.md)
16. [MatchPlan 可读策略作者格式](docs/match-policy-authoring.md)
17. [MatchPlan 可信能力编译与执行](docs/capability-execution.md)
18. [MatchPlan 生产硬切换 ADR](docs/adr/0011-matchplan-production-cutover.md)

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
协议取舍见 [ADR-0005](docs/adr/0005-mcp-2026-stateless-gateway.md)。低耦合契约由
`tests/blackbox/external_mcp_agent.py` 和 `tests/integration/test_mcp_gateway_sdk.py` 使用官方 SDK v2
经真实 HTTP 验证。
