# Responses 状态层专项设计

> 本文描述 Gateway 内置状态接口，以及当前采用的外部 Responses state owner 接入方式。

## Gateway 内置状态接口

`OpenAIResponsesAdapter` 接受 `previous_response_id`。可信部署通过
`create_app(responses_state_store=...)` 注入 `ResponsesStateStore` 后，Gateway 按以下顺序处理请求：

```text
认证
  → state store 恢复前序 input/output items
  → Responses adapter 转换为 canonical history
  → before_model_call Guardrail
  → 固定 Provider 上游
  → before_model_output_release Guardrail
  → 保存已通过检查的完整 response/item 状态
```

当前仓库提供 `InMemoryResponsesStateStore`：

- 在进程内保存 response 和 input history；
- 恢复有界的前序 input/output items；
- `store=false` 的响应不保存；
- 支持非流式和 Responses 命名 SSE 的终态续接；
- 未找到 response、超过状态上限或未配置 state owner 时返回错误；
- 不包含重启恢复和持久化；跨进程状态由外部 Agentic API state owner 处理。

Chat Completions 不使用该状态接口，客户端通过 `messages` 提交完整历史。Remote Core 接收完整的
`past_events + pending_events`，不保存 Responses response/item 状态。

## 外部 Responses state owner

当前外部拓扑使用仓内 `vendor/agentic-api` submodule 中的
[cipeizheng/agentic-api](https://github.com/cipeizheng/agentic-api) fork 作为 Responses state owner。
当前 fork revision 为 `e677afd`，基于 upstream `f20cd2b`：

```text
Responses client
  → vLLM Agentic API（Responses 入口、恢复 previous_response_id、SQLite response/item 状态）
  → agent-guardrail Gateway（接收展开后的 input，执行 Guardrail）
  → 固定模型 Provider
```

Agentic API 是 Responses 入口，Gateway 是它的上游策略和模型入口。Agentic API 恢复 response 后，将前序
items 与本轮 input 合并成完整请求，并清除发往 Gateway 的 `previous_response_id`。Gateway 接收完整 input，
按现有 `before_model_call`、Provider、`before_model_output_release` 顺序执行策略。

当前单实例配置使用 SQLite 保存 response/item 状态。客户端续接只提交
`previous_response_id + new input`。Gateway 不读取 Agentic API 的数据库。

当前集成配置不为 Agentic API 入口增加 API key 或 OIDC。Gateway 是否检查入站 API key 由
`AGENT_GUARDRAIL_GATEWAY_API_KEYS` 配置决定；`AGENT_GUARDRAIL_UPSTREAM_API_KEY` 是 Gateway 访问 Provider
的凭据。

### Agentic API 工具模式

Agentic API 的 Responses 执行器支持 server-side tools，例如 web search 和 MCP；这些工具由 Agentic API
进程直接执行。

当前 fork 使用 `AGENTIC_RESPONSES_TOOL_EXECUTION_MODE=client_only`：

- Responses 请求保留客户端声明的 function tools；
- Agentic API 不执行 server-side tools；
- 模型返回的 function call 由客户端执行；
- 客户端提交的 `function_call_output` 进入下一轮 Responses 请求，并经过 Agentic API、Gateway 和 Provider；
- `gateway` 模式保留在 Agentic API 配置中，用于由 Agentic API 执行工具的部署。

`client_only` 是当前单实例接入配置。默认 Compose 不启动外部 Agentic API；外部拓扑通过独立进程启动。

## 集成测试

跨进程 harness 位于 [`tests/e2e/test_agentic_api_responses.py`](../../tests/e2e/test_agentic_api_responses.py)，
使用本地 Agentic API fork、SQLite、当前 Gateway 和确定性假 Provider。测试覆盖：

- Agentic API 重启后恢复 response ID，Gateway 根据恢复历史拦截请求；
- 仅提交 `previous_response_id + function_call_output` 时，Gateway 上游收到 message、function call 和
  function call output；
- SSE `response.completed` 保存后，下一轮通过 `previous_response_id` 继续请求；
- Provider HTTP 错误和无效 JSON 的错误映射，以及错误响应不形成可续接 response。

运行方式：

```bash
(cd vendor/agentic-api && cargo build --bin agentic-server)
AGENTIC_API_E2E=1 uv run pytest tests/e2e/test_agentic_api_responses.py
```

真实 Provider 的 wire compatibility 和容器网络属于对应部署配置与测试范围。

## 候选项目结论

LiteLLM Proxy 作为 provider router 评估，不承担本项目的 Responses 状态。其 hook 位置早于 session history
恢复，不能直接把恢复后的完整历史交给当前 Gateway。

[Respawn](https://github.com/robertomanfreda/respawn) 实现了 response chain 和
`previous_response_id`，当前范围是单 Gateway 实例，适合作为 Python 备选。

当前采用 Agentic API fork，因为它已有 response/item store、恢复路径、非流式 Responses、SSE、WebSocket 和
工具续接执行路径；本项目只在其上游接入 Gateway，并通过 `client_only` 固定工具执行位置。

## 当前验收范围

- `previous_response_id + new input` 能让 Gateway 检查前序用户输入、assistant output 和本轮输入；
- 前序 `function_call` 与本轮 `function_call_output` 保持 call ID、名称和参数关系；
- SSE 的 `response.completed` 经过输出检查后进入 Agentic API 状态；
- block、Provider 错误和无效 JSON 不产生可续接 response，且错误内容不释放原始上游数据；
- 单实例 SQLite 重启后可以继续已有 response；
- `client_only` 模式下 function call 由客户端执行，Agentic API 不执行 server-side tool。

具体 Provider smoke 和容器网络测试作为后续测试项。

依据：[Agentic API README](https://github.com/vllm-project/agentic-api)、[Agentic API response-store ADR](https://github.com/vllm-project/agentic-api/blob/main/docs/adr/ADR-02_response_store.md)
和 [OpenAI Responses create contract](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)。
