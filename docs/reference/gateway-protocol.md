# Gateway 接口协议参考

> 本文说明 Gateway 对外提供的 HTTP 接口、模型和 MCP 请求如何转换为内部事件、何时执行规则检查，以及错误如何返回。
> 相关参考：[运行指南](../guides/operations.md)、[接入指南](../guides/integration.md)。

## 1. 请求处理流程

Gateway 先把外部请求转换为内部事件，再交给统一的规则分析器。每个模型请求或 MCP `tools/call` 都有自己的 `Trace`；本次准备提交但尚未写入该记录的事件保存在 `PendingTrace` 中。

```text
FastAPI Route
  → 模型服务适配器
  → InputNormalizer / 统一工具数据边界
  → 请求级 EnforcementSession
  → 进程内 GuardrailRuntime / 独立 Core DecisionClient
  → 固定的上游客户端
```

Gateway 的 HTTP 路由负责请求外壳、认证、大小限制和错误返回；适配器负责解析 OpenAI、Anthropic 或 MCP 格式，并转换成内部事件；Session 保存当前请求的事件、决定和审计摘要；Runtime 是唯一的规则分析入口。Gateway 不另行实现一套规则引擎。

本文保留代码和协议中的固定名称，并在首次出现时说明含义：`Canonical` 表示内部统一的数据格式；`Adapter` 表示外部协议与该格式之间的转换器；`SSE` 是 HTTP 流式响应格式；`Trace` 是当前检查范围内的事件记录，`PendingTrace` 是准备提交但尚未写入记录的事件批次。Gateway 的检查范围是单个请求。

## 2. HTTP 接口

| Endpoint | 用途 |
| --- | --- |
| `GET /health/live` | 进程存活 |
| `GET /health/ready` | Runtime ready |
| `GET /v1/policies/current` | 当前 Policy version/hash |
| `POST /v1/openai/chat/completions` | OpenAI Chat Completions，非流式或 SSE |
| `POST /v1/openai/responses` | OpenAI Responses，非流式或命名 SSE |
| `POST /v1/chat/completions` | 标准 OpenAI SDK base URL 的 Chat alias |
| `POST /v1/responses` | 标准 OpenAI SDK base URL 的 Responses alias |
| `POST /v1/anthropic/messages` | Anthropic Messages，非流式或命名 SSE |
| `POST /v1/messages` | 标准 Anthropic SDK base URL alias |
| `POST /v1/providers/...` | 可信部署代码注册的其他 Provider Adapter 路由 |
| `POST /v1/mcp` | MCP `2026-07-28` Streamable HTTP 代理 |

## 3. 模型服务接口范围

Chat Completions 支持文本消息、function/tool calls、工具声明，以及根据请求中声明的 JSON Schema 校验工具参数。Responses 支持 text/instructions、custom function、function output，以及对应的非流式和 SSE 输出。当前协议只接收可以完整转换为内部格式的文本和工具字段；收到服务端历史、内置远程工具、background 或多模态内容时直接返回错误。

`ModelProviderAdapter` 只在接入非内置模型协议时使用。它位于 Gateway 中，把 Gateway 的统一模型请求转换为特定上游服务的 HTTP 格式，再把响应转换回来。OpenAI 和 Anthropic 的内置路由不需要实现它；部署方确实要接入其他协议时，才在创建 Gateway 时通过 `create_app(model_routes=...)` 注册 `/v1/providers/...` 路由。该路由使用代码固定的相对 `upstream_path`，请求不能自行指定上游地址。仓内 Toy Provider 只是黑盒测试用的示例适配器，用 `{prompt} → {answer}` 和 `token/done` 命名 SSE 验证普通与流式流程；正式 Provider 集成以部署配置和对应状态为准。

Anthropic Messages 支持顶层/system message 文本、user/assistant 文本、客户端工具声明、`tool_use/tool_result`、常用采样参数以及非流式/流式输出。`tool_result` 必须紧跟对应的工具轮次，并在 user content 中位于 text 之前；`tool_use.id` 映射为内部的 `call_id`。当前协议只接收可以完整转换的文本和客户端工具字段；收到 `mcp_servers`、server tools/results、thinking/redacted thinking、图片/文档、citations、cache control、container 或 output config 时直接返回错误，以保持 MCP 执行边界。

模型请求按以下方式建立检查上下文：

- 每个 HTTP 请求创建独立的 Session 和 Trace；
- 完整 messages 作为本次客户端声明的 `client_asserted` 快照，因此普通多轮对话由客户端随请求提交的历史覆盖；
- request 历史、`MODEL_CALL` 和 observed response 各形成一个原子 batch；
- Trace、Policy、origin、Relation 和安全事实由 Gateway 控制；
- 模型请求与 MCP 请求使用不同 Trace，不根据时间、调用 ID 或参数内容建立跨协议 Relation。

## 4. 模型请求到内部事件的映射

| Provider 数据 | EventKind | Origin / Relation |
| --- | --- | --- |
| request system/user/assistant 文本 | `message` | `client_asserted` |
| request assistant tool call / Anthropic `tool_use` | `tool_call_proposal` | `client_asserted` |
| request tool role / Anthropic `tool_result` | `tool_result` | `client_asserted`；`influenced_by` 对应 proposal |
| 即将发生的上游模型调用 | `model_call` | `observed`；所有请求历史经 `influenced_by` 指向此调用 |
| response assistant 文本/refusal | `message` | `observed`；`derived_from` model call |
| response assistant tool call / `tool_use` | `tool_call_proposal` | `observed`；`derived_from` model call |

Responses `instructions` 映射 system Message；string input 映射 user Message；message/function_call/ function_call_output history 映射同一组 Canonical Message、ToolCallProposal 和 ToolResult。多个 function call 先组成一个完整 assistant tool turn，缺失、重复或不一致 output 在调用上游前失败。

request ToolResult 必须匹配当前 turn 的 ToolCall ID，Normalizer 建立批内 Relation，并拒绝孤立、重复、跨轮或未完成 group。响应 ToolCall 的名称必须在请求 tools 中声明，arguments 必须通过声明 Schema。

tool declaration、usage 和 finish reason 当前不形成独立 Event；`model` 只进入轻量 `MODEL_CALL`，不会把完整 Provider request 作为聚合 Event。未知 Provider 字段拒绝，不复制到 metadata 或 MatchPlan。

## 5. 非流式请求流程

```text
1. 检查认证、Content-Type 和请求体大小；
2. 严格解析模型服务请求；
3. 由 InputNormalizer 展开请求事件批次；
4. 在 `before_model_call` 检查整批事件；
5. 只有放行或记录后才调用固定上游；
6. 完整且有大小限制地读取非流式响应；
7. 严格解析并展开模型响应事件批次；
8. 在 `before_model_output_release` 检查整批事件；
9. 只有放行或记录后才返回兼容响应。
```

调用前检查不能与上游请求并发。响应转换、Trace 容量或输出决定的失败可能发生在上游调用后，但原始响应仍不得释放。

`allow/log` 原子提交整个批次；`block` 丢弃原始待提交事件，只追加脱敏的决定事件。请求级 Trace 随请求结束；Audit 只持久化违规摘要。

## 6. 流式请求流程与不可撤回边界

```text
完整 request Decision → 连接固定上游 SSE
→ 严格、有界解析上游事件
→ 累计内部统一格式的输出前缀
→ 检查当前输出窗口
→ 放行后释放本窗口
→ 终止事件到达时检查完整输出并原子提交
```

- Chat Completions 使用 data-only SSE 与 `[DONE]`；Responses 要求 SSE `event` 与 JSON `type` 一致，并以 `response.completed` 终止；Anthropic 要求 `message_start → content block → message_delta → message_stop` 命名事件序列，tool input 的 `partial_json` 到 block stop 才解析与放行。
- 原始上游事件不直接透传；适配器严格校验后重新编码为封闭格式，未映射的 Responses metadata 会被丢弃。
- 重复 JSON key 会在重新编码时归一化；unknown field/event、UTF-8/JSON/SSE 错误、identity 改变、超限、timeout 和非成功终止均失败关闭。
- 文本 delta 对“截至本窗口的累计输出前缀”做临时检查；放行不会提交重复的前缀事件，最终完整输出只提交一次。
- function/tool arguments 的增量内容全部暂存，必须与 done/item/结束响应一致，并在完整 JSON object、已声明 Tool、JSON Schema 与 Policy 检查通过后才释放。
- 拦截或错误只释放符合 Provider 格式的脱敏 SSE error，并关闭上游；当前未通过的窗口和之后的内容都不释放。
- 已释放窗口保持已发送状态；需要完整输出原子保证时使用 `stream=false`。
- `x-guardrail-streaming: prefix-guarded-non-retractable` 明示该模式。当前累计前缀重复分析，长流优化属于 P4。

## 7. 模型服务错误

Gateway 错误体只包含稳定 type/code/message、trace、checkpoint 和脱敏 Violation；不返回完整策略、Secret、payload 或堆栈。

| 情况 | HTTP | 是否调用上游 |
| --- | ---: | --- |
| 协议/结构/大小非法 | 400/413/415/422 | 否 |
| `before_model_call` block | 400 | 否 |
| Runtime 不可用 | 503 | 否 |
| 上游失败 | 502/504 | 是 |
| 上游响应/normalization 非法 | 502 | 是，不释放原响应 |
| 输出 Trace capacity/runtime 失败 | 503 | 是，不释放原响应 |
| `before_model_output_release` block | 400 | 是，不释放原响应 |

Streaming 在 HTTP 200/SSE 已开始后不能改写 HTTP status。后续 block、分析失败或上游协议/timeout 错误使用脱敏 SSE error 终止；此前通过的窗口保留，当前未通过窗口不释放。

认证失败为 401；MCP Origin 拒绝为 403。

## 8. 规则与上游服务

embedded 模式的 Policy 来自 Gateway 启动配置 `AGENT_GUARDRAIL_POLICY_FILE`；remote 模式的 Policy 只读挂载到 Core，Gateway 使用固定 Policy identity。请求只引用部署时发布的 Policy 与 capability；远程协议与服务边界见[双容器设计](../design/remote-core-deployment.md)。

Model Provider 上游认证支持：

- `server_managed`：客户端 Key 认证 Gateway，服务端 Key 调用固定上游；
- `pass_through`：转发客户端 Authorization。

以上两种模式用于通用/OpenAI 上游。Anthropic 固定使用独立的 server-managed `x-api-key`，并固定发送 `anthropic-version: 2023-06-01`；标准 Anthropic SDK 发给 Gateway 的 `x-api-key` 只认证 Gateway，不会转发为 Provider Key，也可改用 Gateway Bearer Key。两类 Provider Key 可同时配置且互不覆盖。

Authorization 永不记录；请求不能指定动态 URL；host allowlist 可限制固定地址；redirect 关闭。

## 9. MCP 工具接口（`2026-07-28`）

MCP wire 协议采用无状态请求模型，当前方法集合为：

- `server/discover`、`tools/list`、`tools/call`；
- 校验 `_meta` version/capabilities、`MCP-Protocol-Version`、`Mcp-Method`、条件性 `Mcp-Name` 与 body；
- 上游固定、redirect 关闭，可配置 host 和 Origin allowlist；
- 普通 JSON 和请求级 SSE 均完整缓冲；subscription、长连接 notification 和实时 progress 属于后续协议能力。

只有 `tools/call` 映射为内部 ToolCall。Gateway 为每次调用创建独立 Session，先执行 `before_tool_call`，放行后请求固定 Server，完整读取 ToolResult 后再执行 `before_tool_output_release`。ToolResult 只关联本次实际 ToolCall；`tools/list` 不生成 Tool Event。模型 Gateway 中的 ToolCallProposal 属于模型请求自己的 Trace，不参与 MCP 调用检查。

Guardrail block 返回 HTTP 200 中 JSON-RPC Error `-32040`；不支持协议版本为 `-32022`；Header/body 不一致为 `-32020`。调用前 block 时固定上游请求次数必须为零；输出释放前 block 时上游已执行一次，但原始 ToolResult 不释放。

## 10. 资源限制与生命周期

Gateway 限制 request/response bytes、Core 与上游 timeout、Trace Event、Violation、MatchPlan/capability 预算和 HTTP 连接池。应用启动时创建 embedded 或 remote Runtime；remote 启动会认证 Core 并固定 Policy identity，readiness 会检查 Core 可达且 identity 未变化。模型请求和 MCP `tools/call` 创建独立 Session；health、Policy query 和 MCP 非 Tool 方法不创建 Session。

启动和 Settings 见[运行指南](../guides/operations.md)，接入示例见[应用接入指南](../guides/integration.md)。
