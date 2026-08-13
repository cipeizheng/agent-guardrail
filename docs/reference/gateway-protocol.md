# Gateway 协议参考

> 适合谁：修改 OpenAI/MCP Adapter、HTTP 路由、认证或错误映射的人。
> 解决什么：当前端点、请求生命周期、Canonical 映射和协议边界。
> 不包含什么：环境变量完整清单和 Agent 选择接入方式。

## 1. 组件边界

```text
FastAPI Route
  → Provider Adapter
  → InputNormalizer / Canonical Tool boundary
  → request-scoped EnforcementSession
  → embedded GuardrailRuntime / remote Core DecisionClient
  → fixed UpstreamClient
```

Route 处理 HTTP envelope、认证、资源限制和错误映射；Adapter 处理协议模型、结构校验和 Canonical 转换；
Session 管理 Trace/Decision/Audit；Runtime 是唯一 Policy 判断入口。Gateway 不是第二套规则引擎。

## 2. 当前端点

| Endpoint | 用途 |
| --- | --- |
| `GET /health/live` | 进程存活 |
| `GET /health/ready` | Runtime ready |
| `GET /v1/policies/current` | 当前 Policy version/hash |
| `POST /v1/openai/chat/completions` | OpenAI-compatible 非流式代理 |
| `POST /v1/mcp` | MCP `2026-07-28` Streamable HTTP 代理 |

## 3. OpenAI 范围

当前支持 `stream=false` 的文本消息、function/tool calls、tool declaration 和请求声明 JSON Schema 的
Tool arguments 校验。明确拒绝 streaming、动态上游、无法解析的 role/content/ToolCall 和超限请求。

每个 HTTP 请求创建独立 Session：

- 完整 messages 作为本次 `client_asserted` snapshot，不是服务端可信历史；
- request 历史加 `MODEL_CALL` 和 observed response 各形成一个原子 batch；
- 不接受客户端覆盖 Trace、Policy、origin、tenant、Relation 或 security fact；
- 不维护跨请求 Session Store 或 Tool 调用计数。

## 4. OpenAI Canonical 映射

| OpenAI 数据 | EventKind | Origin / Relation |
| --- | --- | --- |
| request system/user/assistant 文本 | `message` | `client_asserted` |
| request assistant tool call | `tool_call_proposal` | `client_asserted` |
| request tool role message | `tool_result` | `client_asserted`；`may_influence` 对应 proposal |
| 即将发生的上游模型调用 | `model_call` | `observed`；所有请求历史 `may_influence` 此调用 |
| response assistant 文本/refusal | `message` | `observed`；`derived_from` model call |
| response assistant tool call | `tool_call_proposal` | `observed`；`derived_from` model call |

request ToolResult 必须匹配当前 turn 的 ToolCall ID，Normalizer 建立批内 Relation，并拒绝孤立、重复、跨轮
或未完成 group。响应 ToolCall 的名称必须在请求 tools 中声明，arguments 必须通过声明 Schema。

tool declaration、usage 和 finish reason 当前不形成独立 Event；`model` 只进入轻量 `MODEL_CALL`，不会把
完整 Provider request 作为聚合 Event。未知 Provider 字段拒绝，不复制到 metadata 或 MatchPlan。

## 5. OpenAI 生命周期

```text
1. 认证、Content-Type、body size
2. 严格解析 Provider request
3. InputNormalizer 展开 request batch
4. `before_model_call` whole-batch Decision
5. allow/log 后才调用固定上游
6. 完整、有界读取非流式响应
7. 严格解析并展开 observed response batch
8. `before_model_output_release` whole-batch Decision
9. allow/log 后才返回兼容响应
```

调用前检查不能与上游请求并发。response normalization、Trace capacity 或输出 Decision 失败发生在上游调用后，
但原始响应仍不得释放。

allow/log 原子提交整个 batch；block 丢弃原始 pending Event，只追加脱敏 Decision Event。Trace 只在请求
内存中存在，Audit 只持久化 Violation 摘要。

## 6. OpenAI 错误

Gateway 错误体只包含稳定 type/code/message、trace、checkpoint 和脱敏 Violation；不返回完整策略、Secret、
payload 或堆栈。

| 情况 | HTTP | 是否调用上游 |
| --- | ---: | --- |
| 协议/结构/大小非法 | 400/413/415/422 | 否 |
| `before_model_call` block | 400 | 否 |
| Runtime 不可用 | 503 | 否 |
| 上游失败 | 502/504 | 是 |
| 上游响应/normalization 非法 | 502 | 是，不释放原响应 |
| 输出 Trace capacity/runtime 失败 | 503 | 是，不释放原响应 |
| `before_model_output_release` block | 400 | 是，不释放原响应 |

认证失败为 401；MCP Origin 拒绝为 403。

## 7. Policy 与上游

embedded 模式的 Policy 来自 Gateway 启动配置 `AGENT_GUARDRAIL_POLICY_FILE`；remote 模式的 Policy
只读挂载到 Core，Gateway 不持有 Policy 或 Detector 资产。请求不能上传 YAML/Python capability 或选择
Policy。远程协议与服务边界见[双容器设计](../design/remote-core-deployment.md)。

OpenAI 上游认证支持：

- `server_managed`：客户端 Key 认证 Gateway，服务端 Key 调用固定上游；
- `pass_through`：转发客户端 Authorization。

Authorization 永不记录；请求不能指定动态 URL；host allowlist 可限制固定地址；redirect 关闭。

## 8. Streaming 边界

OpenAI 当前拒绝 streaming。MCP 请求级 SSE 也会完整、有界缓冲，通过
`before_tool_output_release` 后才返回，不是实时
转发。实时或分块模式会改变输出阻断承诺，必须先新增 ADR；已经发送的 token 无法收回。

## 9. MCP `2026-07-28`

当前仅支持无状态：

- `server/discover`、`ping`、`tools/list`、`tools/call`；
- 不支持旧 `initialize`、`notifications/initialized`、`Mcp-Session-Id`、GET stream、DELETE session；
- 校验 `_meta` version/capabilities、`MCP-Protocol-Version`、`Mcp-Method`、条件性 `Mcp-Name` 与 body；
- 上游固定、redirect 关闭，可配置 host 和 Origin allowlist；
- 普通 JSON 和请求级 SSE 均完整缓冲；不支持 subscription、长连接 notification 或实时 progress。

只有 `tools/call` 映射 Canonical ToolCall，执行 `before_tool_call`，allow 后请求固定 Server，完整读取
ToolResult 后执行 `before_tool_output_release`。每次调用创建独立 Session；`tools/list` 不伪装 Tool Event。

Guardrail block 返回 HTTP 200 中 JSON-RPC Error `-32040`；不支持协议版本为 `-32022`；Header/body
不一致为 `-32020`。调用前 block 时固定上游请求次数必须为零；输出释放前 block 时上游已执行一次，但
原始 ToolResult 不释放。

## 10. 资源与生命周期

Gateway 限制 request/response bytes、Core 与上游 timeout、Trace Event、Violation、MatchPlan/capability
预算和 HTTP 连接池。应用启动时创建 embedded 或 remote Runtime；remote 启动会认证 Core 并固定 Policy
identity，readiness 会检查 Core 可达且 identity 未变化。每个受保护调用创建独立 Session，health、Policy
query 和 MCP 非 Tool 方法不创建 Session。

启动和 Settings 见[运行指南](../guides/operations.md)，接入示例见
[Agent 与 Enforcement 接入](../guides/integration.md)。
