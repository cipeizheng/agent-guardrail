# ADR-0005：MCP 2026-07-28 无状态 Gateway

- 状态：Accepted
- 日期：2026-08-04
- 替代范围：ADR-0004 中关于 MCP 长 Session 的假设；ADR-0004 其余 Runtime/Enforcement 决策继续有效

## 背景

MCP `2026-07-28` 对协议和 Streamable HTTP 做了破坏性更新：现代协议不再使用 `initialize`
握手、`Mcp-Session-Id`、独立 GET SSE 流或 DELETE session；协议版本、客户端身份和能力改为每个
请求携带，服务端发现改为 `server/discover`。HTTP 请求还必须携带与 body 一致的
`MCP-Protocol-Version`、`Mcp-Method` 和条件性的 `Mcp-Name` Header。

Invariant Gateway 当前 MCP 实现主要面向旧的 session/initialize 时代，不能作为现代协议实现
直接复制。本项目必须避免一开始就绑定已经被替代的生命周期。

## 决策

### 1. 第一版只实现现代协议

- 支持协议版本 `2026-07-28`。
- 使用单一 `POST /v1/mcp` Streamable HTTP endpoint。
- 支持 `server/discover`、`ping`、`tools/list`、`tools/call`。
- 不实现 legacy `initialize`、`notifications/initialized`、GET stream、DELETE session 和
  `Mcp-Session-Id`。
- 未支持版本返回 `UnsupportedProtocolVersionError`（`-32022`），并列出当前支持版本。
- 未支持方法返回 HTTP 404 + JSON-RPC `Method not found`（`-32601`）。

Legacy/dual-era 支持只有在出现真实兼容需求后才能通过新 ADR 增加，不能让旧协议状态污染现代
请求语义。

### 2. 严格验证现代请求 Envelope

Gateway 在解析 body 后验证：

- `params._meta['io.modelcontextprotocol/protocolVersion']`。
- `params._meta['io.modelcontextprotocol/clientCapabilities']`。
- Header/body 中 protocol version、method、tool name 完全一致。
- 重复路由 Header、缺失 Header 和非法 Base64 sentinel 均返回 `HeaderMismatch`（`-32020`）。
- `tools/call` 的 name、arguments 与 JSON-RPC ID 必须结构有效。
- `Mcp-Param-*` Header 原样转发给固定上游；Gateway 不假装理解未缓存的 `x-mcp-header` Schema。

### 3. Stateless Enforcement

现代 MCP 没有协议级 Session，因此每个 `tools/call` HTTP 请求创建一个
`EnforcementSession`：

```text
parse + headers
  → pre_tool
  → block: JSON-RPC Guardrail error，上游调用次数为 0
  → fixed MCP upstream
  → parse complete response
  → post_tool
  → block: 不向客户端返回原 ToolResult
  → allow: 返回兼容响应
```

Gateway 不承诺跨 HTTP 请求的调用次数、隐式审批或历史规则。需要状态的 MCP Tool 必须使用显式
handle；未来 Guardrail 跨请求状态也必须使用经过认证的新 Store/ADR。

### 4. 响应与 Streaming

- 接受上游 `application/json` 或请求级 `text/event-stream`。
- 为保证 `post_tool`，第一版完整、有界缓冲上游响应后再释放。
- 第一版不代理长连接 `subscriptions/listen`，也不宣称实时 progress streaming。
- Guardrail block 使用 HTTP 200 中的 JSON-RPC Error `-32040`，使 MCP Client 能按协议处理；
  HTTP 认证、Origin 和传输错误仍使用对应 HTTP 状态。

### 5. 网络安全

- MCP upstream 只来自启动配置，普通请求不能指定 URL。
- 上游 host 可配置 allowlist，HTTP redirect 关闭。
- 所有带 `Origin` 的请求必须匹配 `mcp_allowed_origins`，空 allowlist 表示拒绝所有 browser Origin。
- 本地默认只监听 `127.0.0.1`；容器部署显式设置 `0.0.0.0`。
- Authorization、Tool 原始参数和 ToolResult 不进入普通日志或 block Audit。

### 6. 兼容性验证

开发依赖使用官方 MCP Python SDK v2，并通过真实 HTTP 黑盒测试验证：外部 MCP Client 只修改
server URL，不导入 `agent_guardrail`；`server/discover`/`tools/list` 可通过，违规 `tools/call`
不会到达上游。

## 结果

优点：

- 直接对齐当前最终规范，不新增已经废弃的 session manager。
- MCP Gateway 成为真正的 Tool 副作用 Enforcement Point。
- 无状态请求易于水平扩展，也与固定上游/请求级 Trace 边界一致。
- 官方 SDK 黑盒测试能及时发现协议漂移。

代价：

- 旧 MCP Client 不能连接第一版 Gateway。
- 不支持订阅、长连接通知和实时 progress。
- 每请求 Trace 无法表达跨 ToolCall 历史规则。
- 完整缓冲增加响应延迟和内存占用，但有明确大小上限。
