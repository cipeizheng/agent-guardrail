# Gateway 设计

当前状态（2026-08-04）：OpenAI 非流式 Gateway v0.1 与 MCP `2026-07-28` Streamable HTTP
Gateway 已实现。两者共享应用工厂、Runtime lifespan、认证、固定上游、大小/超时限制和 JSONL
Audit；分别执行 pre/post LLM 与 pre/post Tool Enforcement。Policy reload、LLM 实时 Streaming 和
Docker 镜像仍未实现。

## 1. 定位

Gateway 从项目第一天进入架构，但分阶段实现。它是 Enforcement Point，不是第二套规则引擎。

MVP Gateway 与 Core 同进程：

```text
Agent Client
   │ OpenAI-compatible HTTP
   ▼
Gateway Route
   ├─ Provider Adapter
   ├─ Request-scoped EnforcementSession
   ├─ Embedded GuardrailRuntime
   ├─ Audit Sink
   └─ Upstream HTTP Client
          │
          ▼
      LLM Provider
```

未来可把 Runtime 后面的 `DecisionEvaluator` 切换成远程 Decision Client，但行为和数据模型保持
一致。MVP 不启动单独 Core 服务。

## 2. 组件边界

```text
FastAPI Route
   │ validate HTTP envelope
   ▼
OpenAI Adapter ── normalize ──► Canonical Event
   │                                │
   │                                ▼
   │                       EnforcementSession
   │                                │
   │                                ▼
   │                       GuardrailRuntime
   │                                │
   │                             Decision
   │                                │
   ├── block ◄───────────────────────┘
   │
   └── allow/log ──► UpstreamClient ──► fixed LLM Provider
```

- Route 只处理 HTTP envelope、认证、限制和错误映射。
- OpenAI Adapter 只处理协议模型、Canonical 转换及结构校验。
- EnforcementSession 管理当前请求的 Trace 和审计。
- Runtime 是唯一规则判断入口。
- UpstreamClient 是可注入接口，测试使用 HTTP MockTransport。

## 3. MVP 协议范围

第一版只支持：

- OpenAI-compatible `POST /v1/openai/chat/completions`（SDK base URL 为 `/v1/openai`）。
- 非流式 `stream=false`。
- 文本消息与 function/tool calls。
- OpenAI tool 定义及 JSON Schema 参数结构校验。
- 单一显式配置的上游 Base URL。
- pre_llm 与 post_llm。
- JSON 拒绝响应。

明确拒绝：

- `stream=true`：当前返回明确的 400，不静默降级。
- 未在 allowlist 的上游地址。
- 无法解析的消息或 ToolCall。
- 超出请求体限制的输入。

## 4. 路由设计

当前端点：

| Endpoint | 用途 |
|---|---|
| `GET /health/live` | 进程存活 |
| `GET /health/ready` | Runtime 已 ready；不主动探测上游或 Audit 路径 |
| `POST /v1/evaluate` | 直接提交 Canonical Context 获取 Decision |
| `POST /v1/openai/chat/completions` | OpenAI-compatible 代理 |
| `POST /v1/mcp` | MCP `2026-07-28` Streamable HTTP 代理 |
| `GET /v1/policies/current` | 当前策略 version/hash，不返回 Secret |

`/v1/evaluate` 是未来拆分 Core 的稳定边界，但 MVP 中调用同进程 Runtime。

OpenAI SDK 使用：

```python
client = OpenAI(
    api_key=os.environ["GATEWAY_API_KEY"],
    base_url="http://localhost:8080/v1/openai",
)
```

`POST /v1/evaluate` 请求体直接使用版本化 `GuardrailContext`，响应为版本化 `Decision`。该端点
只做判断，不代理 LLM/Tool，也不执行 block 行为；调用方必须自行 Enforcement。它默认关闭，启用
后与其他受保护端点共用 `AGENT_GUARDRAIL_GATEWAY_API_KEYS`。如果没有配置 Gateway Key，当前
认证器会允许匿名访问，因此生产启用该端点时必须同时配置认证或通过外部网络边界限制访问。

当前通过 `AGENT_GUARDRAIL_EVALUATE_ENDPOINT_ENABLED=true` 显式开启，默认返回 404。

## 4.1 启动与 Agent 接入

```bash
export AGENT_GUARDRAIL_POLICY_FILE="$PWD/examples/policies/secret-email.yaml"
export AGENT_GUARDRAIL_UPSTREAM_BASE_URL="https://api.openai.com/v1"
export AGENT_GUARDRAIL_UPSTREAM_API_KEY="provider-key"
export AGENT_GUARDRAIL_GATEWAY_API_KEYS='["gateway-key"]'
uv run --extra gateway python -m agent_guardrail.gateway
```

Agent 侧只改变模型地址：

```python
client = OpenAI(
    api_key="gateway-key",
    base_url="http://127.0.0.1:8080/v1/openai",
)
```

默认认证模式是 `server_managed`：客户端 Bearer Key 只用于 Gateway 认证，上游使用
`AGENT_GUARDRAIL_UPSTREAM_API_KEY`。设置
`AGENT_GUARDRAIL_UPSTREAM_AUTH_MODE=pass_through` 时才转发客户端 Authorization。

## 5. Session 与 Trace 语义

LLM Gateway v0.1 每个 HTTP 请求创建一个新的 `EnforcementSession`：

- Trace ID 由服务端产生，通过响应 Header 和错误体返回。
- 请求携带的历史 messages 是本次 `model_request` 的不可信内容，不自动转换成可信审批事件。
- 不接受客户端通过 Header 覆盖生产 Trace、Policy 或 tenant 属性。
- 不维护跨 HTTP 请求 Session Store。
- Tool 调用次数等跨请求规则在 LLM 或现代 MCP Gateway 中都不可依赖；当前只有任务级 Inline
  Session 能提供这类历史。

未来若引入会话存储，必须用新 ADR 定义认证、并发、TTL、租户隔离和重放语义。

## 6. Canonical 映射

| OpenAI 数据 | EventKind | Phase | 说明 |
|---|---|---|---|
| Chat Completions request | `model_request` | `pre_llm` | messages、model、tools 的标准化视图 |
| Assistant response | `model_response` | `post_llm` | content、标准化 ToolCall；当前不保留 finish reason |

OpenAI Adapter 必须：

- 拒绝重复 ToolCall ID、无法解析的 arguments 和非法 role/content 组合。
- 验证响应中的工具名存在于请求声明的 tools 中。
- 使用请求中声明的 JSON Schema 校验 ToolCall arguments。
- 将 Provider 特有字段限制在有大小上限的 metadata，不允许 Rule 默认依赖。

上述结构校验是协议完整性要求。生产 Policy 中的 Tool allow/deny、参数范围、Secret/PII 等仍由
Rule 判断。

## 7. 严格请求生命周期

```text
1. 验证认证、Content-Type 和大小
2. OpenAI Adapter 严格解析 Provider Request
3. 转换 Canonical Events
4. 创建请求级 Session，完整等待 Runtime 的 pre_llm Decision
5. block → 返回拒绝；绝不创建上游请求
6. allow/log → 构建并发送上游请求
7. 完整读取非流式响应
8. 严格解析响应并转换 Canonical Event
9. 完整等待 Runtime 的 post_llm Decision
10. block → 返回拒绝；不返回原响应
11. allow/log → 返回兼容响应
12. 写入脱敏 Audit Record
```

不能为了“零额外延迟”并发执行步骤 4 和 6。

## 8. Event 提交与内容保留

- pre/post Decision 为 `allow/log` 时，Session 才把当前 Event 追加到请求级 Trace。
- Decision 为 `block` 时，丢弃当前原 Event，只追加包含 rule ID/code 的脱敏 Decision Event。
- post_llm block 后，Provider 原响应不得进入 Access Log、Audit Record 或返回体。
- Request Trace 默认只存在于内存；JSONL Audit 只保存 Decision 摘要。

## 9. 拒绝响应

Gateway 自有错误结构：

```json
{
  "error": {
    "type": "guardrail_violation",
    "code": "guardrail_blocked",
    "message": "Request blocked by guardrail policy",
    "trace_id": "trc_...",
    "phase": "pre_llm",
    "violations": [
      {
        "rule_id": "secret-exfiltration",
        "message": "Potential secret would be sent to the model"
      }
    ]
  }
}
```

不得把完整策略、完整 Secret 或内部堆栈返回客户端。

建议状态码：

- 400：输入格式不受支持。
- 401/403：Gateway 认证失败。
- 422：请求可解析但 Guardrail 配置参数非法。
- 429：未来实现 Guardrail/Gateway 速率限制后使用；当前没有 rate limiter。
- 502：上游模型失败。
- 503：策略未就绪或 Core 不可用。
- Guardrail block：MVP 使用 400 保持 OpenAI Client 可识别；后续通过 ADR 固定。

错误映射必须区分：

| 情况 | HTTP | 是否调用上游 |
|---|---:|---|
| 输入协议非法 | 400/422 | 否 |
| pre_llm block | 400 | 否 |
| Runtime 未就绪/异常 | 503 | 否 |
| 上游失败 | 502/504 | 已调用 |
| 上游响应协议非法 | 502 | 已调用，但不返回原响应 |
| post_llm block | 400 | 已调用，但不返回原响应 |

## 10. Policy 来源

MVP 只有一个服务端启动策略：

```text
启动时指定的 AGENT_GUARDRAIL_POLICY_FILE
```

不允许普通请求头直接上传 Python Rule、任意 YAML 或选择 Policy。未来可以允许受信任客户端
选择服务端已存在的命名 Policy Profile：

```text
X-Guardrail-Policy: strict-email-agent
```

客户端不能覆盖生产环境强制规则。

## 11. 上游认证

MVP 两种模式二选一并通过配置声明：

1. Pass-through：客户端 Authorization 转发给固定上游。
2. Server-managed：Gateway 从 Secret 环境变量读取上游 Key。

约束：

- Authorization 永不写日志。
- 不允许请求动态指定任意 upstream URL。
- Provider Host 使用 allowlist。
- 重定向默认关闭，防止 Key 被转发到非预期主机。
- 错误响应不得包含请求头。

## 12. ToolCall 的边界

LLM Gateway 能阻止模型产生的 ToolCall 返回 Agent，但不能保证 Agent 不通过其他路径执行工具。

真正可靠的工具 Enforcement 必须位于：

- `GuardedToolExecutor`；或
- MCP Gateway 的 `tools/call` 转发前。

因此生产文档不能把 LLM Gateway 描述为完整 Tool Sandbox。

## 13. Streaming 路线

OpenAI Gateway 当前不支持 streaming。MCP Gateway 只接受请求级 SSE，并在有界完整缓冲和
`post_tool` 检查后返回，不是实时转发。后续 LLM Streaming 只允许显式模式：

- `buffered`：完整缓冲、完成 post_llm 检查后再返回；安全但不是真流式。
- `observe-only`：逐 token 返回，只记录不承诺输出阻断。
- `chunk-guarded`：每个安全边界缓冲检查，语义复杂，需要独立 ADR。

任何模式都必须在 API 与文档中显式声明，不能让用户误以为已发送 token 能被收回。

## 14. 资源与可靠性限制

- 请求体大小限制。
- 上游连接、读取和总超时。
- Rule/Detector 超时。
- 最大 Trace Event 数。
- 最大 Violation 数。
- HTTP Client 连接池。
- 优雅关闭。
- Readiness 在 Policy 加载失败时返回失败。
- Gateway 启动时创建一个 Runtime，所有请求复用；每个请求只创建 Session。
- FastAPI lifespan 负责 Runtime、HTTP Client 和 Audit Sink 的启动与关闭。

## 15. MCP `2026-07-28` Gateway

当前实现只对齐现代无状态协议：

- `POST /v1/mcp`，支持 `server/discover`、`ping`、`tools/list`、`tools/call`。
- 不支持旧版 `initialize`、`notifications/initialized`、`Mcp-Session-Id`、GET stream 或 DELETE
  session。
- 严格校验每个请求 `_meta` 中的 protocol version/client capabilities，以及
  `MCP-Protocol-Version`、`Mcp-Method`、条件性 `Mcp-Name` Header 与 body 的一致性。
- `tools/call` 转换成 Canonical ToolCall，执行 `pre_tool`；allow 后才请求固定 MCP Server。
- 完整、有界读取 ToolResult，再执行 `post_tool`；block 时不释放原结果。
- 上游只来自启动配置，host allowlist、redirect 关闭、Origin allowlist 和响应大小限制共同约束
  代理边界。
- 普通 JSON 与请求级 SSE 均可代理，但第一版缓冲完整响应；不支持订阅、长连接通知和实时
  progress。

现代 MCP 没有协议级 Session。每个 `tools/call` 创建独立 EnforcementSession 和 Trace，因此不
承诺跨 ToolCall 的计数、隐式审批或历史规则。`tools/list` 只做协议透传，不伪装成
`pre_tool` Event。

Guardrail block 返回 HTTP 200 中的标准 JSON-RPC Error `-32040`；协议版本不支持返回
`-32022`；Header/body 不一致返回 `-32020`。MCP Client 因而不会把阻断误判为工具成功。

外部 Agent 使用官方 MCP Python SDK v2，只把 server URL 指向
`http://127.0.0.1:8080/v1/mcp`。真实 HTTP 黑盒测试证明安全调用会到达固定上游，而 Secret
调用在 `pre_tool` 被阻断时上游 `tools/call` 计数为零。完整兼容性决策见
[ADR-0005](adr/0005-mcp-2026-stateless-gateway.md)。

## 16. 与 Invariant Gateway 的差异

借鉴：

- Provider Adapter。
- pre/post Guardrail。
- block/log 分离。
- Trace 与 Annotation。
- LLM 和 MCP 都作为代理边界。

调整：

- Core 默认内嵌，本地可用。
- pre_llm 完成后才请求上游。
- 非流式优先保证输出阻断。
- Policy 配置不通过任意请求头上传。
- Gateway 从一开始限制上游地址和敏感日志。
