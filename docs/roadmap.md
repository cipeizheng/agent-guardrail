# 开发路线图

## 阶段 0：设计基线

状态：已完成（2026-08-04）。

交付：

- uv Python 3.12 项目。
- 总体架构与安全不变量。
- Rule/Detector/Decision 设计。
- 模拟 Agent 和接入顺序。
- Gateway 和 Docker 设计。
- AI 辅助开发约束。

完成标准：

- `uv sync --dev` 成功。
- 测试与 lint 成功。
- 所有待决问题显式记录。
- 后续 AI 不需要重新猜测系统边界。

## 阶段 1：Core v0.1

状态：已完成（2026-08-04）。Canonical Model、Registry、严格 YAML Loader、Engine、错误/超时
策略、内存 Trace 与单次评估 Detector Cache 已完成；规则目录扩展属于阶段 2。

预计：3～5 个工作日。

任务：

- Pydantic Canonical Models。
- Rule 和 Detector Protocol。
- Rule Registry。
- YAML Policy 严格校验。
- Guardrail Engine。
- Decision 聚合。
- Rule 超时和错误策略。
- 内存 Trace 与 Detector Cache。

验收：

- allow/log/block 全部有单测。
- 未知 Rule/字段在启动时失败。
- 一次检查内 Detector 结果可缓存。
- Core 没有网络或工具副作用。
- 覆盖率至少 85%。

## 阶段 2：规则、Detector 与模拟 Agent

状态：进行中。已完成 Runtime、Session、GuardedLLMClient、GuardedToolExecutor、testing 迁移、
Secret Detector、支持 post_llm/pre_tool 双重检查的 Secret 外发规则和 Email Agent 演示。其余
内置规则继续按小切片实现。

预计：4～6 个工作日。

任务：

- `DecisionEvaluator` Protocol 与 `GuardrailRuntime` 门面。
- `EnforcementSession`：统一 Event、Trace、脱敏 Decision Event 和 Audit。
- `GuardedLLMClient`：共享 Session 的 pre/post LLM Enforcement。
- `GuardedToolExecutor`：改为共享 Session，不再自行维护 Trace/Audit。
- 将 ScriptedLLM、FakeToolExecutor、SimulatedAgent 迁到 `agent_guardrail.testing`。
- SimulatedAgent 只依赖 LLMClient/ToolExecutor Protocol。
- Tool allow/deny。
- 参数约束和外部域名。
- 调用次数。
- Secret Detector。
- 基础 PII Detector。
- Email Agent 示例。

验收：

- 无 API Key 可完成端到端演示。
- pre_llm block 后 LLM 调用次数为零。
- pre_tool block 后工具调用次数为零。
- Secret 日志只有类型/指纹，无原值。
- 固定 Trace fixtures 可复现所有规则。
- Runtime、Inline LLM 与 Inline Tool 复用同一 DecisionEvaluator 契约。
- block 的原始 Event 不进入 Trace，只留下脱敏 Decision Event。
- 生产包不导入 testing，SimulatedAgent 不依赖具体 Guardrail Wrapper。

### 阶段 2 推荐切片

按顺序实施，每个切片独立通过 pytest、Ruff 和 Pyright：

1. **2A：目录与协议迁移（已完成）**
   - 新增 `runtime/`、`enforcement/`、`testing/`。
   - 移动 provider-neutral Chat Model 和 LLM/Tool/Audit Protocol。
   - 仅做行为保持的 import 迁移。
2. **2B：Runtime + Session（已完成）**
   - 实现 Runtime 生命周期和 PolicyInfo/Readiness。
   - 实现 Event 提交语义与 block 脱敏事件。
   - 让现有 Tool Wrapper 使用 Session。
3. **2C：GuardedLLMClient（已完成）**
   - 完成 pre_llm/post_llm。
   - 测试 block 时 Fake LLM 为零次、post block 不泄露原响应。
4. **2D：解耦模拟 Agent（已完成）**
   - Agent 构造函数只接收 Protocol。
   - 更新 demo 和端到端安全语义测试。
5. **2E：结构化 Tool 规则**
   - Tool allow/deny、参数 Schema/范围、外部域名和调用次数。

## 阶段 3：Gateway v0.1

状态：首个完整非流式切片已完成（2026-08-04）。

任务：

- FastAPI 应用工厂。
- Health/Readiness。
- `/v1/evaluate`。
- 请求级 EnforcementSession。
- OpenAI-compatible `/v1/openai/chat/completions` 非流式代理。
- OpenAI 请求/响应 Canonical Adapter。
- ToolCall ID、名称、arguments 与声明 JSON Schema 结构校验。
- pre/post LLM Enforcement。
- 请求大小、超时和上游 allowlist。
- 兼容错误响应。
- JSONL Audit。

验收：

- pre_llm block 时 Fake Upstream 请求次数为零。
- post_llm block 时客户端拿不到原始响应。
- `stream=true` 明确拒绝。
- API Key 不出现在日志。
- 使用 MockTransport 的集成测试不访问网络。
- 请求中的消息历史不被当作可信用户确认或服务端历史。
- Gateway 全进程复用一个 Runtime，每个请求创建独立 Session。

### 阶段 3 推荐切片

1. **3A：Gateway composition root**：Settings、FastAPI lifespan、Runtime、health/ready。
2. **3B：Decision API**：`/v1/evaluate` Schema、认证边界和契约测试。
3. **3C：OpenAI Adapter**：严格请求/响应模型与双向 Canonical fixture。
4. **3D：Upstream proxy**：固定上游、超时、禁止重定向、MockTransport 测试。
5. **3E：完整 Enforcement**：pre/post、错误映射、JSONL Audit、内容泄露测试。

上述 3A～3E 已完成。后续 Gateway 工作以兼容性 fixture、认证强化、结构化日志和性能限制为主，
不在 v0.1 中加入 streaming。

## 阶段 4：Docker 与发布

状态：未开始。仓库当前没有 Dockerfile、Compose、CI 或 `.env.example`。

预计：2～4 个工作日。

任务：

- 多阶段 Dockerfile。
- Compose。
- 非 root 用户。
- Policy 只读 Volume。
- 数据 Volume。
- `uv sync --frozen` 构建。
- CI：test/lint/build/image smoke。
- `.env.example`。

验收：

- 新机器上 `docker compose up --build` 可启动。
- Health/Readiness 通过。
- 容器重启后审计数据保留。
- 镜像不包含开发依赖和本地 Secret。

## 阶段 5：MCP 与真实 Agent Adapter

状态：MCP `2026-07-28` Gateway 纵向切片已完成（2026-08-04）；框架 Adapter 待后续需求。

预计：按需求拆分。

优先顺序：

1. OpenAI SDK 使用 Gateway（已完成）。
2. MCP `2026-07-28` Streamable HTTP Gateway（已完成）。
3. OpenAI Agents SDK Inline Adapter（未实现）。
4. LangGraph Node Adapter（未实现）。
5. 其他供应商协议（未实现）。

验收重点：

- 所有适配器复用同一 Canonical Model 和 Policy。
- MCP `tools/call` block 时服务器未收到调用。
- Adapter 契约测试不依赖收费 API。
- 第一版只代理 `server/discover`、`ping`、`tools/list`、`tools/call`，其他方法明确拒绝。
- 官方 MCP Python SDK v2 只修改 server URL 即可连接，不导入本项目。
- legacy `initialize`、MCP session、GET/DELETE transport 明确拒绝，不混入现代状态模型。

## 阶段 6：生产强化

- Policy 热加载和版本回滚。
- JWT、API Key 轮换和主体权限模型（静态 Bearer API Key 已实现）。
- Rate limit。
- SQLite/PostgreSQL Audit Adapter。
- OpenTelemetry。
- 性能基准与资源限制。
- 可选模型 Detector。
- Buffered Streaming。
- 可选远程 Core。

## 暂不排期

- 自定义 DSL。
- 完整 Explorer UI。
- 未审核的 LLM 策略生成。
- 任意 Python Policy 上传。
- 自动内容改写/Redact。
- 精确跨系统污点追踪。

## 推荐实施切片

每个开发任务应在 0.5～2 天内完成，并以垂直能力切分。例如：

```text
Event Model + serialization + tests
Policy Config + one concrete Rule + tests
pre_tool wrapper + blocked side-effect test
OpenAI request conversion + contract fixtures
```

避免一次任务要求“实现整个 Core”或“完成整个 Gateway”。
