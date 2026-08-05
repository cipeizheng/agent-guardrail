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
Secret Detector、基础 PII Detector、支持 post_llm/pre_tool 双重检查的 Secret/PII 外发规则、
Tool Allowlist/Denylist、Trace 关系查询、类型化 `EventRelation` 可信来源追踪、`tool_result_flow`
规则、Event 信任来源、Candidate batch、`PendingTrace → PolicyAnalyzer` 原子分析和 Email Agent
演示。项目已根据 ADR-0007 转向 Invariant 风格事件分析；独立 Message/Input Normalizer 与表达式
Policy 尚未实现。

预计：4～6 个工作日。

任务：

- `PolicyAnalyzer` Protocol 与 `GuardrailRuntime` 门面。
- `EnforcementSession`：统一 Event、Trace、脱敏 Decision Event 和 Audit。
- `GuardedLLMClient`：共享 Session 的 pre/post LLM Enforcement。
- `GuardedToolExecutor`：改为共享 Session，不再自行维护 Trace/Audit。
- 将 ScriptedLLM、FakeToolExecutor、SimulatedAgent 迁到 `agent_guardrail.testing`。
- SimulatedAgent 只依赖 LLMClient/ToolExecutor Protocol。
- Tool allow/deny（已实现）。
- 同一 Session 的来源边、直接/传递关系查询和 ToolResult 来源流向限制（已实现）。
- 参数约束和外部域名。
- 调用次数。
- Secret Detector。
- 基础 PII Detector（已实现：邮箱、常见北美电话、美国 SSN、Luhn 银行卡号、中国大陆
  18 位居民身份证号和大陆手机号形状）。
- Email Agent 示例。

验收：

- 无 API Key 可完成端到端演示。
- pre_llm block 后 LLM 调用次数为零。
- pre_tool block 后工具调用次数为零。
- Secret/PII 日志只有类型、审计安全指纹或遮罩证据，无原值。
- 固定 Trace fixtures 可复现所有规则。
- 仅有时间顺序而没有显式来源边时，不得声称 ToolResult 流向 ToolCall。
- Runtime、Inline LLM 与 Inline Tool 复用同一 PendingTrace/PolicyAnalyzer 契约。
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
5. **2E：结构化 Tool 规则（进行中）**
   - Tool allow/deny（已完成）。
   - 基础 PII 外发阻断（已完成）。
   - Trace 来源边、关系查询和 `tool_result_flow`（已完成）。
   - 参数 Schema/范围、外部域名和调用次数（未实现）。
6. **2F：Event Graph 演进（进行中）**
   - 类型化 `EventRelation` 与 Trace 图不变量（已完成）。
   - `EventOrigin`、Candidate Relation、候选事件批量原子提交（已完成）。
   - `PendingTrace`、Decision v2 Event identity 与 `PolicyAnalyzer`（已完成）。
   - 独立 Message/Input Normalizer 与全量历史信任边界（未实现，ADR-0007 已接受）。
   - 多模态 Content 与跨请求 TraceStore（未实现，分别需要专项安全设计）。
7. **2G：Invariant 风格策略输入（下一步）**
   - 定义独立 Message/ToolCall/ToolResult Event Schema 和封闭 TextContent。
   - 为显式增量 Framework Adapter 与全量历史 Gateway 分别定义 Input Normalizer。
   - 迁移 Built-in Rule 直接查询一等 ToolCall，确认边界 ModelRequest/ModelResponse EventKind 是否仍
     有协议职责；无引用者删除，有降级职责者明确标记。
   - 建立 CEL 与安全改造 Invariant Interpreter 的真实策略兼容性测试集。
8. **2H：Sandboxed Expression Policy（2G 后）**
   - 根据技术验证新增 Parser/AST/类型检查/有界 Interpreter。
   - YAML 增加严格 expression entry；不允许 module path、动态 Python 或 I/O。
   - 量词、变量绑定、Relation 查询和 Detector 调用必须覆盖正常、类型错误和资源耗尽测试。

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

- 完整 Explorer UI。
- 未审核的 LLM 策略生成。
- 任意 Python Policy 上传。
- 自动内容改写/Redact。
- 精确跨系统污点追踪。

## 已接受但待排期

- Sandboxed Expression Policy；先完成阶段 2G 的 CEL/Invariant Interpreter 技术验证。
- 认证后的跨请求 TraceStore 与 Guardrail Run Token。
- 多模态 Content、媒体下载安全和 TransformationPlan。

## 推荐实施切片

每个开发任务应在 0.5～2 天内完成，并以垂直能力切分。例如：

```text
Event Model + serialization + tests
Policy Config + one concrete Rule + tests
pre_tool wrapper + blocked side-effect test
OpenAI request conversion + contract fixtures
```

避免一次任务要求“实现整个 Core”或“完成整个 Gateway”。
