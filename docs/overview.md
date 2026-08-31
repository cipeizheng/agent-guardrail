# 架构概览

> 适合谁：第一次理解系统或评审跨层变化的人。
> 解决什么：从规则输入、分析到实际阻断的完整主线。
> 相关细节：YAML 字段见 Policy 作者指南，规则匹配见分析引擎参考，协议错误码见 Gateway 协议参考。

## 1. 系统定位

Agent Guardrail 是面向 AI Agent 的可解释安全规则分析与执行控制框架。它在 Agent 调用模型和外部工具时
执行部署者编写的安全规则。输入包括检测组件给出的结果、
Agent 已经发生和即将发生的操作记录、这些记录之间的明确联系，以及部署者提供的规则；输出是允许、记录或
阻断。应用可以直接读取结果，代理服务也可以在模型与 MCP 工具调用前、输出释放前落实结果。MCP 是 Agent
调用外部工具的标准协议。

框架保证规则按照固定格式加载、分析过程受资源上限约束、执行记录保持一致，以及阻断发生在受保护操作之前。
检测准确度由所选检测组件决定，具体规则的安全与效用由对应应用工作负载评估。数据流使用“来自哪里、经过
什么处理、最终发送到哪里或触发什么操作”的路径描述。

后文使用以下代码术语：`Detector` 表示检测组件，`Event` 表示一条结构化执行记录，`Relation` 表示两条记录
之间明确的产生或影响关系，`Decision` 表示允许、记录或阻断结果，`Gateway` 表示位于 Agent 与模型或工具
服务之间的代理。

生产安全规则经过一条固定执行链：

```text
严格 YAML 规则
  → 字段和类型检查
  → 不可变的内部执行计划
  → 连接部署者注册的检测与条件判断组件
  → 在当前执行历史和待检查操作中匹配规则
  → 生成命中结果或分析错误
  → 汇总为允许、记录或阻断
  → 在模型或工具边界落实结果
```

生产规则采用数据配置，所有结果经过上述执行链。分析服务负责读取记录和计算结果；模型调用、工具调用和
其他 Agent 业务操作由边界代理或应用执行。

项目同时提供直接内容检测接口，代码名称为 `DetectorRunner`。应用可以提交文本或结构化 JSON，直接调用
部署者发布的检测组件并获得脱敏结果。该接口与安全规则共享相同的输入上限、超时、结果数量和格式校验。

## 2. 运行图

```text
应用调用、模型服务请求或流式消息
          │
          ▼
接入接口完成协议转换和字段规范化
          │ 当前待检查操作
          ▼
执行边界分配记录编号和顺序，并校验来源、记录联系、安全上下文和容量
          │
          ▼
规则分析读取已确认历史与当前操作，生成命中结果或错误
          │
          ▼
允许/记录：一次性保存当前操作
阻断：保存脱敏结果并丢弃当前操作中的原始内容
```

Runtime 管理 Analyzer 生命周期；Adapter 只处理 Provider/Framework wire↔canonical 协议；Enforcement
控制何时允许副作用；Gateway 组合 HTTP、认证、固定上游以及请求级或显式任务级 Session。OpenAI
Chat/Responses、Anthropic Messages 以及可信部署注册的其他 Adapter 复用同一
InputNormalizer/Session/Runtime，不复制 Policy 执行链。Anthropic 仅映射 client tools；服务端 MCP/Tool
执行不属于已中介流量并被内置 Adapter 拒绝。

三种产品入口的职责不同：

| 入口 | 是否需要 YAML | 输入与输出 | 谁决定/控制副作用 |
| --- | --- | --- | --- |
| `DetectorRunner` | 否 | text/JSON → Detection fact | 应用代码；SDK 不返回 Decision |
| `GuardrailRun` | 是 | Event/Relation → Decision | 应用在副作用前检查 `blocked` |
| Gateway/Inline | 是 | Provider 调用 → Decision + enforcement | 受信 Gateway/Wrapper |

Gateway 的 Decision backend 可以是进程内 `GuardrailRuntime`，也可以是独立 Core 容器中的同一 Runtime。
远程模式传输封闭、版本化的 `PendingTrace → Decision`；Core 不持有 Provider Key、不调用 LLM/Tool，Gateway
不挂载 Policy 或 Detector 资产并继续负责 Trace 原子提交、Audit 和副作用顺序。

## 3. Event、Trace 与来源

长期策略 Event 是：

- `MESSAGE`：封闭的 role 和 TextContent；
- `MODEL_CALL`：一次即将发生的模型操作；
- `TOOL_CALL_PROPOSAL`：模型建议、尚未实际执行的 ToolCall；
- `TOOL_CALL`：实际准备执行的 call ID、工具名和 JSON arguments；
- `TOOL_RESULT`：规范化 call ID、工具名和 JSON output。

Event 不含 `pre/post LLM/Tool` Phase；Policy 因而可以用于 Agent 的 memory、retrieval、prompt builder、
handoff 等任意语义插入位置。`GuardrailRun` 是框架无关 SDK：应用提交这些 Event，并用同一 run 返回的
`EventRef` 显式连接关系，不需要为每个 Framework 编写专用 Adapter。

`EventOrigin` 只回答声明来自客户端、实际观察还是可信派生，不代表内容可信或已授权。外部输入默认
`client_asserted`；只有 Enforcement 可以建立 `observed/derived`。

`EventSecurityFacts` 只保存绑定到该 Event payload 的来源信任分类及 authority。可信 Session/SDK 接入
显式提供后，该事实随 Event 跨提交保留；默认 unknown，且不从 origin、顺序或关系自动推断。

精确来源只存在于类型化 `Event.relations`。Adapter/Enforcement 只能在掌握对应事实时建立
`derived_from` 或 `influenced_by`；`precedes/immediately_precedes` 只由 sequence 得出，绝不自动生成
Relation。

单进程 Gateway task session 允许 Model 与 MCP 请求共享 Trace。可信 Host 用 opaque token 选择已有 task，
并可把 provider `call_id` 作为专用 proposal 引用随 MCP 请求携带；Gateway 只有在同 task 内找到唯一已提交的
observed proposal，且工具名/参数完全一致时，才建立 proposal→实际 ToolCall 的 `influenced_by`。显式
Model history 中可唯一匹配的 MCP ToolResult 输入边同样重连到 observed ToolResult。该机制不从时间、名称
相似或普通 payload 猜测 Relation，也不自动建立 source trust 或用户授权。

## 4. Snapshot 与 pending 分析

Matcher 在不可变 snapshot 上枚举 typed/multi Event binding、collection、derive 和量词，并执行显式条件。
pending 分析看到 `committed past + whole pending batch`，但 Finding 至少有一个 subject 必须属于 pending，
避免只匹配历史 Event 就重复阻断当前操作。

所有搜索、关系、Predicate/Detector、Finding 和 evidence 都使用分项预算。超限、timeout、参数或实现错误
进入结构化 AnalysisError，由生产 Policy 显式映射，不能静默变成 allow。

## 5. Policy 与 capability

MatchPlan 是 action-free 分析 IR。Rule action 和失败动作保存在生产 Policy 外层；Analyzer 在完整匹配后按
`block > log > allow` 聚合 Decision。

直接 Detector SDK 使用同一部署 Registry，但不编译 MatchPlan。`detect_text`、`detect_json` 和
`detect_many` 先完成 capability/encoding/输入上限预校验，再按 descriptor deadline 调用 Detector，并严格
校验 detection type、数量、span、mask 和 fingerprint。timeout、backend 异常和非法返回通过脱敏
`DetectorExecutionError` 显式失败，绝不伪装成空检测结果。

YAML 只能引用部署方注册并发布 descriptor 的 Predicate/Detector。Predicate 必须纯且无 I/O；Detector
输入编码、字节、deadline、结果类型、数量和 evidence 均受 descriptor 与 MatchPlan 预算约束。Policy
不能指定 module、模型地址、文件、进程、网络 endpoint 或实现参数。

默认 Registry 只包含本地确定性算法。`prompt_injection_model`、`prompt_injection_judge`、带外部 backend
的 `pii`、`semgrep` 和 `yara_injection_signatures` 必须由部署启动代码绑定固定 backend/profile 后显式
发布；Policy 只能看到稳定 capability 名称和有限类型，不能看到或更换 profile。内置 `full_deberta` 是已真实
运行的固定部署 preset（默认仍为 `local`），组件变量可自由组合出等价的逐组件部署；`is_similar` 和
`prompt_injection_judge` 只在部署注入 `EmbeddingProfile`/LLM judge backend 后发布，Policy 提供比较文本和
阈值，但不能选择 model、endpoint 或凭据。

## 6. Enforcement 保证

- `before_model_call` allow 前不请求模型上游。
- `before_tool_call` allow 前不执行工具。
- 非流式 `before_model_output_release` allow 前不向客户端/Agent 释放原始模型响应。
- Streaming 文本窗口只在累计 Canonical 前缀通过 tentative Decision 后释放；Tool arguments 在完整
  JSON/Schema/Policy 检查前不释放；terminal 时完整输出再检查并只提交一次。
- `before_tool_output_release` allow 前不释放 ToolResult；但输出检查 block 不能撤销已经执行的工具。
- block 不提交原始 pending Event，Audit 只接收脱敏 Decision。

Streaming block/error 会隐藏当前未通过窗口并以脱敏 SSE error 终止，但不能撤回早先已经通过并发送的窗口，
也不能保证未来上下文不会改变对旧前缀的判断。需要完整输出原子保证时使用非流式模式。当前累计前缀重复
分析，增量性能属于 P4。

这些名称只属于 Model/MCP Gateway 的执行检查点，不进入 Event、PendingTrace、Decision、Inline Wrapper
或 YAML。编程式 SDK 只负责分析并返回 Decision；应用必须在真正副作用前检查 `blocked`。

OpenAI、Anthropic 和 MCP Gateway 在没有 task token 时为每个受保护 HTTP 请求创建独立 Session；有效 token 时复用
同一单用户任务级 Session/Trace。Inline LLM 与 Tool Wrapper 也必须共享任务级 Session/Trace。Gateway 的
task state 只有单进程内存、TTL 和容量界限，不是持久化/分布式历史服务。Gateway 只能中介经过它的流量，Agent 直接 Shell/函数/HTTP 需要 Framework Hook、
Sandbox 或网络代理。Guardrail 不拦截 syscall、进程、宿主文件系统或任意网络 egress；对应边界外威胁和
所需强制控制见[安全模型的 Sandbox 责任矩阵](security-model.md#8-guardrail-无法替代的-sandbox-控制)。

## 7. 接下来读什么

- 写 Policy：[Policy 作者指南](guides/policy-authoring.md)
- 理解 Matcher：[分析引擎参考](reference/analysis-engine.md)
- 增加 Detector/Predicate：[Capability 参考](reference/capabilities.md)
- 接入 Agent：[接入指南](guides/integration.md)
- 审查资产与威胁：[安全模型](security-model.md)
- 修改 HTTP/MCP：[Gateway 协议](reference/gateway-protocol.md)
