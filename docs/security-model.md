# 安全模型与威胁路径

> 本文说明系统保护什么、哪些请求被信任、检测结果如何参与安全判断，以及 Guardrail 与沙箱分别负责什么。
> T01–T10 是本文使用的威胁分类；检测能力的交付状态见 [`capability-status.yaml`](capability-status.yaml)，后续实现见[开发路线图](roadmap.md)。

## 1. 规则要保护的对象

安全规则可以描述 Agent 系统中的三类资产：

- **数据**：PII、Secret、私有文档和其他受限内容的机密性；
- **意图**：system/developer 控制、用户授权目标和 Agent 决策的完整性；
- **资源**：文件、账户、网络、资金和外部系统的操作完整性。

部署方组合检测结果、可信来源信息、数据去向和授权信息，为具体应用编写规则。规则中的路径描述信息或指令来自哪里、经过模型或工具怎样处理，以及最终发送到哪里或触发什么操作。审计数据的机密性与可追责性、分析服务的可用性和执行边界的完整中介是框架支撑属性。大语言模型在该模型中是可能受外部输入影响、生成内容或提出高权限操作的推理组件；模型提供商也是规则管理的数据目的地。

内容审核的建模对象是用户身心安全、产品使用政策和合规边界。当前 T01–T10 路径聚焦隐私、控制完整性和资源完整性；应用可以另外配置内容审核规则集。

## 2. 信任边界与基本假设

默认信任：

- 部署管理员及其只读安全规则、启动配置和已注册组件清单；
- 本项目的规则分析、执行边界、输入规范化、请求级 Trace 和协议转换实现；
- 双服务部署中的独立分析服务、只读规则与模型资产，以及代理访问分析服务的专用凭据；
- 由可信执行边界实际建立的检查位置、记录来源和记录之间的明确联系；
- 只接收脱敏结构的审计存储。

默认不信任其安全断言：

- 普通客户端、用户消息和请求携带的历史；
- 模型输出；
- 网页、检索文档、MCP Server 和其他 ToolResult 内容；
- Provider payload 中自称的 origin、authorization 或 provenance；
- Detector 对用户同意和目的地授权的猜测。

用户输入可以表达业务意图，但不能因此覆盖 system/developer Policy；`observed` 模型响应只证明响应经过 Enforcement Point，不证明内容正确、安全或已获授权。

本产品只有一个用户，不建立 principal、tenant、数据所有者或跨用户共享模型。Gateway/Core Bearer key 是部署服务凭据，只保护调用边界，不代表终端用户身份。

Gateway 为每个模型请求和每个 MCP `tools/call` 分别创建 Trace。模型请求携带的历史仍是客户端声明的数据；MCP Gateway 观察到的实际调用和结果只属于该次工具请求。跨调用的可信来源与因果关系由应用通过 `GuardrailRun` 显式建立。

远程 Core 的内部网络不是低敏通道：`PendingTrace` 可能包含完整 prompt、PII 或 Tool arguments。部署必须限制 Core 端口只对 Gateway 可达，并保护链路与节点；Core/Gateway 均不得记录协议 body。Core 不持有 Provider/MCP 凭据，Gateway 不持有 Policy/模型，以缩小单容器泄露后的权限集合。

## 3. 数据来源、处理过程和目的地

威胁路径不是“某个检测器命中”这么简单，而是受保护的数据、意图或资源是否跨越了未经允许的目的地。代码中用 Source、Transform 和 Sink 表示来源、处理过程和目的地：

```text
Source(trust, sensitivity)
  → Transform(LLM, Agent, Tool, relation/influence)
  → Sink(destination, operation, authorization)
  → Enforcement decision
```

主要运行路径：

```text
用户/私有数据 ── before_model_call ──> 模型提供商 ── before_model_output_release ──> Agent/用户
外部内容/ToolResult ───────────────┘             │
                                                  ▼
                                                Agent
                                                  │
                                           before_tool_call
                                                  ▼
                                      外部或高权限 Tool/资源
```

一个 PII 检测结果只有与目的地（destination）和授权（authorization）组合后才可能成为隐私违规。例如，同一用户可以允许某类私有数据进入选定模型服务，却拒绝它进入外部 Tool 或 Audit；这不需要推断数据归属或收件人身份。Prompt Injection 检测同样只是信号；核心控制目标是不可信内容不能在缺少独立授权时影响高权限动作。

目标规则形态是：

```text
Detector Fact + trusted security context + source/sink path = Finding
Finding + deployment action mapping = Decision
```

也就是说：检测器只提供“发现了什么”，安全上下文说明“数据来自哪里、要去哪里以及是否获准”，规则命中后，部署配置再把命中结果转换为放行、记录或拦截。

## 4. 事件来源不等于内容可信度

`EventOrigin` 只回答“事件记录来自哪里”，不回答事件内容是否安全：

- `client_asserted`：当前请求声明，未经服务端历史证明；
- `observed`：Enforcement Point 实际收发；
- `derived`：可信 Adapter/Session 能精确建立派生关系。

它不回答：

- 内容是否可信或含 Prompt Injection；
- 数据是否为 PII/Secret；
- 目的地是否被授权；
- ToolCall 是否符合用户意图。

因此不能把 `observed` 当作 `trusted`，也不能把 `client_asserted` 自动当作恶意。安全事实命名不得复用三个 EventOrigin 值，避免实现混淆这两个维度。

## 5. 请求安全上下文与事件来源事实

生产代码中的 `FlowSecurityContext` 为一批待检查事件提供有限、类型化且带授权来源的安全事实：

| 事实 | 当前封闭值示例 | 可授权生产方 |
| --- | --- | --- |
| `trust_class` | trusted control、user content、external untrusted、model generated、mixed | deployment/Enforcement/data source |
| `sensitivity` | public、private、PII、secret、mixed | deployment/data source/受控 Detector |
| `destination` | LLM provider、Agent runtime、client、external Tool、Audit | deployment/Enforcement |
| `authorization` | allowed、denied | deployment/独立 authorization service |

每个维度默认 `unknown`。非 unknown 值必须携带 Schema 允许的 `SecurityFactAuthority`；unknown 不能伪装成已有 authority。Context 不携带身份、租户或敏感内容，作为 immutable 字段随 `PendingTrace` 进入 Analyzer。生产 Policy 只有显式声明下面四个 optional string 参数，才能读取对应值，而且默认必须为 `unknown`：

```text
security_trust_class
security_sensitivity
security_destination
security_authorization
```

普通 attributes/metadata 和 SDK Event payload 不能进入这个通道。Gateway 按执行 checkpoint 建立 destination；可信应用通过 Session 或 SDK 的专用安全上下文参数提供其他事实。authority 是信任边界内的类型化声明，不是加密凭证。非 unknown authorization 必须同时绑定已知 destination；目标变化时使用与新目标对应的 authorization。

当前 `EventSecurityFacts` 另外持久保存绑定到一个 Event payload 的 `trust_class` 和 `trust_authority`。可信 Session/SDK 接入必须把该事实显式绑定到具体 Candidate；allow/log 后它随 Event 进入 Trace，后续 pending 分析可读取 `[source, security_facts, trust_class]`，再与 `source → target` 的显式 `influenced_by/derived_from` 组合。默认值为 unknown；非 unknown authority 仍只允许 deployment、Enforcement 或 data source。

Event trust 不从 `EventOrigin`、sequence、Tool 名或 Relation 自动推断，也不从一次 `FlowSecurityContext` 自动复制。二者语义不同：Event fact 描述该 Event payload 自身的来源可信度；Flow context 描述当前 pending batch 的 source→sink 判断语境。普通 HTTP/Provider payload 和 metadata 不能设置 Event fact；可信嵌入式宿主可以通过 `CandidateEvent.security_facts`、`EnforcementSession.submit` 或 `GuardrailRun` typed helper 的专用参数提供。

后续能力方向包括 Event 级 sensitivity、可信目的地 Registry 和 `tool_effect` descriptor；这些能力继续沿用外部 YAML 的声明式和无 I/O 边界。principal、tenant、owner identity、跨用户状态和按用户授权属于独立产品范围。

`derived_from` 只用于可信 Adapter 掌握的精确来源；保守的控制影响使用 `influenced_by`。两者都不能由 Detector 或 Policy 写回 Trace。内容级外泄判断仍需敏感数据 Detector，不能只凭先后关系证明相同数据被复制。

## 6. 检查点的保护含义

| 检查点 | 主要保护 | 当前保证 |
| --- | --- | --- |
| `before_model_call` | 数据不进入未经授权的模型目的地；恶意输入不进入模型 | Decision 完成前不请求上游 |
| `before_model_output_release` | 原始模型内容/ToolCallProposal 不释放给 Agent 或用户 | 非流式完整通过；流式只释放已检查累计前缀，已释放窗口不可撤回 |
| `before_tool_call` | 外发和资源副作用 | block 时实际 Tool 调用次数为零 |
| `before_tool_output_release` | ToolResult 不进入后续 Agent/模型/用户 | 不能撤销已经执行的 Tool 副作用 |
| Audit | 原始 Secret/PII 不进入诊断面 | 只接受脱敏 Decision；可信 producer 仍负责遮罩 |

这些 checkpoint 是 Model Provider/MCP Gateway 的执行概念，不是 Event 字段，也不能写入 YAML 选择条件。

LLM Gateway 只能中介经过它的模型请求和响应；MCP Gateway 只能中介经过固定 MCP Server 的 `tools/call`。两类请求各自使用请求级 Trace，不把模型提出的调用自动关联到 MCP 实际调用。Agent 直接调用本地 Shell、函数或 HTTP 是 T10，需要 Framework Hook、Sandbox 或网络代理。

## 7. T01–T10 威胁分类

| ID | 威胁路径 | 检查点 | 当前覆盖 |
| --- | --- | --- | --- |
| T01 | 敏感数据 → 未授权模型提供商 | `before_model_call` | 部分：Detector、调用前检查、destination context 已有；完整 authorization Policy 属后续设计 |
| T02 | 敏感数据 → 外部 Tool | `before_tool_call` | 部分：Detector、external_tool context、邮件与来源路径示例已实现 |
| T03 | 不可信 ToolResult 注入 → 后续模型请求 | `before_model_call` | 部分：请求中的显式 ToolResult 历史会参与检测和调用前决策；可信的跨调用来源关系由应用通过 `GuardrailRun` 提供 |
| T04 | 不可信影响 → 未授权高权限 Tool | `before_tool_call` | 部分：MCP 调用的工具名、参数和目的地会在副作用前决策；模型建议到实际调用的关系由应用通过 `GuardrailRun` 显式提供，Tool risk 和独立授权属于后续能力 |
| T05 | 敏感模型输出 → 未授权客户端展示面 | `before_model_output_release` | 部分：输出释放前检查/client destination 已有；展示面授权 Policy 属后续设计 |
| T06 | 原始敏感数据 → Finding/Error/Audit | Audit | 已支持结构、遮罩和测试；受信任 producer 仍是边界 |
| T07 | Unicode 控制/格式字符绕过 Detector | `before_model_call` | 部分：Unicode fact、type 选择和调用前检查已有；来源 trust/意图语境 Policy 属后续设计 |
| T08 | 预算/timeout/异常 → 隐式 allow | Analyzer | 已支持显式失败映射与 fail-closed 配置 |
| T09 | 一个目的地的授权被复用于另一目的地 | 任一 sink checkpoint | 部分：destination 变化会清空 authorization；目的地 Registry/一次性授权凭证属后续设计 |
| T10 | Agent 绕过应用检查或 Gateway 直接产生副作用 | 无 | 由 Hook、Sandbox 或网络代理控制 |

T01–T10 是本文中的威胁分类。生产覆盖由 Matcher/capability 单元测试以及 `GuardrailRun`、OpenAI 和 MCP 的实际副作用集成测试证明；表中的“部分”和“边界外”表示当前覆盖级别。

## 8. Guardrail 与沙箱的责任边界

`EnforcementSession` 保证待提交事件经过分析并按决定原子记录。副作用控制由 Gateway 的固定调用顺序，或可信应用在执行操作前检查 `Decision` 来完成。其他主机和网络路径由 Hook、Sandbox 或网络代理中介；命令、代码和 URL Detector 用于判断已经进入 Guardrail 的内容。

以下威胁不由本项目当前 Runtime/Gateway 解决，部署 Agent 具备 Shell、代码执行或本地函数能力时必须由 Sandbox、网络与主机安全层处理：

| 部署侧威胁 | Guardrail 的可见范围 | 所需强制控制 |
| --- | --- | --- |
| 直接网络外发 | `curl`、Python/Node socket、DNS 或自带二进制可绕过应用检查和 Gateway | Sandbox default-deny egress；只允许 Guardrail Gateway/受控 Broker；同时限制 DNS、IPv4/IPv6、loopback 和云 metadata |
| 直接文件、进程和本地 IPC 副作用 | 原生 syscall、子进程、Unix socket 和未包装函数不会形成可信 Tool Event | 只读或临时文件系统、最小挂载、PID/IPC namespace、syscall/capability 限制；真实副作用移到外部 Broker |
| 宿主或控制面访问 | Docker socket、host network/PID、设备、Kubernetes API 等可绕开应用层 Policy | 不使用 privileged/host namespace，不挂载控制面 socket，最小 service account 与设备访问 |
| 凭据窃取与直接使用 | Agent 能读取环境变量、文件或 metadata 中的 Key 时，可直接访问上游 | Sandbox 内不放 Provider/Tool 凭据；凭据只由外部 Gateway/Broker 持有并绑定允许的目的地与操作 |
| 持久化和跨任务污染 | 后台进程、共享可写目录或复用工作区可在本次 Decision 之后继续生效 | 每任务短生命周期 Sandbox、临时文件系统、禁止后台守护进程、显式且最小的持久卷 |
| 资源耗尽 | Policy 无法撤销已经开始的 fork bomb、内存/磁盘填满或长时间计算 | CPU、内存、PID、磁盘、文件描述符和 wall-clock 配额，超限强制终止整个 Sandbox |
| Sandbox 逃逸或内核/运行时漏洞 | 内容 Detector 不是 syscall、内核或虚拟化安全边界 | 独立 VM/强化容器运行时、seccomp/LSM、无 capabilities、及时修补；高风险场景使用更强隔离 |

推荐把不可信 Agent 放在 Sandbox 内，把 Guardrail Gateway、Policy/Core、真实 Tool Broker 和凭据放在 Sandbox 外。Sandbox 只允许访问 Gateway/Broker。仅将代码/Shell Executor 沙箱化时，Agent 与 Guardrail 可在外部，该 Executor 使用独立任务环境，并由外部服务持有生产凭据和网络访问权限。

Sandbox 与 Guardrail 关注不同层次：Sandbox 强制执行主机、网络和资源隔离，Guardrail 判断目的地或操作授权、ToolResult 中的 Prompt Injection、PII 的模型去向以及 Audit 脱敏。因此 T01–T09 的数据流、意图、部署授权和内容判断由 Guardrail 与参数化 Tool Broker 共同处理。

Agent Sandbox 与集群网络策略由部署环境提供，本仓库的 `docker compose` 只加固 Core/Gateway 服务：只读文件系统、non-root 和私网不构成 Agent 隔离证明。部署清单见[运行指南](guides/operations.md#3-agent-隔离与部署边界)。

## 9. 检测能力与交付状态

Detector 按 T01–T10 威胁覆盖排序，而不是按函数名数量排序。命中仍须与可信 source/sink/trust 语境组合，不能单独宣称解决了威胁路径。

具体 capability 名称和验证状态只在[状态矩阵](capability-status.yaml)维护；实现顺序只在[roadmap](roadmap.md)维护。与 Invariant 的对齐只表示 I01–I14 行为与安全结果对齐，不复制 IPL、Policy import、handler 权限或由 Policy 获得的 I/O 权限。

当前生产边界和后续方向见[当前架构合同](current-architecture-contract.md)。T10 由 Framework Hook、Sandbox 或网络代理提供控制，Detector 数量不改变这条部署边界。
