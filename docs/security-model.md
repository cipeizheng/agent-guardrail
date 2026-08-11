# 安全模型与威胁路径

> 适合谁：定义资产、评审信任边界或把 Detector 映射到实际威胁路径的人。
> 解决什么：数据、意图、资源以及 T01–T10 source→sink 安全目标。
> 不包含什么：capability 完成状态和未来实现排期；它们分别见
> [`capability-status.yaml`](capability-status.yaml)与[roadmap](roadmap.md)。

## 1. 保护目标

Agent Guardrail 保护用户在 Agent 系统中的三类核心资产：

- **数据**：PII、Secret、私有文档、租户数据和其他受限内容的机密性；
- **意图**：system/developer 控制、用户授权目标和 Agent 决策不被不可信内容静默改写；
- **资源**：文件、账户、网络、资金和外部系统只执行经过 Policy 允许的操作。

Audit 数据的机密性与可追责性、分析服务的可用性和所有受保护边界的完整中介是支撑属性。LLM 不是
默认受信任的安全决策者，也通常不是被保护资产；它是可能受不可信输入影响、产生错误内容或提出高权限
操作的推理组件。模型提供商还是一个数据目的地，是否允许接收某类数据必须由部署策略决定。

内容审核（Moderation）保护用户身心安全、产品使用政策和合规边界，不等同于隐私或 Agent 权限安全。
它属于可选 content-safety profile，不是当前核心威胁路径的前置依赖。

## 2. 信任主体与假设

默认信任：

- 部署所有者及其只读 Policy、启动配置和 capability 注册清单；
- 本项目 Runtime、EnforcementSession、InputNormalizer 和协议 Adapter 的实现；
- 由可信 Enforcement Point 实际建立的 phase、Event origin 和类型化 Relation；
- 只接收已经脱敏结构的 AuditSink。

默认不信任其安全断言：

- 普通客户端、用户消息和请求携带的历史；
- 模型输出；
- 网页、检索文档、MCP Server 和其他 ToolResult 内容；
- Provider payload 中自称的 origin、owner、tenant、authorization 或 provenance；
- Detector 对业务所有权、用户同意和目的地授权的猜测。

认证用户可以表达业务意图，但不能因此覆盖 system/developer Policy；`observed` 模型响应只证明响应经过
Enforcement Point，不证明内容正确、安全或已获授权。

## 3. Source → Transform → Sink 模型

威胁路径不是“某个 Detector 命中”，而是受保护属性跨越一个未经允许的 Sink：

```text
Source(principal, trust, sensitivity, owner)
  → Transform(LLM, Agent, Tool, relation/influence)
  → Sink(destination, recipient, operation, authority)
  → Enforcement decision
```

主要运行路径：

```text
用户/私有数据 ── pre_llm ──> 模型提供商 ── post_llm ──> Agent/用户
外部内容/ToolResult ───────────────┘             │
                                                  ▼
                                                Agent
                                                  │
                                               pre_tool
                                                  ▼
                                      外部或高权限 Tool/资源
```

一个 PII Detection 只有与 owner、destination 和 authorization 组合后才可能成为隐私违规。同一个邮箱发给
其所有者或经过批准的处理方可以允许，发给未知外部邮件或错误租户则应拒绝。Prompt Injection Detection
同样只是信号；核心控制目标是不可信内容不能在缺少独立授权时影响高权限动作。

目标规则形态是：

```text
Detector Fact + trusted security context + source/sink path = Finding
Finding + deployment action mapping = Decision
```

## 4. EventOrigin 不等于内容信任

当前 `EventOrigin` 继续只回答“事件声明来自哪里”：

- `client_asserted`：当前请求声明，未经服务端历史证明；
- `observed`：Enforcement Point 实际收发；
- `derived`：可信 Adapter/Session 能精确建立派生关系。

它不回答：

- 内容是否可信或含 Prompt Injection；
- 数据是否为 PII/Secret、属于哪个用户或租户；
- 目的地是否被授权；
- ToolCall 是否符合用户意图。

因此不能把 `observed` 当作 `trusted`，也不能把 `client_asserted` 自动当作恶意。安全事实命名不得复用
三个 EventOrigin 值，避免实现混淆这两个维度。

## 5. 当前 FlowSecurityContext 与后续 Security Fact 合同

当前生产 `FlowSecurityContext` 已为一个 pending batch 提供最小、类型化且有明确授权来源的相对事实：

| 事实 | 当前封闭值示例 | 可授权生产方 |
| --- | --- | --- |
| `trust_class` | trusted control、user content、external untrusted、model generated、mixed | deployment/Enforcement/data source |
| `sensitivity` | public、private、PII、secret、mixed | deployment/data source/受控 Detector |
| `owner_scope` | current/other principal 或 tenant、shared | deployment/authentication/data source |
| `destination` | LLM provider、Agent runtime、client、external Tool、Audit | deployment/Enforcement |
| `authorization` | allowed、denied | deployment/独立 authorization service |

每个维度默认 `unknown`。非 unknown 值必须携带 Schema 允许的 `SecurityFactAuthority`；unknown 不能
伪装成已有 authority。Context 不携带原始 principal/tenant ID 或敏感内容，作为 immutable 字段随
`PendingTrace` 进入 Analyzer。生产 Policy 只有显式声明下面五个 optional string 参数，才能读取对应
值，而且默认必须为 `unknown`：

```text
security_trust_class
security_sensitivity
security_owner_scope
security_destination
security_authorization
```

普通 attributes/metadata 和 `/v1/evaluate` 客户端不能进入这个通道。OpenAI、MCP 和 Inline Enforcement
当前会按 pre/post 边界建立 destination；其他事实只有可信嵌入式宿主明确提供时才非 unknown。authority
是信任边界内的类型化声明，不是加密凭证。非 unknown authorization 必须同时绑定已知 destination；
Enforcement 切换 sink 时会清空旧 authorization，避免跨目的地复用授权。

后续仍需要 Event 级 owner/sensitivity、真实主体与目的地 Registry、认证映射、跨请求租户状态和
`tool_effect` descriptor。它们也不能由外部 YAML 获得 I/O 或动态代码权限。

`derived_from` 只用于可信 Adapter 掌握的精确来源；保守的控制影响使用 `may_influence`。两者都不能由
Detector 或 Policy 写回 Trace。内容级外泄判断仍需敏感数据 Detector，不能只凭先后关系证明相同数据被
复制。

## 6. Enforcement Point 的保护含义

| Point | 主要保护 | 当前保证 |
| --- | --- | --- |
| `pre_llm` | 数据不进入未经授权的模型目的地；恶意输入不进入模型 | Decision 完成前不请求上游 |
| `post_llm` | 原始模型内容/ToolCall 不释放给 Agent 或用户 | 非流式响应完整通过后才释放 |
| `pre_tool` | 外发和资源副作用 | block 时实际 Tool 调用次数为零 |
| `post_tool` | ToolResult 不进入后续 Agent/模型/用户 | 不能撤销已经执行的 Tool 副作用 |
| Audit | 原始 Secret/PII 不进入诊断面 | 只接受脱敏 Decision；可信 producer 仍负责遮罩 |

LLM Gateway 只能中介经过它的模型请求和响应；MCP Gateway 只能中介经过固定 MCP Server 的
`tools/call`。Agent 直接调用本地 Shell、函数或 HTTP 是 T10，需要 Framework Hook、Sandbox 或网络代理。

## 7. T01–T10 威胁基线

| ID | 威胁路径 | Point | 当前覆盖 |
| --- | --- | --- | --- |
| T01 | 敏感数据 → 未授权模型提供商 | `pre_llm` | 部分：Detector、严格 pre、destination context 已有；owner/auth Policy 未实现 |
| T02 | 敏感数据 → 外部 Tool | `pre_tool` | 部分：Detector、external_tool context、邮件与来源路径示例已实现 |
| T03 | 不可信 ToolResult 注入 → 后续模型请求 | `pre_llm` | 部分：Detector/关系/context 可组合；Adapter 尚未自动分类 trust |
| T04 | 不可信影响 → 未授权高权限 Tool | `pre_tool` | 部分：静态 Tool Rule/context 已有；risk/独立授权 Policy 未实现 |
| T05 | 敏感模型输出 → 错误用户 | `post_llm` | 部分：严格 post/client destination 已有；owner-aware Policy 未实现 |
| T06 | 原始敏感数据 → Finding/Error/Audit | Audit | 已支持结构、遮罩和测试；受信任 producer 仍是边界 |
| T07 | Unicode 控制/格式字符绕过 Detector | `pre_llm` | 部分：Unicode fact、type 选择和严格 pre 已有；来源 trust/意图语境 Policy 未完整交付 |
| T08 | 预算/timeout/异常 → 隐式 allow | Analyzer | 已支持显式失败映射与 fail-closed 配置 |
| T09 | 一个租户的数据 → 另一个租户 | `post_llm` | 部分 Schema：owner_scope 已有；主体 Registry/跨请求可信状态未实现 |
| T10 | Agent 绕过 Wrapper/Gateway 直接副作用 | 无 | 明确边界外，需要 Hook/Sandbox/代理 |

T01–T10 是本文中的威胁分类，不是第二套 Policy 解释器。生产覆盖由 Matcher/capability 单元测试以及
Inline、OpenAI、MCP 的实际副作用集成测试证明；“部分”或“边界外”不能因文档场景而写成已交付。

## 8. Detector 与交付状态

Detector 按 T01–T10 威胁覆盖排序，而不是按函数名数量排序。命中仍须与可信 source/sink/trust 语境
组合，不能单独宣称解决了威胁路径。

具体 capability 名称和验证状态只在[状态矩阵](capability-status.yaml)维护；实现顺序只在
[roadmap](roadmap.md)维护。与 Invariant 的对齐只表示 I01–I14 行为与安全结果对齐，不复制
IPL、Policy import、handler 权限或由 Policy 获得的 I/O 权限。

当前生产边界和明确未交付项见[当前架构合同](current-architecture-contract.md)。T10 在出现 Framework
Hook、Sandbox 或网络代理前始终属于边界外，不能用增加 Detector 数量解决。
