# 架构概览

> 适用对象：第一次了解系统，或需要理解跨层调用关系的读者。
> 阅读目标：理解规则文件如何经过代码中的分析对象，最后变成放行、记录或拦截决定。

## 1. 系统定位

Agent Guardrail 是面向 AI Agent 的安全控制层。部署者配置检测能力并编写 YAML 规则；应用或 Gateway 提交消息、模型调用、工具调用和工具结果，系统返回放行、记录或拦截决定。

规则可以同时检查内容、来源、处理过程、目的地和授权。检测器提供内容事实，事件关系记录来源和影响，安全上下文提供目的地与授权；规则把这些信息组合成命中结果和最终决定。

本文中的代码名称对应以下职责：

| 代码名称 | 作用 |
| --- | --- |
| `PolicyDocument` / `AuthorPolicy` | 读取并校验 YAML 规则的对象 |
| `MatchPlan` | 编译后的、可执行的规则检查计划 |
| `SnapshotMatcher` | 按检查计划检查事件，生成 `Finding` 和 `AnalysisReport` |
| `MatchPolicyAnalyzer` | 将分析报告转换为 `Decision` |
| `EnforcementSession` | 检查待提交事件，返回决定，并原子提交允许的事件 |

## 2. 规则执行流程

```text
version-3 YAML
  → PolicyDocument / AuthorPolicy（校验后的规则模型）
  → MatchPlan（不可变的检查计划）
  → 能力连接（capability linking：连接已注册的检测能力）
  → SnapshotMatcher（执行规则匹配）
  → AnalysisReport（命中项和分析错误）
  → MatchPolicyAnalyzer（将报告转换为决定）
  → Decision（放行、记录或拦截）
  → EnforcementSession（提交事件、返回决定并记录结果）
```

分析部分只负责读取任务记录并计算结果；模型调用、工具调用和其他业务副作用由应用或 Gateway 在决定允许后执行。

## 3. 三种接入入口

项目提供三种主要入口。区别在于应用交给系统检查什么，以及谁负责执行实际操作：

| 入口 | 适合检查的内容 | 返回结果 | 实际操作由谁执行 |
| --- | --- | --- | --- |
| `DetectorRunner` | 一段文本或一个 JSON 值 | 脱敏 `Detection` 检测结果 | 应用代码 |
| `GuardrailRun` | 消息、模型调用和工具调用组成的一批事件 | `Decision` 和 `EventRef` | 应用在副作用前检查 `Decision` |
| Gateway | 模型服务请求和 MCP 工具调用 | HTTP 响应或 MCP 结果 | Gateway |

Gateway 可以使用进程内的 `GuardrailRuntime`，也可以调用独立 Core 的 `RemoteGuardrailRuntime`。两者都通过 `PolicyAnalyzer.analyze_pending` 分析一批待提交事件；独立 Core 接收完整且有大小限制的 `PendingTrace`，返回 `Decision`。

## 4. 事件、任务记录与关系

系统把一次消息、模型调用或工具操作记录为 `Event`；同一个任务的事件集合组成 `Trace`；事件之间的来源或影响用 `Relation` 表示。当前事件类型为：

- `MESSAGE`：带角色和文本内容的消息；
- `MODEL_CALL`：一次实际模型操作的轻量记录；
- `TOOL_CALL_PROPOSAL`：模型提出的工具调用；
- `TOOL_CALL`：即将产生工具副作用的实际调用；
- `TOOL_RESULT`：工具返回的规范化结果。

Enforcement 会把脱敏的 `GUARDRAIL_DECISION` 作为结果记录追加到 Trace；它属于系统输出，不参与 Policy 输入 Event binding，也不作为 Relation source。

Event 使用 `EventOrigin` 标记记录来自客户端声明、执行层观察还是可信派生；使用 `EventSecurityFacts` 保存绑定到具体内容的来源可信度。`derived_from` 描述派生关系，`influenced_by` 描述可能影响；`precedes` 只描述先后顺序。

框架无关的 `GuardrailRun` 由应用提交 Event，并用返回的 `EventRef` 建立关系。Gateway 为每个模型请求和每个 MCP `tools/call` 分别建立请求级 Trace，不跨两类协议推断 Relation。

## 5. 完整记录与待提交记录的分析

匹配器每次在一份不可变的事件快照上检查规则。`snapshot` 表示已经存在的完整任务记录；`pending` 表示已经存在的记录加上本次准备提交的整批事件：

| 分析范围 | 可见 Event | Finding 条件 |
| --- | --- | --- |
| `snapshot` | 完整任务记录 | 所有引用属于该记录 |
| `pending` | 已提交记录 + 本次整批待提交事件 | 每条命中结果至少涉及一条待提交事件 |

所有搜索、关系、capability、Finding 和 evidence 都使用分项预算。超时、超限、参数错误和实现错误进入结构化 `AnalysisError`，由 Policy 的失败动作映射为 Decision。

## 6. 规则与检测能力

`MatchPlan` 只描述如何检查，不保存“命中后做什么”；规则动作和错误动作保存在生产 Policy 外层。部署代码把条件判断和检测器注册到 Registry，YAML 只能引用已发布的名称和有界参数。

Predicate 是纯的、类型化的条件判断。Detector 返回有限类型、位置、置信度、脱敏证据和上下文指纹。`DetectorRunner` 与 `MatchPlan` 共享同一套输入、截止时间、结果数量和脱敏限制，因此直接检测和规则中的检测使用相同的执行边界。

默认 Registry 提供本地确定性能力；可选配置由部署代码固定模型、规则、进程、地址和凭据后发布。当前名称、入口和状态见[检测能力状态矩阵](capability-status.yaml)。

## 7. 执行检查点

```text
before_model_call → Model → before_model_output_release
before_tool_call  → Tool  → before_tool_output_release
```

- 模型或工具的实际调用分别在 `before_model_call` 或 `before_tool_call` 决定允许之后发生。
- 非流式模型输出在 `before_model_output_release` 通过后释放。
- Streaming 文本以累计 Canonical 前缀逐窗口检查；完整 Tool arguments 通过 JSON、Schema 和 Policy 检查后释放。
- `before_tool_output_release` 控制工具结果是否交给后续 Agent、模型或客户端；它不能撤销已经执行的工具副作用。
- 拦截不会提交原始待提交事件，审计记录只接收脱敏的决定摘要。

Streaming 已释放窗口保持已发送状态；需要完整输出原子判断时使用非流式模式。当前累计前缀逐次重新分析，性能优化列在[roadmap](roadmap.md)。

## 8. 相关文档

- 编写规则：[规则编写指南](guides/policy-authoring.md)
- 理解规则分析：[分析引擎参考](reference/analysis-engine.md)
- 使用或增加检测能力：[检测能力参考](reference/capabilities.md)
- 接入 Agent：[接入指南](guides/integration.md)
- 审查资产与威胁：[安全模型](security-model.md)
- 修改 HTTP/MCP：[Gateway 协议参考](reference/gateway-protocol.md)
