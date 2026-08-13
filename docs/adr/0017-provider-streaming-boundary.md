# ADR-0017：Provider-neutral Adapter 与不可撤回的流式释放边界

- 状态：Accepted
- 日期：2026-08-13
- 影响范围：LLM Provider Adapter、Gateway 输出释放与 Streaming 错误语义

## 背景

Gateway 当前只处理 OpenAI Chat Completions 的非流式 JSON。把 Responses API 或 Streaming 直接继续写入
现有路由，会让 Canonical Event、Enforcement 顺序和具体 Provider chunk 格式重新耦合。实时 Streaming 还
改变了现有“完整输出检查通过后才释放”的承诺：已经发送给客户端的字节无法撤回，后续上下文也可能改变
对早先文本前缀的安全判断。

## 决策

1. Gateway 建立统一 Model Provider 管线；Adapter 只负责请求/响应/流事件协议与 provider-neutral
   `ModelRequest/ModelResponse` 之间的转换。
2. 首批 Adapter 支持 OpenAI Chat Completions 与 Responses API。Responses 只接受本地可完整观察的文本、
   custom function 与 function output；隐藏服务端历史、内置远程 Tool、多模态和 background 请求失败关闭。
3. 非流式响应继续完整、有界读取，转换为 Canonical output，并在完整
   `before_model_output_release` Decision 后释放。
4. 流式请求在完整 `before_model_call` Decision 后才连接固定上游。Gateway 只接受有界、严格解析的 SSE；
   原始上游 event 永不直接透传，只有 Adapter 重新编码的封闭 event 可以进入释放缓冲区。
5. 上游 SSE 事件先进入未释放缓冲区。每个文本 delta 只有在包含该 delta 的累计 Canonical 输出前缀通过
   tentative Decision 后，才连同此前结构事件一起释放。
6. Tool/function arguments delta 不逐块释放；只有完整 arguments 是 JSON object、Tool 已声明且通过其
   JSON Schema，并且对应 Canonical ToolCallProposal 通过 Decision 后，才释放相关 SSE 事件。
7. Provider 的终止事件到达时，对完整 Canonical output 再做一次原子 Decision；allow/log 后提交最终
   output Event 并释放终止事件。
8. 流开始后的 block、分析不可用、协议错误、预算或上游失败通过 provider-compatible 的脱敏 SSE error
   终止流；不再释放当前缓冲区或后续上游内容。
9. 流式检查不声称能够撤回已经释放的内容，也不声称早先安全前缀在看到未来上下文后仍可重新阻断。每次
   释放只保证：截至该次释放可见的累计 Canonical 前缀已经通过当时 Policy。
10. tentative 流检查不提交重复前缀 Event；最终 output 仍作为一个原子 batch 提交。跨 HTTP Session、
    增量 Matcher 状态和历史扫描优化属于后续 P4。

## 安全与失败语义

- `before_model_call` block 时上游请求数为零。
- 非流式 output block 时原始响应字节为零释放。
- 流式 output block 时当前未通过窗口与之后内容为零释放；此前已经通过的窗口不可撤回。
- 任一内容-bearing SSE 都必须由 Adapter 纳入累计 Canonical output；额外字段、重复 JSON key、流中
  function arguments 与 terminal response 不一致时失败关闭，不能识别的内容类型不透传。
- Provider error 原文、响应 body、Policy、Secret、PII 和堆栈不得进入 Gateway error event 或 Audit。
- Adapter 不能创建可信数据来源、owner 或 authorization；它只能建立自己实际观察到的 Provider 边界和
  Canonical Relation。

## 后果

- Streaming 的输出保证弱于非流式完整缓冲保证，但延迟更低且边界可验证；高保证部署仍可要求
  `stream=false`。
- 累计前缀会重复分析，长输出的 cache、批处理和增量 Matcher 优化后置到 P4。
- 新 Provider 只需实现封闭 Adapter 与流状态机，不得复制 Runtime、Policy 或 EnforcementSession。
- Chat 与 Responses 的 wire event 不进入 Core；Core 继续只分析 provider-neutral Event 与 Relation。
