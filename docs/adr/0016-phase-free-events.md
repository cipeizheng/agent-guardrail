# ADR-0016：Phase-free Event 与 Enforcement Checkpoint 分离

- 状态：Accepted
- 日期：2026-08-13
- 替代范围：当前 v3 Policy、Canonical Event 与 Gateway/Inline 接入合同中的 Phase 耦合

## 背景

当前 `pre_llm/post_llm/pre_tool/post_tool` 同时出现在 Event、Detector context、YAML binding、Decision、
Audit 和 Gateway 中。它把 provider/framework-neutral 的轨迹分析绑定到四个代理 hook，也迫使 retrieval、
memory、prompt builder 等任意 SDK 调用伪装成 LLM 或 Tool 阶段。聚合 `MODEL_REQUEST/MODEL_RESPONSE` 和
payload 相等 provenance 桥又使增量身份与 Tool proposal/execution 语义不明确。

仓库仍为未正式发布的 `0.1.0`，本次直接替换现有合同，不保留双 Schema、fallback 或长期兼容解释器。

## 决策

1. Canonical Event 不再包含 Phase；pending batch 不再要求同 Phase。
2. 一等事件为 `MESSAGE`、`MODEL_CALL`、`TOOL_CALL_PROPOSAL`、`TOOL_CALL`、`TOOL_RESULT`；
   `GUARDRAIL_DECISION` 仍只能由 Enforcement 创建。
3. `MODEL_CALL` 是轻量、provider-neutral 的实际模型操作事件，通过 Relation 引用输入；它不是完整请求快照。
4. `TOOL_CALL_PROPOSAL` 表示模型建议，`TOOL_CALL` 表示即将产生真实副作用的调用。
5. `derived_from` 表示精确数据来源；新增 `may_influence` 表示可信 Adapter/SDK 建立的保守影响边。
   单纯 sequence 只支持 `precedes/immediately_precedes`，不得自动生成来源或影响边。
6. YAML Event binding 删除 `phases`；Policy 描述 typed Event、past/pending、Relation、fact 和安全上下文，
   不描述 Agent flow 或 hook 调度。
7. `before_model_call`、`before_model_output_release`、`before_tool_call`、`before_tool_output_release` 是
   OpenAI/MCP Gateway checkpoint，只负责副作用与释放顺序，不进入 Event、Matcher、Decision、Inline Wrapper
   或 Detector。
8. 删除 `GuardrailContext`、直接 `/v1/evaluate`、聚合 `MODEL_REQUEST/MODEL_RESPONSE`、完整快照兼容桥和
   payload 相等 provenance 推断。
9. Programmatic SDK 以一个 run 持有一个 `EnforcementSession/Trace`，返回 trace-scoped `EventRef`；
   Framework adapter 只是事件转换便利层，不是 Core 的前提。

## 安全与失败语义

- `MODEL_CALL` 或实际 `TOOL_CALL` 的 pending Decision allow 前，不得产生对应外部副作用。
- assistant `MESSAGE`、`TOOL_CALL_PROPOSAL` 或 `TOOL_RESULT` allow 前，不得释放原始输出。
- block 不提交原始 pending Event，只提交脱敏 Decision Event；系统错误继续失败关闭。
- 只有受信任 SDK/Adapter/Enforcement 能建立非客户端 Relation 和安全上下文；Policy 与 Detector 不能写回
  Trace。
- Gateway checkpoint 可以出现在协议错误或运维日志中，但不是安全策略输入，避免同一规则随接入方式漂移。

## 后果

- 当前 v3 YAML 被直接覆写；旧 `phases` 字段因 strict Schema 被拒绝。
- Event/Decision/远程 Core wire model 发生破坏性变化，所有仓内调用方、示例、测试和文档同步迁移。
- OpenAI/MCP Gateway 继续提供四个既有副作用保证，但 Core 和 Programmatic SDK 可以在任意事件位置使用。
- 真正实时 streaming 仍需单独 ADR，因为已经释放的 chunk 不可撤回。
