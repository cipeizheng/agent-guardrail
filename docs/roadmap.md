# 开发路线图

> 当前实现边界见[当前架构合同](current-architecture-contract.md)。Capability 范围、稳定 ID 和状态只以
> [`capability-status.yaml`](capability-status.yaml) 为准。本文件只安排工作顺序，不重复声明完成状态。

## 产品阶段

| 阶段 | 目标 | 当前状态 |
| --- | --- | --- |
| P0 | 直接 Detector SDK：不写 YAML，在任意代码位置调用 Detector | 已交付 |
| P1 | Provider Adapter 标准化：Responses API，并证明不依赖 OpenAI wire format | 已交付 |
| P2 | Streaming：定义并实现已释放内容不可撤回的保证 | 已交付 |
| P3 | 跨事件安全语境：可信来源、Tool risk 与有用的 source→sink Rule | 下一阶段 |
| P4 | 长 Session 与性能：避免历史反复扫描，再考虑跨 HTTP 状态 | 规划 |
| P5 | 部署工程：热加载、发布、SBOM 和可观测性 | 规划 |

“已交付”只表示当前合同与测试覆盖的范围，不表示所有 T01–T10 路径完成，也不改变 capability 状态矩阵中
`baseline`、`adapter_only` 或 `planned` 的含义。

### P0：直接 Detector SDK

`DetectorRunner` 提供 text/canonical JSON/batch、capability 枚举和脱敏错误，并与 MatchPlan 共用唯一有界
Detector 执行器。它只返回 fact，不返回 Decision，也不控制应用副作用。

### P1：Provider Adapter 标准化

- `ModelProviderAdapter` 统一封闭 wire Schema、固定相对上游路径、canonical request/output 和流 decoder；
- OpenAI Chat Completions 与 Responses API 使用同一个 InputNormalizer、Session、Runtime 和 Enforcement；
- Responses 当前限 text/instructions/custom function/function output；隐藏历史、内置 Tool、background 和
  多模态后置；
- 可信宿主可以在 `/v1/providers/...` 注册 Adapter，启动时拒绝路由覆盖与上游路径逃逸；
- Toy Provider 的 `{prompt} → {answer}` 非流式与 `token/done` named SSE 黑盒测试只验证架构不依赖
  OpenAI wire format，不把 Toy 写成正式 Provider capability。

### P2：Streaming

- 支持 Chat 的 data-only SSE/`[DONE]` 与 Responses 的 named SSE/`response.completed`；
- 每个文本窗口按累计 Canonical 前缀 tentative 检查，Tool arguments 完整 JSON/Schema/Policy 检查后才释放；
- terminal event 对完整 output 再检查并只提交一个最终 Event；
- block/error 隐藏当前未通过窗口并发脱敏 SSE error，但此前已通过并释放的窗口无法撤回；
- 原始上游 event 不透传；Adapter 重编码封闭字段，并绑定 function delta/done/item/terminal 一致性；
- 上游 bytes、单 event、event 数量和总时间有界；未知/畸形内容失败关闭。

当前实现会重复分析累计前缀。增量 Matcher/cache 是 P4，而不是把 P2 的性能写成已经解决。

## P3：跨事件安全语境

- 先建立部署可提供的 destination、source trust 与 Tool risk 分类；
- 实现 T01–T04 的 destination/trust-aware v3 Policy，authorization 只在已有独立授权服务时接入；
- 为不可信 ToolResult → LLM/高风险 Tool 建立 trust 与显式 Relation 组合策略；
- 增加真实 Gateway/SDK source→sink 回放，验证受保护副作用；
- 保持 T10 为明确边界外，直到存在 Framework Hook、Sandbox 或网络代理。

P3 只围绕单用户数据流构建规则，不引入 principal/tenant Registry、owner-aware Policy 或跨用户状态。
T09 使用跨目的地授权复用/confused-deputy 路径，不使用跨租户泄漏定义。

## P4：长 Session 与性能

- 为 Matcher 建立安全的历史 cursor、增量索引与 relation/finding cache，避免每个窗口或新 Event 全量扫描；
- 用真实长会话与长流 benchmark 固定内存、延迟和缓存 identity；
- 完成单进程增量语义后，再设计跨请求 Session Store、run token、TTL/CAS 与 Policy identity；
- Session Store 仍服务同一用户的连续运行，不加入用户、租户或数据所有权字段。

## P5：部署工程

- Policy 热加载、原子版本切换和回滚；
- SBOM、镜像签名、发布流水线和集群编排；
- 脱敏 metrics/tracing、SLO、流终止原因和容量可观测性；
- Provider Adapter 的版本/兼容矩阵与真实上游 smoke。

## Capability 维护

Detector 与 Predicate 的稳定 ID/状态继续只由 `capability-status.yaml` 管理。当前唯一明确的验证缺口是
`P1-D04 is_similar`：接入、预算、timeout、脱敏和 Enforcement 已测试，但真实外部 embedding backend 尚未
smoke/eval，因此仍为 `adapter_only`。其他 capability 后续按威胁覆盖维护，不创建重复名称。

## 可验证 Transformation（P3 之后）

- 设计独立 `TransformationPlan`，支持可审计 redact/replace；
- Decision 绑定输入、变换 span、输出 fingerprint 和 Policy version；
- 保持普通 `allow/log/block` Action 不承担 payload 修改；
- 对调用前/输出释放前 checkpoint、重复变换、编码偏移和敏感数据泄漏建立测试。

该阶段必须先更新当前架构合同，因为它改变“Analyzer 只判断、不修改 payload”的现行边界。

## 明确后置

- 交互式 Tool `require_approval`、一次性授权凭证和完整 Sandbox；
- Moderation、Copyright 等 content/compliance profile；
- MCP subscriptions/listen；
- 多模态 Content、受控下载和 OCR/媒体 Detector；
- 常见 Framework 的可选生命周期 recipe/hook；
- 完整 Web UI 和分布式控制平面。

多用户/多租户身份、跨用户共享、按用户授权、租户隔离和租户控制面不是后置功能，而是明确不属于本产品。
未来若改变这一边界，必须先明确改写当前架构合同，并重新设计完整身份与隔离模型，不能逐字段恢复。

这些项目不能用文档或模拟测试写成已交付。任何改变当前架构合同的项目必须同步更新合同、专项设计和测试；
需要讨论的 proposal 在结论合并后删除。
