# 开发路线图

> 当前实现边界见[当前架构合同](current-architecture-contract.md)。Capability 范围、稳定 ID 和状态只以
> [`capability-status.yaml`](capability-status.yaml) 为准。本文件只安排工作顺序，不重复声明完成状态。

## 已完成的工程基线

- 唯一严格 v3 YAML → MatchPlan → AnalysisReport → Decision 生产链；
- typed/multi Event binding、derive、量词、顺序/精确 Relation 和 whole-pending Matcher；
- PendingTrace batch 原子提交、EventOrigin、显式 provenance 和脱敏 Audit；
- OpenAI 非流式、MCP `2026-07-28` 无状态 Gateway 与 Inline LLM/Tool Enforcement；
- 固定 Policy 的无状态远程 Core、失败关闭 DecisionClient 与 Core/Gateway 双容器 Compose；
- `pre_llm/pre_tool` 副作用前置，非流式 `post_llm` 完整检查后释放；
- FlowSecurityContext 的 trust/sensitivity/owner/destination/authorization 专用可信通道；
- I01–I14 生产行为测试、T01–T10 威胁基线和分项预算；
- 当前架构短合同、精简 ADR 路由和 capability 状态矩阵。

这组基线不表示所有 T01–T10 路径已端到端覆盖，也不表示 `baseline` 或 `adapter_only` capability 已达到
Invariant/NeMo 的算法覆盖面。

## 阶段 A：P0 检测能力

P0 的本地算法和安全 adapter 表面已经进入状态矩阵。`full_local_v1` 已运行 P0-D03 的英文
Presidio/spaCy、P0-D04 的锁定 checkpoint 和 P0-D06 的真实 YARA ruleset。完成目标以固定 Invariant 基线
对齐或超越为准，不再把通用多语言 NER 作为退出条件。独立 `jailbreak` 和 `dangerous_command` 已移除。

`P0-D02 secrets` 的 Invariant provider 类别与误报过滤已经没有待实现代码；后续增加 provider 时继续升级
同一 `secrets`，不创建平行的 `enhanced_secrets`。

每项退出条件：真实算法/后端运行，正常/攻击/边界/失败/预算/脱敏测试，Registry→MatchPlan→Decision
集成，以及 pre block 的上游副作用为 0。Detector hit 仍只是事实，不能单独宣称威胁路径完成。

## 阶段 B：P1 检测与结构能力

P1 的纯本地 `fuzzy_contains`、Python AST/IPython 和 hidden content 已进入默认 Registry；
`full_local_v1` 已运行隔离的 Semgrep 1.170.0 backend。剩余工作：

1. `P1-D04 is_similar`：OpenAI-compatible embedding adapter、Invariant string/list max-pair 行为、命名阈值、
   profile model 选择、预算、timeout、脱敏与 Enforcement 已实现；在目标部署上运行真实 embedding backend 的
   安全/攻击/边界准确率、延迟和失败评测后，才能从 `adapter_only` 提升为 `verified`。

`P1-P01 fuzzy_contains`、`P1-D01 python_ast_ipython` 和 `P1-D03 hidden_content` 后续只做算法维护；不再创建
第二套 Detector 名称。

`fuzzy_contains` 继续是纯 Predicate；`is_similar` 因执行 encoder I/O 使用专用 Similarity 条件和部署固定
backend。Semgrep/YARA/模型只允许部署 profile 固定后端，Policy 仍不能获得文件、进程或网络选择权。

## 阶段 C：从 Detector fact 到威胁路径

- 建立 principal/tenant/destination Registry 和可信解析边界；
- 实现 T01–T05/T09 的 owner/destination/authorization-aware v3 Policy；
- 为不可信 ToolResult → LLM/高风险 Tool 建立 trust 与显式 Relation 组合策略；
- 增加真实 Gateway/Inline source→sink 回放，验证受保护副作用和跨租户隔离；
- 保持 T10 为明确边界外，直到存在 Framework Hook、Sandbox 或网络代理。

## 阶段 D：可验证 Transformation

- 设计独立 `TransformationPlan`，支持可审计 redact/replace；
- Decision 绑定输入、变换 span、输出 fingerprint 和 Policy version；
- 保持普通 `allow/log/block` Action 不承担 payload 修改；
- 对 pre/post、重复变换、编码偏移和敏感数据泄漏建立测试。

该阶段需要新 ADR，因为它改变当前“Analyzer 只判断、不修改 payload”的合同。

## 阶段 E：接入与部署

- Framework 增量 InputNormalizer、OpenAI Agents SDK/LangGraph Adapter；
- 为当前非 root 双容器构建补 SBOM、镜像签名、发布流水线和集群编排；
- Policy 热加载、原子版本切换和回滚；
- 跨请求 Session Store、tenant/run token、TTL/CAS 和 Monitor identity 持久化；
- 多模态 Content、受控下载、OCR/媒体 Detector；
- 经过单独设计的 chunk-guarded LLM streaming。

## 明确后置

- 交互式 Tool `require_approval`、一次性授权凭证和完整 Sandbox；
- Moderation、Copyright 等 content/compliance profile；
- MCP subscriptions/listen；
- 完整 Web UI 和分布式控制平面。

这些项目不能用文档或模拟测试写成已交付。任何改变当前架构合同的项目先写短 ADR，再更新合同和测试。
