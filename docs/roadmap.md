# 开发路线图

> 当前实现边界见[当前架构合同](current-architecture-contract.md)。Capability 范围、稳定 ID 和状态只以
> [`capability-status.yaml`](capability-status.yaml) 为准。本文件只安排工作顺序，不重复声明完成状态。

## 已完成的工程基线

- 唯一严格 v3 YAML → MatchPlan → AnalysisReport → Decision 生产链；
- typed/multi Event binding、derive、量词、顺序/精确 Relation 和 whole-pending Matcher；
- PendingTrace batch 原子提交、EventOrigin、显式 provenance 和脱敏 Audit；
- OpenAI 非流式、MCP `2026-07-28` 无状态 Gateway 与 Inline LLM/Tool Enforcement；
- `pre_llm/pre_tool` 副作用前置，非流式 `post_llm` 完整检查后释放；
- FlowSecurityContext 的 trust/sensitivity/owner/destination/authorization 专用可信通道；
- I01–I14 生产行为测试、T01–T10 威胁基线和分项预算；
- 当前架构短合同、精简 ADR 路由和 capability 状态矩阵。

这组基线不表示所有 T01–T10 路径已端到端覆盖，也不表示 `baseline` 或 `adapter_only` capability 已达到
Invariant/NeMo 的算法覆盖面。

## 阶段 A：P0 检测能力

这是当前唯一开发主线。按稳定 ID 完成：

1. `P0-D02 enhanced_secrets`：对齐 detect-secrets 类别与误报过滤，保留脱敏 span/fingerprint。
2. `P0-D03 contextual_multilingual_pii`：本地 Presidio 类规则和多语言/NER profile；区分真实后端与 adapter。
3. `P0-D04 model_prompt_injection`：运行锁定的真实 checkpoint 和攻击/安全语料，把状态从
   `adapter_only` 提升为 `verified`。
4. `P0-D05 jailbreak`：确定性高信号 heuristic 与独立模型 profile，分别报告事实。
5. `P0-D06 yara_injection_signatures`：部署方固定并预编译规则；YAML 不能上传规则或选择文件。

每项退出条件：真实算法/后端运行，正常/攻击/边界/失败/预算/脱敏测试，Registry→MatchPlan→Decision
集成，以及 pre block 的上游副作用为 0。Detector hit 仍只是事实，不能单独宣称威胁路径完成。

## 阶段 B：P1 检测与结构能力

P0 完成后依次实现：

1. `P1-P01 fuzzy_contains`：有界编辑距离/模糊包含 Predicate，目标和阈值来自有限参数。
2. `P1-P02 embedding_similarity`：本地或明确部署 profile 的 embedding，相似度计算保持纯且有界。
3. `P1-D01 python_ast_ipython`：Python AST/IPython 结构、语法错误和危险节点事实。
4. `P1-D02 semgrep`：固定语言/规则的隔离 backend，验证 timeout、输出上限和进程残留边界。
5. `P1-D03 hidden_content`：隐藏 HTML、不可见样式、注释和有界编码内容事实。

Fuzzy/embedding 需要比较目标，因此优先复用现有 Predicate 参数，而不是为 YAML 增加新的 Detector 配置
语言。Semgrep/YARA/模型只允许部署 profile 固定后端，Policy 仍不能获得文件、进程或网络选择权。

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
- Dockerfile、非 root 单容器、healthcheck、只读 Policy mount、SBOM；
- Policy 热加载、原子版本切换和回滚；
- 跨请求 Session Store、tenant/run token、TTL/CAS 和 Monitor identity 持久化；
- 多模态 Content、受控下载、OCR/媒体 Detector；
- 经过单独设计的 chunk-guarded LLM streaming。

## 明确后置

- 交互式 Tool `require_approval`、一次性授权凭证和完整 Sandbox；
- 远程 Core/Decision Service；
- Moderation、Copyright 等 content/compliance profile；
- MCP subscriptions/listen；
- 完整 Web UI 和分布式控制平面。

这些项目不能用文档或模拟测试写成已交付。任何改变当前架构合同的项目先写短 ADR，再更新合同和测试。
