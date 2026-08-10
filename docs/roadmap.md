# 开发路线图

## 已完成

### 阶段 0：设计与工程基线

- uv/Python 3.12、Ruff、Pyright、pytest coverage 和 build；
- Canonical Event/Trace/Decision 模型；
- Runtime/Enforcement/Gateway 分层和安全不变量；
- ADR、AI 辅助开发和提交前审计流程。

### 阶段 1：Runtime 与 Enforcement

- `PendingTrace → PolicyAnalyzer → Decision` 主边界；
- Candidate batch 同 Trace/Phase、有界、原子提交；
- block 丢弃原始 pending Event，只记录脱敏 Decision Event；
- Guarded LLM/Tool、AuditSink、确定性测试 Agent；
- pre_llm/pre_tool 副作用前置与 post 边界隐藏原始输出。

### 阶段 2：独立 Event 与 Gateway

- Message/ToolCall/ToolResult 一等 Event、EventOrigin 和类型化 Relation；
- OpenAI 全量快照 InputNormalizer 与 observed response 批次；
- OpenAI-compatible 非流式 Gateway；
- MCP `2026-07-28` 无状态 Gateway；
- Inline/Gateway/MCP 的可信 request→response、proposed call→execution、call→result 关系记录。

### 阶段 3：Invariant 对齐 MatchPlan

- I01–I14 可执行 compatibility fixture；
- Finding/AnalysisReport 和稳定 identity；
- anchor-free MatchPlan、全局/单 Rule 成本账本；
- typed/multi binding、collection、derive、量词、顺序和精确关系；
- whole-pending SnapshotMatcher 与 bounded MatchMonitor；
- 可读严格 YAML、typed Python AuthorPolicy、声明式 predicate 内联；
- trusted Predicate/Detector descriptor、编译、timeout/cache/evidence。

### 阶段 4：生产硬切换（ADR-0011）

- 唯一 `version: 3` Policy YAML 直接编译到 MatchPlan；
- `AnalysisReport → MatchPolicyAnalyzer → Decision`；
- action/error/max_violations 失败安全映射；
- Runtime、OpenAI Gateway、MCP 和 Inline 全部接入；
- Secret、PII、Tool Access、ToolResult Flow 示例迁移为多 Event YAML；
- 删除 Python Rule/RuleRegistry/GuardrailEngine、Structured RulePlan、mandatory anchor、Safe Profile
  迁移桥、v1/v2 Loader 和旧回归样例；
- 旧 v1/v2 Policy 在 Schema 边界拒绝，不提供自动迁移器。

## 当前阶段：规则与接入扩展

按优先级：

1. 参数 JSON Schema/范围约束；
2. 外部域名/URL 策略及可信 URL capability；
3. Tool 调用次数和窗口计数；
4. Prompt Injection 与危险命令 Detector；
5. 可证明 stable identity 的 Framework 增量 InputNormalizer；
6. OpenAI Agents SDK/LangGraph Adapter。

每项必须先建立正常、违规、相邻上限、脱敏和副作用未发生测试。新增 MatchPlan 节点或 capability 要
通过 I01–I14 相邻 fixture，不得重新引入动态 Python、mandatory anchor 或自动顺序 provenance。

## 后续阶段

### 部署

- Dockerfile、非 root 单容器和 healthcheck；
- Compose 示例、只读 Policy mount、Audit volume；
- SBOM/依赖扫描和最小镜像验证。

### 长生命周期

- Policy 热加载、原子版本切换和回滚；
- 跨请求 Session Store：tenant/run token、TTL、CAS、幂等和保留策略；
- committed MatchMonitor identity 持久化；
- 远程 Core/Decision Service。

### 协议与内容

- LLM 实时 Streaming 增量策略；
- MCP subscription/listen；
- 多模态 Content、下载/SSRF/大小限制和媒体 Detector；
- 可验证 TransformationPlan（redact/replace），不扩张普通 Action 枚举。

## 持续验收

- `uv sync --frozen --extra gateway --dev`；
- `pytest --cov` 覆盖率至少 80%（以 `pyproject.toml` 的 `fail_under` 为准）；
- Ruff、Pyright、build、`git diff --check`；
- Secret/PII 不进入 Decision、Audit、异常或日志；
- 生产模块不导入 testing；
- README、architecture、policy、runtime、gateway、deployment 与路由/配置事实一致。
