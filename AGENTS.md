# Repository Instructions

本仓库使用 AI 辅助实现。日常任务以短合同为入口，ADR 只按任务路由读取，禁止把全部历史 ADR 无差别
塞入上下文。

## 开始任务前

必须按顺序阅读：

1. 本文件。
2. [`docs/current-architecture-contract.md`](docs/current-architecture-contract.md)。
3. [`docs/adr/README.md`](docs/adr/README.md)，并且**只读取其任务路由命中的 ADR**。
4. 与任务直接相关的专项设计文档和代码测试。
5. 实现任务再阅读 [`docs/contributing.md`](docs/contributing.md)。

涉及 Detector、Predicate 或 roadmap 时还必须阅读
[`docs/capability-status.yaml`](docs/capability-status.yaml)。`docs/overview.md` 是完整架构说明，只在
架构评审、跨层修改或短合同无法回答问题时读取，不是每项任务的默认前置全文。

## 工作规则

- 当前实现、不可破坏约束、事实来源和未交付范围以 current architecture contract 为准。
- 非 ADR 文档必须区分“当前实现”“设计合同”“后续规划”，不得把 target、adapter 或模拟测试写成
  verified 能力。
- Capability 状态只能使用状态矩阵的封闭词汇；`adapter_only`、`baseline` 和 `planned` 不得写成
  `verified`。
- 新增 MatchPlan 节点或 capability 必须用 I01–I14 相邻行为测试验证表达、成本和脱敏边界，并映射
  T01–T10；不能重新引入 mandatory anchor、自动 provenance 或第二执行器。
- MCP 版本升级必须先核对官方最终规范和官方 SDK，再修改 ADR、Adapter、黑盒测试与文档。
- 修改前检查工作树；已有修改属于用户，保留无关改动，不使用破坏性 Git 命令。
- 新增行为必须有正常、违规、边界、失败安全和受保护副作用未发生测试。
- 修改代码后同步检查 README、专项设计、roadmap、状态矩阵和部署配置。

## 实现原则

正确性和安全边界 > 可解释性 > 可测试性 > 性能 > 功能数量。

参考 Invariant 时只吸收 typed/multi Event binding、派生值、量词、snapshot Policy、
`past_events + pending_events` Monitor、增量 Finding 和算法覆盖面；不复制 Python import/link、handler、
远程服务耦合、输入检查与上游请求并发或自动 provenance。Invariant `->` 只能对应
`precedes/may_influence`，不能生成 `derived_from`。

参考 NeMo Guardrails 时不复制 Colang、动态 `actions.py` 加载或完整对话编排。Detector hit 只是 fact；
必须映射到安全模型的资产和 T01–T10 路径，并与可信 source/sink、owner、destination 或 authorization
语境组合。

## 完成与提交

提交前至少运行：

```bash
uv sync --frozen --extra gateway --dev
uv run pytest --cov=agent_guardrail --cov-report=term-missing
uv run ruff check .
uv run pyright
uv build
git diff --check
```

检查暂存文件和 Secret 泄露；不得提交 `.venv`、缓存、构建产物、`.env`、审计数据或真实凭据。未经用户
要求不提交或暂存文件。
