# AI 辅助开发指南

## 1. 文档优先级

发生冲突时按以下优先级处理：

1. 用户当前明确要求。
2. 根目录 `AGENTS.md`。
3. 已接受 ADR。
4. `docs/architecture.md` 的安全不变量。
5. 专项设计文档。
6. 现有代码和测试。

不能因为实现方便而静默改变架构；需要改变时先新增或更新 ADR。

## 2. AI 开始任务前

必须：

1. 阅读 `AGENTS.md`。
2. 阅读任务相关文档。
3. 检查现有代码、测试和未提交修改。
4. 写出本次任务明确不做什么。
5. 将任务拆成可独立验证的小步骤。

## 3. 实现约束

- Python 3.12，优先标准库与小型依赖。
- 公共数据模型使用 Pydantic。
- I/O API async-first，纯计算可以同步。
- Core 不导入 FastAPI、OpenAI SDK 或具体 Agent 框架。
- Provider/Framework 代码位于 `adapters/`，HTTP composition 位于 `gateway/`。
- Inline Enforcement 位于 `enforcement/`，且只依赖 `DecisionEvaluator`。
- Fake 与 SimulatedAgent 位于 `testing/`，生产模块不得导入它们。
- 配置模型 `extra="forbid"`。
- 使用显式依赖注入，不使用不可控的全局单例。
- 时间、ID、HTTP Client 和 Tool Executor 必须可替换以便测试。
- 不使用 `eval`、`exec`、动态外部 import 或 pickle 策略。
- 不把未知异常吞掉并返回 allow。
- 不把 Secret、完整 prompt 或工具结果写入普通日志。

## 4. 测试模板

每个 Rule 至少测试：

- 不适用阶段。
- 安全输入。
- 明确违规。
- 缺失/畸形字段。
- 配置边界。
- Rule/Detector 错误路径。

每个 Enforcement Point 至少测试：

- allow 时副作用执行一次。
- log 时副作用执行一次且审计存在。
- block 时副作用执行零次。
- 超时时符合 fail-open/fail-closed 配置。
- 原始敏感内容未出现在错误或日志。

Gateway 测试统一使用 HTTP MockTransport/Fake Upstream，不允许单元测试访问真实模型 API。

## 5. Definition of Done

任务完成必须同时满足：

- 行为符合设计文档。
- 新代码有类型明确的公共接口。
- 正常与失败路径有测试。
- `uv run pytest` 通过。
- `uv run ruff check .` 通过。
- `uv run pyright` 通过。
- 相关文档和示例更新。
- 没有新增未声明的网络、文件或进程副作用。
- 没有降低安全不变量。

## 6. 推荐任务提示模板

```text
目标：
实现 <一个具体能力>。

必须阅读：
- AGENTS.md
- docs/<相关文档>
- docs/adr/<相关 ADR>

范围：
- ...

明确不做：
- ...

验收：
- ...
- block 时副作用计数必须为零
- pytest 和 ruff 通过
```

## 7. Review 检查清单

- 检查是否在 Policy Decision 前启动了副作用。
- 检查错误是否被错误地当作 allow。
- 检查 raw Secret 是否进入日志。
- 检查规则是否错误地依赖 Provider 原始格式。
- 检查 YAML 是否能够指定任意 Python 对象。
- 检查缓存 key 是否包含 policy/detector version。
- 检查 Trace 是否有无限增长风险。
- 检查拒绝响应是否泄露堆栈或完整策略。
- 检查 block 是否真的阻止了工具/网络调用。
- 检查 LLM 与 Tool Wrapper 是否错误地创建了不同 Session/Trace。
- 检查 block 的原始 Event 是否误入 Trace 或 Audit。

## 8. 何时停止并请求设计决策

以下情况不得自行猜测：

- 要新增 Action 或改变严重度顺序。
- 要支持 streaming 并声称可阻断输出。
- 要允许外部用户编写动态策略。
- 要引入远程 Core、数据库或消息队列。
- 要改变 Canonical Event 字段语义。
- 要保存完整 prompt/工具结果。
- 要增加自动 Redact/Rewrite。

先写 ADR，列出安全影响、兼容性和替代方案。
