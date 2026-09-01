# evals/corpus —— 第三方 AgentDojo 语料生成环境

独立的 `pyproject.toml`/`uv.lock` 固定 `agentdojo==0.1.35`，执行范围是从上游安装导出固定攻击载荷：

- `uv run --project evals/corpus python evals/prompt_injection/gen_agentdojo.py`
- 输出 `data/benchmarks/prompt-injection/agentdojo-release.json`，供 `agentdojo_payloads.py`、`promptguard2.py` 与 LLM judge 特性评估消费。

这里的 AgentDojo 用途是第三方 Detector 攻击载荷来源。输出是固定语料文件。

依赖安装入口是 `uv run --project evals/corpus`；`pyproject.toml` 的 pyright exclude 覆盖该独立环境。
