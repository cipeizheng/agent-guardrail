# AgentDojo 第三方语料生成环境

这个独立环境使用自己的 `pyproject.toml` 和 `uv.lock` 固定 `agentdojo==0.1.35`，只负责从上游安装包导出固定的提示注入攻击载荷。它不参与主项目的运行时依赖：

- `uv run --project evals/corpus python evals/prompt_injection/gen_agentdojo.py`
- 输出 `data/benchmarks/prompt-injection/agentdojo-release.json`，供 `agentdojo_payloads.py`、`promptguard2.py` 与 LLM 评审检测的效果评估使用。

这里的 AgentDojo 只作为第三方攻击载荷来源，输出是供检测效果评估使用的固定语料文件。

依赖安装入口是 `uv run --project evals/corpus`；`pyproject.toml` 的 pyright exclude 覆盖该独立环境。
