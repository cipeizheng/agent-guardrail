# evals/corpus —— 第三方语料生成与模型剖面环境

独立的 `pyproject.toml`/`uv.lock`,固定 `agentdojo==0.1.35`(依赖上游 AgentDojo 安装导出攻击负载)。
它是被删的 `evals/agentdojo` E2E 环境唯一存续的职责载体:

- **再生成 release 外部语料**:`uv run --project evals/corpus python evals/detection/gen_agentdojo.py`
  导出 `data/benchmarks/detection/agentdojo-release.json`,被 detection 的 `release_external` 轴与
  prompt_injection 的 `agentdojo_payloads.py`/`promptguard2.py` 消费。
- **detection 模型剖面臂**:`uv run --project evals/corpus python evals/detection/run.py --profile full_deberta`
  (启用 DeBERTa PI 模型等资产)。

不进入仓库默认依赖;`pyproject.toml` 的 pyright exclude 将其排除。