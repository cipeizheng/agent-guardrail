# Prompt injection Detector benchmark

这是一套独立评测，不属于 pytest，也不改变 capability 的 `verified/baseline/planned` 状态。它回答的范围是：
当前 `DetectorRunner` 对固定攻击载荷和良性难例的分类效果如何。

## 选择与边界

- **[BIPIA attack payloads](https://github.com/microsoft/BIPIA)**：125 条间接 prompt injection 攻击指令，作为正样本。只使用仓库根 MIT
  许可覆盖的 `text_attack_test.json` 与 `code_attack_test.json`，不下载带独立许可的任务上下文数据。
- **[NotInject](https://github.com/leolee99/PIGuard)**：339 条含有常见注入触发词但语义正常的 hard negatives，作为负样本。
- 两者均固定到 manifest 中的 Git revision、文件大小和 SHA-256；下载后评测可以完全离线运行。
- 本评测不调用 LLM、Agent 或 Tool，因此不能给出攻击成功率（ASR）、任务效用或 source→sink 阻断率。
  BIPIA 的完整端到端协议以及 [AgentDojo](https://github.com/ethz-spylab/agentdojo) 属于下一层评测，
  需要真实模型驱动的 Agent。
- [PINT](https://github.com/lakeraai/pint-benchmark) 完整数据没有公开下载入口，因此不作为可复现的第一阶段输入。

## 环境与运行

```bash
uv sync --frozen --extra detectors --dev
uv tool install semgrep==1.170.0
uv run python evals/prompt_injection/fetch.py

AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=data/detector-assets \
  uv run agent-guardrail-prefetch-detectors

uv run python evals/prompt_injection/run.py \
  --profile full_local_v1 \
  --device cpu \
  --detector-assets-dir data/detector-assets \
  --detectors prompt_injection prompt_injection_model
```

默认报告写入已忽略的 `data/benchmarks/prompt-injection/results/latest.json`。报告包含 confusion matrix、
recall、false-positive rate、precision/F1、balanced accuracy、延迟和分类别 detection rate；不保存原始
prompt 或 Detector evidence。`full_local_v1` 当前固定使用 0.85 判定阈值；Detector version 将模型、运行库和
阈值身份绑定进报告。`misclassified_sample_ids` 可通过固定数据文件和 manifest 复核。

若只评测不需要外部资产的规则 Detector：

```bash
uv run python evals/prompt_injection/run.py \
  --profile local \
  --detectors prompt_injection
```

这些指标只能校准 Detector。P3 的 destination/trust-aware Policy 和受保护副作用必须另做 Gateway/SDK
source→sink 回放，不能由本报告替代。
