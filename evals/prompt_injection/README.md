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

# 可选:PromptGuard 2 候选 profile 的固定资产(镜像 repo,约 1.1GB)
AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=data/detector-assets \
  uv run agent-guardrail-prefetch-promptguard2

uv run python evals/prompt_injection/run.py \
  --profile full_deberta \
  --device cpu \
  --detector-assets-dir data/detector-assets \
  --detectors prompt_injection prompt_injection_model
```

报告经由共享的 `evals/lib/reporting.py` 写入不可变 run 目录
`data/benchmarks/prompt-injection/results/<UTC时间戳>-prompt-injection/report.json`，并 append
`results/index.jsonl`、原子更新 `results/latest.json`（布局与约定见 [evals/README.md](../README.md)）。
报告包含 confusion matrix、recall、false-positive rate、precision/F1、balanced accuracy、延迟、
分类别 detection rate，以及按可检测性类别（`benign`/`style_detectable`/`content_undetectable`，
定义见 `evals/lib/detectability.py`）分组的指标——BIPIA text 攻击在
`content_undetectable` 上的内容分类 recall 是标签噪声，不读作 Detector 缺口。报告不保存原始
prompt 或 Detector evidence。`full_deberta` 的部署默认阈值是 0.85,PromptGuard 2 候选 profile
(`full_promptguard2`/`promptguard2`,Llama 4 Community License,非默认)为 0.9；Detector version 将模型、运行库和
阈值身份绑定进报告。`misclassified_sample_ids` 可通过固定数据文件和 manifest 复核。

### 操作点标定（threshold sweep）

`--prompt-model-threshold` 是部署级参数（传给 `create_deployment_detector_registry`；Policy 不能选择）。
传入一个足够低的值（≤ 0.01，例如 `1e-6`）时，每个样本的原始分类分数通过 Detection confidence 完整暴露
（无 Detection 记为 0.0），报告额外输出 `prompt_injection_model` 的 `operating_points`：

- `roc_auc`：含并列分数处理的 rank-based AUC；
- `precision_at_recall`（0.80/0.90/0.95）与 `recall_at_fpr`（0.01）；
- `threshold_grid`：0.30–0.95 固定网格的混淆矩阵（含 0.85 行，可直接与历史报告对照），
  判定语义与 Detector 一致（`score > threshold`）。

```bash
uv run python evals/prompt_injection/run.py \
  --profile full_deberta \
  --device cpu \
  --detector-assets-dir data/detector-assets \
  --detectors prompt_injection_model \
  --prompt-model-threshold 1e-6
```

一次低阈值运行即可得到全部分数分布；`overall` 混淆矩阵对应低阈值操作点本身，历史 0.85 结果看
`threshold_grid["0.85"]`。

若只评测不需要外部资产的规则 Detector：

```bash
uv run python evals/prompt_injection/run.py \
  --profile local \
  --detectors prompt_injection
```

这些指标只能校准 Detector。P3 的 destination/trust-aware Policy 和受保护副作用必须另做 Gateway/SDK
source→sink 回放，不能由本报告替代。
