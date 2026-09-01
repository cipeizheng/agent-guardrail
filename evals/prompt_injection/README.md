# 提示注入检测效果评估

本评估记录提示注入检测器对固定攻击载荷和良性难例的分类表现。代码中的 `DetectorRunner` 是直接运行一个或多个检测器的接口；检测能力的交付状态记录在 `docs/capability-status.yaml`。

## 评估范围与数据

- **[BIPIA attack payloads](https://github.com/microsoft/BIPIA)**：125 条间接 prompt injection 攻击指令，作为正样本。输入范围是仓库根 MIT 许可覆盖的 `text_attack_test.json` 与 `code_attack_test.json`。
- **[NotInject](https://github.com/leolee99/PIGuard)**：339 条包含常见注入触发词、但语义正常的困难负样本，作为负样本。
- 两者均固定到 manifest 中的 Git revision、文件大小和 SHA-256；下载后评测可以完全离线运行。
- 主入口执行检测组件。AgentDojo 在这里提供固定攻击载荷；输出指标描述检测组件的分类结果。
- [PINT](https://github.com/lakeraai/pint-benchmark) 作为可选语料；纳入评估时使用 revision-pinned 公开下载文件。

## 安装与运行

```bash
uv sync --frozen --extra detectors --dev
uv tool install semgrep==1.170.0
uv run python evals/prompt_injection/fetch.py

AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=data/detector-assets \
  uv run agent-guardrail-prefetch-detectors

# 可选：PromptGuard 2 profile 的固定资产（镜像 repo，约 1.1GB）
AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=data/detector-assets \
  uv run agent-guardrail-prefetch-promptguard2

uv run python evals/prompt_injection/run.py \
  --profile full_deberta \
  --device cpu \
  --detector-assets-dir data/detector-assets \
  --detectors prompt_injection prompt_injection_model
```

报告经由共享的 `evals/lib/reporting.py` 写入不可变的单次运行目录 `data/benchmarks/prompt-injection/results/<UTC时间戳>-prompt-injection/report.json`，追加到 `results/index.jsonl`，并原子更新 `results/latest.json`（目录布局见 [评估工具说明](../README.md)）。报告包含混淆矩阵、召回率、误报率、精确率/F1、平衡准确率、延迟、各类别检测率，以及按可检测性分类（`benign`/`style_detectable`/`content_undetectable`，定义见 `evals/lib/detectability.py`）分组的指标。BIPIA 文本攻击在 `content_undetectable` 分组中的内容分类召回率，按数据标签可能存在噪声解释。报告保存样本 ID、聚合指标和脱敏结果。`full_deberta` 的部署默认阈值是 0.85，PromptGuard 2 可选配置（`full_promptguard2`/`promptguard2`，Llama 4 Community License）为 0.9；`Detector version` 会把模型、运行库和阈值身份绑定进报告。`misclassified_sample_ids` 可通过固定数据文件和清单复核。

### 阈值评估

`--prompt-model-threshold` 是传给 `create_deployment_detector_registry` 的部署级参数，Policy Schema 不负责设置它。传入一个足够低的值（≤ 0.01，例如 `1e-6`）时，每个样本的原始分类分数会通过 `Detection.confidence` 完整保留（没有检测结果的样本记为 0.0），报告额外输出 `prompt_injection_model` 的 `operating_points`（不同阈值下的评估结果）：

- `roc_auc`：考虑并列分数的排序式 AUC；
- `precision_at_recall`（0.80/0.90/0.95）与 `recall_at_fpr`（0.01）；
  - `threshold_grid`：0.30–0.95 固定阈值网格中的混淆矩阵（含 0.85 阈值），判定方式与 Detector 一致（`score > threshold`）。

```bash
uv run python evals/prompt_injection/run.py \
  --profile full_deberta \
  --device cpu \
  --detector-assets-dir data/detector-assets \
  --detectors prompt_injection_model \
  --prompt-model-threshold 1e-6
```

一次低阈值运行即可得到全部分数分布；`overall` 混淆矩阵对应低阈值结果，0.85 阈值的结果查看 `threshold_grid["0.85"]`。

若只评测不需要外部资产的规则 Detector：

```bash
uv run python evals/prompt_injection/run.py \
  --profile local \
  --detectors prompt_injection
```

可选的 AgentDojo 固定载荷由独立环境生成：

```bash
uv run --project evals/corpus python evals/prompt_injection/gen_agentdojo.py
```

要经生产 `DetectorRunner` 特性评估 DeepSeek judge，可配置 `DEEPSEEK_API_KEY` 后运行：

```bash
uv run python -m evals.prompt_injection.judge
```

该命令输出 DeepSeek judge 在固定语料上的分类特性。仓库单元测试和集成测试验证规则执行、调用前检查、输出释放和受保护操作的执行次数。
