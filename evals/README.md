# 评测体系总览

本目录是仓库的全部评测入口。三层各回答一个问题，下层不能替代上层：

| 层 | 目录 | 回答的问题 | 是否需要真实模型 |
| --- | --- | --- | --- |
| 事实层 | [prompt_injection/](prompt_injection/) | Detector 对固定攻击/难例语料的分类效果（含阈值标定） | 否 |
| 决策层 | [detection/](detection/) | Policy 在单个决策点（pending call / tool_result 释放）上的 ALLOW/BLOCK | 否 |
| 端到端层 | [agentdojo/](agentdojo/) | 完整链路的 ASR/效用与 adapter/Policy 一致性 | 是（consistency.py 除外） |

路线图与各项结论见 [NEXT-STEPS.md](NEXT-STEPS.md)；决策层 gate 判据见
[detection/preregistration.md](detection/preregistration.md)（预注册，跑轴之前冻结）。

## 共享基础设施：`evals/lib/`

Stdlib-only（同时被仓库 venv 与 `evals/agentdojo` 的独立环境导入；两处的 agent-guardrail
editable 安装都通过 pyproject 的 `dev-mode-dirs` 把仓库根目录放上 `sys.path`，入口直接
`from evals.lib import ...`，不再各自做 `sys.path.insert`）：

- `metrics.py`：`roc_auc`（含并列处理）、`confusion_at`、`precision_at_recall`、`recall_at_fpr`。
  语义与部署 Detector 一致：无 Detection 记为 0.0，判定 `score > threshold`。
- `reporting.py`：所有入口共用的报告写入（见下节）。
- `preflight.py`：比较型评测的测量力预检（见「预检约定」）。
- `detectability.py`：语料可检测性类别（见「可检测性类别」）。

新增评测入口时必须复用上述模块，不要再各写一份。

## 结果布局（不可变 run 目录）

一次评测运行 = 一个只写一次的目录，绝不覆盖历史结果（起因：judge-arm 重跑时 402 报错结果
覆盖了唯一一次有效运行的逐样本分数）：

```
data/benchmarks/<eval>/
  results/
    20260817T032219Z-agentdojo-consistency/report.json   # 本次运行的完整报告
    20260817T024958Z-prompt-injection/report.json
    ...
    index.jsonl   # append-only：每行一次运行的 id、git revision、摘要指标
    latest.json   # 最近一次运行的副本（兼容旧消费者；指向性文件，不是唯一存储）
```

- 入口脚本通过 `lib.reporting.write_run_report` 写入：打 `run` 块（id、UTC 时间、git
  revision/dirty）→ 写时间戳目录 → append `index.jsonl` → 原子更新 `latest.json`。
- 手工不得编辑或删除 `results/` 下的历史目录；需要重跑就产生新目录。
- `judge_arm.py` 仍保留 `--output` 作为 latest 指针路径（默认 `judge-arm.json`），同样
  经由 `write_run_report` 写入。

## 预检约定（测量力）

比较型评测（baseline vs guarded）在跑处理臂之前必须确认对照臂有信号：baseline ASR 为 0 时，
guarded 的所有数字都与「攻击从未发生」不可区分（AgentDojo floor-effect 教训，见 NEXT-STEPS）。
`agentdojo/run.py` 在 `--mode both` 下于 baseline 组完成后检查，ASR 为 0 即中止并给出补救建议；
`--allow-floor` 可显式记录一次 floor-effect 运行（报告内标注 `measurement_power`）。

## 可检测性类别

混合语料上的平均 recall 会掩盖「内容层原则上不可分」的子集（BIPIA text 攻击即合法用户指令的
样子，内容分类器在该子集上的 recall 是标签噪声而非 detector 缺口）。语料样本在
`lib/detectability.py` 中按 (benchmark, dataset) 声明类别：

- `benign`：非攻击（FPR 一侧）。
- `style_detectable`：载荷带词法/风格攻击特征（imperative 元指令、散文中的代码块）。
- `intent_only`：文本流畅无害，只有与用户意图/通道上下文的错配能暴露。
- `content_undetectable`：内容层与合法指令不可区分——该子集上的内容分类指标只作记录，不读作
  detector 缺口。
- `unclassified`：未声明；报告聚合时直接报错，逼新语料先归类。

`prompt_injection/run.py` 输出每个 Detector 的 `detectability` 分组指标；
`detection/judge_arm.py` 输出 `per_detectability` 混淆计数。

## 环境

- 事实层/决策层：仓库 venv（`uv sync --frozen --extra detectors --dev` 后 `uv run python evals/...`）。
- 端到端层：`evals/agentdojo` 有独立 `pyproject.toml`（固定 agentdojo 版本），进入该目录
  `uv run`；也被 ruff/pyright 排除在外。模型凭据只放 `.env`，不进 git。
