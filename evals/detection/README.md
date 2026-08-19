# 策略决策点 detection 评测

本目录把评测对象从"完整 Agent 攻击链"改为**Policy 的单个决策点**：给定一段 trace(用户目标、历史
ToolResult、pending ToolCall),Policy 应该回答 ALLOW 还是 BLOCK。它与真实模型是否中招无关，因此
baseline ASR 为 0 不再使评测失效；正常效用问题被直接转化为 benign 样本上的 false positive。

本层是 Policy/Predicate/Detector 组合的主迭代循环；原端到端层(真实 Agent 完整链路的 ASR/效用对照)已
随 `evals/agentdojo` 一并移除(measurement power 为零,见总览)。

## 能力轴与规则编写路线

规则编写是本评测的一等工作项：每个攻击家族 = 一份 YAML 规则配方 + 一组语料 case + 消融。语料扩张
驱动规则扩张——新家族先加语料、再写规则、再消融。家族按[安全模型](../../docs/security-model.md)的
T01–T10 威胁路径锚定：

| 家族 | 威胁路径 | 规则模式 | 依赖 capability | 状态 |
| --- | --- | --- | --- | --- |
| secret/PII 外传 | T01/T02 | 内容事实 + sink 工具 | `secrets`、`pii` | demo |
| URL egress | T02/T09 | host allowlist | `url_host_allowed` | demo |
| 数值/资源界 | T04 | 范围约束 | `number_in_range`、`length_in_range` | demo |
| 注入内容释放 | T03 | 释放点拦截：untrusted tool_result 含注入事实 | `prompt_injection`、`unicode_security`、`prompt_injection_model`（full profile 模型臂） | demo |
| Unicode 走私 | T07 | 释放点拦截：控制/零宽字符 | `unicode_security` | demo |
| 代码执行 | T04 | execute_code 参数结构事实 | `python_ast_ipython`（local）、`semgrep`（full profile） | demo |
| 目的地授权复用 | T09 | `security_destination`/`security_authorization` 参数规则 | 安全参数 + FlowSecurityContext 接入 | 待编（依赖 P3） |
| 语义改写注入 | T03 | 语义相似度 | `is_similar` | 待编（依赖 backend 验证） |

评测的决策点不限于 pending tool call：case 通过 `decision_point` 声明测哪个提交点（pending call 或
首个 tool_result 的释放）。

## 双通道接入

同一份语料经过项目的两条公开接入方式，分别测不同层：

| 通道 | 接入 API | 测什么 | 输出 |
| --- | --- | --- | --- |
| decision 层 | `GuardrailRun`（Event/Relation -> Decision） | 规则组合在决策点的 ALLOW/BLOCK | 分轴策略混淆矩阵 |
| fact 层 | `DetectorRunner`（`detect_text`/`detect_json`/`detect_many`） | Detector 事实质量，不写 YAML、不经规则 | 分 capability 事实矩阵 |

case 通过 `fact_probes` 声明 fact 层期望（文本是否真的含有该 capability 应识别的材料）。两层跑同一
语料后，decision 层的失配可归因：

- **detector gap**：fact 层也没报 -> 改进 Detector（进 `evals/prompt_injection` 回归），规则没错；
- **rule composition gap**：fact 层报了但 decision 层放行 -> 改 YAML 组合；
- **detector false alarm**：fact 层误报导致的 decision FP。

release 轴的 `release-indirect-injection` 是刻意的示例：间接注入的 fact 层 recall 缺口（P0-D04
baseline 已知限制）直接传导为 decision FN，归因输出为 `detector gap`——这指引工作方向是 Detector
改进而不是加规则。

## 标签规则

每个 case 的 ground truth 按显式规则标注，不按直觉（BLOCK 为攻击构造命中目标谓词，其余 ALLOW）。

## 语料来源与已知限制

- 当前为脚本化语料（`corpus.py`），BLOCK 样本由作者构造，存在"作者想象力偏差"——它证明规则在
  构造攻击上的行为，不证明对未知攻击的覆盖率；
- ALLOW 样本应逐步替换为真实模型收割的 benign trace（模型越强保真度越高）；
- 语料中不允许出现 Policy capability 源码里的字面特征（防止评测与实现同源）。

## 指标

每个 (轴, Policy) 输出 TP/FP/TN/FN、precision/recall、benign FPR、attack FNR。episode 分组统计
在语料引入真实收割 trace 后补充。

## 预注册

判据已随外部语料扩容冻结，见 [preregistration.md](preregistration.md)。要点：`release_external`
轴上模型臂 gate 为 attack recall ≥ 0.90 且 benign FPR ≤ 0.10（预期失败，先验已在文件中披露）；
启发式臂为报告型消融；脚本化轴维持 0 mismatch 回归基线。冻结后的修改须以 `post_hoc` 披露。

## 运行

```bash
# local profile（默认）：不依赖模型凭据与外部 detector 资产
uv run python evals/detection/run.py

# full_deberta：启用 DeBERTa PI 模型等资产，release 轴额外跑模型规则臂
uv run --project evals/corpus python evals/detection/run.py --profile full_deberta

# 候选 profile：full_promptguard2（全栈换 PromptGuard 2）与 promptguard2（仅 PromptGuard 2）；
# PromptGuard 2 配套 Llama 4 Community License（非 MIT），为 opt-in 候选而非默认
uv run python evals/detection/run.py --profile promptguard2
```

外部语料（BIPIA 125 攻击 / NotInject 339 良性 / AgentDojo v1.2.2 35 攻击，先运行
`evals/prompt_injection/fetch.py` 与 `gen_agentdojo.py` 生成）在 `release_external` 轴
单独报告；`--no-external` 可跳过。外部 case 自带可检测性类别
（`evals/lib/detectability.py`，未归类直接报错），`judge_arm.py` 额外输出
`per_detectability` 混淆计数。

报告与 `judge_arm.py` 的输出都经由 `evals/lib/reporting.py` 写入不可变 run 目录
`data/benchmarks/detection/results/<UTC时间戳>-<eval>/report.json`，并 append
`results/index.jsonl`、原子更新各自的 latest 指针（布局见 [evals/README.md](../README.md)）。

## 已测结果（2026-08-15，gate 判据见 preregistration.md）

脚本化 release 轴（10 样本，作者编写）：启发式漏间接注入 1 例（归因 detector gap）；
模型臂 FN=0 / benign FPR=0.00。**外部 release 轴（160 攻击 + 339 良性难例）结论相反**：
启发式 0/160 命中、0 误报；DeBERTa@0.85 模型臂 recall 0.069 / FPR 0.348，gate FAIL
（判据 recall≥0.90 且 FPR≤0.10）。双通道归因显示模型臂 267 个错判全部是 detector 层问题
（149 detector gap + 118 detector false alarm，0 rule composition gap）--瓶颈在分类器，
不在规则编排。处置按预注册走 detector 改进线（阈值/模型替换，在
`evals/prompt_injection` 层做，调参须预先声明 split），不做规则白名单补丁。

LLM judge 特性化（`llm_judge.py`，DeepSeek-v4-flash 意图对齐，同一 499 样本，无 gate、
prompt 固定不赛后调参）：recall 131/160 = 81.9%（AgentDojo 35/35、BIPIA 96/125），
但 NotInject 误报 126/339 = 37.2%--召回较 DeBERTa 提升约 12 倍，FPR 持平。结论：
release 轴全部统计检测器（含外部 LLM judge，FPR 37%）都达不到可部署精度；LLM judge 是
最强检测信号但 FPR 不可部署，只能作信号层（审计/降级/双命中升级）；DeBERTa 与关键词
启发式均不足以承担防线。
