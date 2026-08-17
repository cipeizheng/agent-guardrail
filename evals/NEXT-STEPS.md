# 评测驱动的后续开发步骤

> 状态：后续规划，不是当前实现。依据是 2026-08 本地评测结果（`data/benchmarks/`，不进 git）与对
> Invariant / NeMo Guardrails / OpenAI Guardrails 三个仓库的对照调研。涉及 capability 交付状态的仍以
> [capability-status.yaml](../docs/capability-status.yaml) 为准；本文件不改变任何当前实现声明。

## 已确认的根因

三层评测指向同一缺口——prompt injection **fact 层检测有效性**：

- 规则 `prompt_injection` 在外部语料 fact recall ≈ 0；`prompt_injection_model` recall ≈ 8%、FP 135；
- `release_external` 轴 FNR = 1.0（归因 `detector gap`）；
- AgentDojo E2E targeted ASR 相对下降 0%（guardrail 几乎未产生 block）。

原有一个评测体系缺口已闭合（2026-08-17，P0-2）：`flow_agentdojo` 决策层 gate 通过
（recall 0.952）而 E2E 无拦截，scripted-agent 一致性测试证实不是 Adapter 构造 bug，
而是地板效应（baseline 模型未中招，攻击目标调用从未出现）。

## 评测基础设施规整（2026-08-17 完成）

针对历史浪费的复盘（judge-arm 覆盖事故、floor-effect 无效运行、混合语料指标污染）落地了
四层规整，总览与约定见 [README.md](README.md)：

1. **不可变 run 目录**：所有入口经 `evals/lib/reporting.py` 写
   `results/<UTC时间戳>-<eval>/report.json` + append-only `index.jsonl` + `latest` 指针，
   历史结果不可覆盖；
2. **测量力预检**：`agentdojo/run.py --mode both` 在 baseline ASR=0 时中止 guarded 臂
   （`--allow-floor` 可显式记录 floor-effect 运行）；
3. **可检测性类别**：语料按 `style_detectable` / `intent_only` / `content_undetectable` /
   `benign` 声明（`evals/lib/detectability.py`，未归类报错）；BIPIA text 攻击归
   `content_undetectable`，其内容分类 recall 不再读作 Detector 缺口；
4. **共享指标/报告库**：`evals/lib/metrics.py`（与原 `run.py` 实现逐位等价，含
   None-score 与并列分数语义）统一 ROC AUC、confusion、Prec@R、Recall@FPR。

## P0（先做，纯评测/归因，不动架构）

1. **操作点标定**：~~已完成（2026-08-16）~~。`run.py` 支持 `--prompt-model-threshold`（部署级参数，
   `create_deployment_detector_registry` 透传）+ `operating_points` 输出（ROC AUC、Prec@R、
   Recall@FPR、threshold grid）。**结论：0.85 不是错误操作点；没有任何操作点可用。** 低阈值
   全量打分（464 样本）显示 `prompt_injection_model` 在 BIPIA(攻击)/NotInject(良性难例) 上
   **ROC AUC = 0.365（低于随机）**，Recall@FPR≤1% 不可达，FPR 36% 时 recall 仍仅 8%--
   分数排序本身与标签反相关：模型学到的是注入“触发词风格”（NotInject 全是含触发词的正常文本），
   不是注入“意图”。阈值调优路线就此关闭；改进必须换输入构造（P1-3）或换判别器（P2-6）。
   结果：`data/benchmarks/prompt-injection/results/sweep-latest.json`（不进 git）。
2. **E2E↔决策层一致性归因**：~~已完成（2026-08-17，`agentdojo/consistency.py`）~~。三个发现：
   - **地板效应**：AgentDojo pilot 的 0% ASR 相对下降不是防御失效--baseline ASR 本身就是
     0/8（deepseek-v4-flash 自行扛住 11 个攻击模板中的 10 个，仅 system_message 1/8），
     0->0 无法测量任何防御价值。E2E 想有测量力必须先让 baseline ASR 非零（更强攻击面或
     更弱模型）。
   - **规则从未触发异常--已排除 Adapter bug**：scripted-agent 一致性测试（确定性执行攻击
     路径，经真实 suite / 工具 / Adapter / Policy）中，email-exfiltration 与 file-destruction
     均在 `blocked_before_tool_call` 拦截，violation code 正确--**E2E 的 0 block 不是
     Adapter 的 may_influence/trust 构造 bug，纯粹是地板效应（模型没中招，pending 调用从未
     出现攻击目标）**。该异常闭合。结果：
     `data/benchmarks/agentdojo/results/20260817T034153Z-agentdojo-consistency/`（不进 git）。
   - **E2E 假阳性遗留**：同测试中 benign flow（用户自己要求发邮件）也被 taint 规则拦截
     （`clean_utility` = 0）--与决策层 delegated 灰区同一根源，但 E2E 侧目前只有 3 个
     case 的脚注。见下方新增条目 7。

## P1（检测有效性实验）

3. **输入构造实验**：~~已完成（2026-08-17，`prompt_injection/segments.py`）--负结果~~。
   把 BIPIA 攻击载荷埋进 4k/12k 字符良性邮件长度的 tool result（位置 0.1/0.5/0.9），
   对比 full-input 与 segment_max（≤1500 字符分段取最大分）：
   **两条条件 recall 均为 0.0**，攻击样本分数中位数 ~1e-4（full）/ ~5e-4（segment_max），
   远低于 0.85 操作点；分段只把分数抬了约 4 倍，量级上仍不可用。结论：DeBERTa 分类器的
   失分不是 512-token 截断机制造成的，**该模型对间接注入载荷本身无判别力，输入构造路线
   与阈值调优路线（P0-1）一并关闭**。改进只剩换判别器（P2-6 LLM judge）。结果：
   `data/benchmarks/prompt-injection/results/segments-latest.json`（不进 git）。
4. **离线延迟基准**：NeMo benchmark 模式——mock OpenAI-compatible 上游压测 Gateway，无 API key
   量化"安全 vs 延迟"（含 streaming 每前缀重分析的成本基线），作为 P4 增量优化的前置数据。
5. **E2E 假阳性的系统度量**：决策层已有 named/delegated 分组的 gate 语义，E2E 侧没有对应
   物--consistency 测试里 benign flow 全被 taint 拦截（`clean_utility` = 0）目前只是 3-case
   脚注。需要扩展 scripted benign flows 到决策层 39 个 benign case 的 E2E 镜像（named 组应
   放行、delegated 组应拦截），让"E2E 上的合法任务损失"有可与决策层对读的数字。

## P2（新 capability，走 adapter_only 起步）

6. **`LLMJudgeProfile` 部署注入 Detector**：类比 `EmbeddingProfile`——部署方固定 judge 模型、
   endpoint、prompt 与超时，Policy 只见 capability 名与有界参数；输出走现有 descriptor 校验与
   脱敏。仅用于释放点检查（外部数据显示延迟 P50 秒级）。验证路径：`evals/detection` 加模型臂，
   未达完成定义前状态保持 `adapter_only`。
7. **第三方攻击语料管道**：把 Garak 类扫描器生成的攻击语料接入 `release` 轴，对冲自编剧本的
   author-imagination bias（detection 评测 limitations 第 1 条）。

## 明确不做（对照调研后的取舍）

- input 检查与 LLM 调用并行（违反不可破坏约束 4）、guardrail 出错默认放行、
  Python 动态策略/动态 import、policy+trace 上云——三家对照进一步证实当前排除理由。
