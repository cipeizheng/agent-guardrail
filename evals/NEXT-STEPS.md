# 评测驱动的后续开发步骤

> 状态：后续规划，不是当前实现。依据是 2026-08 本地评测结果（`data/benchmarks/`，不进 git）与对
> Invariant / NeMo Guardrails / OpenAI Guardrails 三个仓库的对照调研。涉及 capability 交付状态的仍以
> [capability-status.yaml](../docs/capability-status.yaml) 为准；本文件不改变任何当前实现声明。

## 已确认的根因

两层评测指向同一缺口——prompt injection **fact 层检测有效性**：

- 规则 `prompt_injection` 在外部语料 fact recall ≈ 0；`prompt_injection_model` recall ≈ 8%、FP 135；
- `release_external` 轴 FNR = 1.0（归因 `detector gap`）。

原端到端层（`evals/agentdojo`）已整体删除（2026-08-19）：它既是被删 `flow_agentdojo` 决策轴
（BLOCK 标签复刻规则谓词、影响边脚本手喂，自证循环）的端到端对应物，又因 baseline ASR = 0/8 而
**measurement power 为零**——baseline 从未被攻击，0→0 的 ASR 相对下降无法测量任何防御价值。
保留下来且站得住的两条结论：防御产生 0 block **不是** Adapter/Policy 构造 bug（确定性攻击路径在
`blocked_before_tool_call` 被正确拦截）；以及端到端层若重新引入，必须先让 baseline ASR 非零
（更强的攻击面或更弱的模型），否则按 README 预检约定视为无测量力。

## 评测基础设施规整（2026-08-17 完成）

针对历史浪费的复盘（judge-arm 覆盖事故、floor-effect 无效运行、混合语料指标污染）落地了
四层规整，总览与约定见 [README.md](README.md)：

1. **不可变 run 目录**：所有入口经 `evals/lib/reporting.py` 写
   `results/<UTC时间戳>-<eval>/report.json` + append-only `index.jsonl` + `latest` 指针，
   历史结果不可覆盖；
2. **测量力预检**：比较型评测先跑 baseline 组，ASR=0 即中止 guarded 臂并给出补救建议
   （`evals/lib/preflight.py`，原由被删 `agentdojo/run.py --mode both` 承担，见 README 预检约定）；
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
   不是注入“意图”。阈值调优路线就此关闭；改进必须换输入构造（P1-3）或换判别器（P2-7）。
   结果：`data/benchmarks/prompt-injection/results/sweep-latest.json`（不进 git）。
2. **端到端层删除（2026-08-19）**：`evals/agentdojo`（run.py/adapter/consistency.py/一致性测试/两条
   flow 策略）随 E2E 层整体移除。删除前的历史归因保留了三条可复用教训：地板效应（baseline ASR
   = 0/8，0→0 无测量力）、0 block 非 Adapter bug（确定性攻击路径在 `blocked_before_tool_call`
   被正确拦截）、E2E 层若重引入必须先让 baseline ASR 非零。原 `may_influence` 流程规则
   （block-email/file-destruction-flow）与 flow 概念一并删除。

## P1（检测有效性实验）

3. **输入构造实验**：~~已完成（2026-08-17，`prompt_injection/segments.py`）--负结果~~。
   把 BIPIA 攻击载荷埋进 4k/12k 字符良性邮件长度的 tool result（位置 0.1/0.5/0.9），
   对比 full-input 与 segment_max（≤1500 字符分段取最大分）：
   **两条条件 recall 均为 0.0**，攻击样本分数中位数 ~1e-4（full）/ ~5e-4（segment_max），
   远低于 0.85 操作点；分段只把分数抬了约 4 倍，量级上仍不可用。结论：DeBERTa 分类器的
   失分不是 512-token 截断机制造成的，**该模型对间接注入载荷本身无判别力，输入构造路线
   与阈值调优路线（P0-1）一并关闭**。改进只剩换判别器（P2-7 LLM judge）。结果：
   `data/benchmarks/prompt-injection/results/segments-latest.json`（不进 git）。
4. **离线延迟基准**：NeMo benchmark 模式——mock OpenAI-compatible 上游压测 Gateway，无 API key
   量化"安全 vs 延迟"（含 streaming 每前缀重分析的成本基线），作为 P4 增量优化的前置数据。
5. ~~**E2E 假阳性的系统度量**~~（作废，2026-08-19）：对象是被删 agentdojo E2E 策略的 flow taint
   规则（benign flow 全被拦截、`clean_utility`=0）。规则与 E2E 层已随端到端层删除一并移除，
   该度量不再有主体。

6. **分类器差距探针（LlamaFirewall 对照，2026-08-17）**：DeBERTa 在缺失的语料格上补测完成--
   AgentDojo 载荷 vs NotInject 难例，**ROC AUC 仅 0.590**（PromptGuard 2 论文同基准 0.942；
   threshold 0.85 时 recall 0.257 / FPR 0.398）。结论：PI 差距的主因是**分类器本身**，
   其次才是语料选择（BIPIA/NotInject 0.365 vs AgentDojo/NotInject 0.590）。
   ~~等待 HF 授权~~ **已完成（2026-08-17，`prompt_injection/promptguard2.py`）**：官方仓库
   manual gating 被拒后改用 gravitee-io 镜像同版权重（报告记录 model_source）。三向对比：
   PromptGuard 2 在 AgentDojo/NotInject 上 **AUC 0.972、recall@0.9 = 0.971、FPR 4.1%**
   （DeBERTa：AUC 0.590、recall@0.85 = 0.257、FPR 39.8%）--style_detectable 类上分类器
   差距是真实的、换模型收益巨大；但在 BIPIA/NotInject 上 PromptGuard 2 **AUC 0.436，
   同样低于随机**（recall@0.9 = 0.008）--content_undetectable 的原理性上限结论在强得多的
   分类器上依然成立。可执行结论：PromptGuard 2 是 `prompt_injection_model` 槽位的有力
   替换候选（Llama 4 Community License，非 MIT，商用需过条款 + 700M MAU 条款）。
   结果：`promptguard2-latest.json` 与 `agentdojo-payloads-latest.json`（均不进 git）。
   **已正式接入（2026-08-18）**：新增候选部署 profile `full_promptguard2` /
   `promptguard2`（自描述封闭预设，非组合语法；默认阈值 0.9；镜像 commit + size +
   SHA-256 pin；评分路径对齐 LlamaFirewall）。`full_deberta` 保持默认与 verified；
   capability 记为 `prompt_injection_model_promptguard2`（baseline）。
## P2（新 capability，走 adapter_only 起步）

7. **LLM judge 部署注入 Detector**：~~实现已完成（2026-08-18）~~。`LLMJudgeBackend`/
   `LLMJudgeProfile`/`LLMJudgeDetector` 与 `create_llm_judge_detector_registry` 已随
   `prompt_injection_judge` capability（`P1-D05`）落地：部署方固定 judge 模型、endpoint、prompt 与
   超时，Policy 只见 capability 名与有界参数，输出走现有 descriptor 校验与脱敏。剩余缺口是真实
   judge backend 的 smoke/eval（`evals/detection` 加模型臂）与延迟实测（外部数据显示 P50 秒级，
   仅建议释放点检查），完成前状态保持 `adapter_only`。
8. **第三方攻击语料管道**：把 Garak 类扫描器生成的攻击语料接入 `release` 轴，对冲自编剧本的
   author-imagination bias（detection 评测 limitations 第 1 条）。

## 明确不做（对照调研后的取舍）

- input 检查与 LLM 调用并行（违反不可破坏约束 4）、guardrail 出错默认放行、
  Python 动态策略/动态 import、policy+trace 上云——三家对照进一步证实当前排除理由。
