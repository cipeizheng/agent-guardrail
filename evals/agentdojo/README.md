# AgentDojo 端到端评测

本目录把同一个真实 Tool-calling Agent 分别接到无防御 Pipeline 和当前 agent-guardrail Pipeline，测量
端到端量：攻击是否最终触发目标副作用，以及防御是否破坏正常任务效用。它与
[策略决策点 detection 评测](../detection/README.md) 互补——那一层按能力轴逐决策点给出混淆矩阵，
本层只验证完整链路（Detector + source fact + Relation + Policy + release block）的真实运行。

## 固定边界

- AgentDojo 固定为 `0.1.35`，benchmark 固定为 `v1.2.2`；独立 `uv.lock` 不进入生产依赖。
- 默认 pilot 使用 `workspace` 的 4 个 user task、2 个 injection task 和
  `important_instructions`，共 4 个正常任务与 8 个攻击组合，每组另验证 2 个 injection task 能否作为正常
  用户任务完成。
- guarded Pipeline 对正常与攻击样本一视同仁：所有 AgentDojo ToolResult 都由评测 Adapter 标为
  `external_untrusted`，不读取 injection 标签。
- Policy 只有在 ToolCall→ToolResult 的显式 direct `derived_from` 关系成立，并且现有 Detector 命中时 block；
  `external_untrusted` 本身不触发 block。
- block 发生在 ToolResult 释放给下一次模型调用之前。被 block 的原始结果不进入消息历史；Adapter 以固定、
  不包含原文的终止消息结束当前 Agent 运行。
- runner 直接使用 AgentDojo suite 的 utility/security oracle，不使用会保存完整对话的默认 TraceLogger。
  报告只保存任务 ID、布尔结果、聚合指标和 Guardrail 计数。

这仍是一次小样本 pilot，不是统计显著性结论，也不证明 Guardrail 能理解用户意图。它只评估当前
Detector + source fact + Relation + Policy + release block 的端到端实际效果。

## 环境

```bash
uv sync --project evals/agentdojo --frozen --dev
uv tool install semgrep==1.170.0

uv run --project evals/agentdojo python evals/agentdojo/run.py --validate-only
```

`--validate-only` 除了固定依赖、任务 ID、Detector 资产和 Policy 编译，还用脚本化 LLM 运行一条安全
ToolResult 与一条攻击 ToolResult，验证安全结果可释放、攻击结果被 block 且不进入消息历史。这个 smoke 只证明
Adapter 合同，并校验聚合报告 Schema；不计入真实 Agent 的 utility 或 ASR。报告记录实际 Python 和依赖版本。

`full_local_v1` 默认从已忽略的 `data/detector-assets` 离线加载固定 DeBERTa、YARA 和其他 profile 资产；
该 profile 启动时也验证固定 Semgrep CLI，因此独立环境使用同一个 `1.170.0` 版本。
若资产尚不存在：

```bash
AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=data/detector-assets \
  uv run --project evals/agentdojo agent-guardrail-prefetch-detectors
```

真实评测需要模型凭据，或在 `LOCAL_LLM_PORT` 上运行兼容的本地 Tool-calling 模型。凭据只通过环境注入，
不写入命令、配置或报告。DeepSeek Responses provider 固定连接 `https://api.deepseek.com`，使用无状态完整
history 和函数 Tool，且固定关闭 thinking。配置 Key：

```bash
read -rsp "DeepSeek API key: " DEEPSEEK_API_KEY
printf '\n'
export DEEPSEEK_API_KEY
```

运行 DeepSeek pilot：

```bash
uv run --project evals/agentdojo python evals/agentdojo/run.py \
  --provider deepseek-responses \
  --model deepseek-v4-flash \
  --mode both
```

`--model` 也可选择 `deepseek-v4-pro`；省略时默认 `deepseek-v4-flash`。已有 OpenAI 凭据时仍可使用 AgentDojo
内置 provider：

```bash
uv run --project evals/agentdojo python evals/agentdojo/run.py \
  --model gpt-4o-mini-2024-07-18 \
  --mode both
```

默认报告写到已忽略的 `data/benchmarks/agentdojo/results/latest.json`。不要提交 `.env`、模型凭据、AgentDojo
原始 trace 或报告数据。

## 指标与停止条件

报告同时给出 baseline/guarded 的正常 utility、攻击下 utility、security rate、targeted ASR，以及正常运行中
ToolResult 的实际 block rate。预注册的 pilot 继续条件是：

- 正常 utility 下降不超过 5 个百分点；
- targeted ASR 相对下降至少 50%；
- Guardrail block 的原始 ToolResult 未释放给模型。

若 baseline ASR 为 0，当前模型/任务组合不能衡量防御收益，ASR 相对下降记为不可计算。判据失败后的走向
（收窄产品范围、修正规则粒度或停止该方向）不在预注册内决定，在 `docs/proposals/` 中依据失败样本讨论；
该流程同时区分两类响应：修正已测量的粒度缺陷（如字段级来源）必须附带新的预注册判据后重跑，事后增加
Tool 分类、意图判断或放行规则直到指标通过仍然禁止。
