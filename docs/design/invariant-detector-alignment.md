# Invariant Detector 对齐合同

> 适合谁：实现或评审本项目内置 Detector/Predicate 的开发者。
> 解决什么：规定与同级 Invariant checkout 的算法对齐范围、名称映射和安全差异。
> 不包含什么：Capability 的当前交付状态；状态只以 `capability-status.yaml` 为准。

## 1. 对齐基线与含义

参考对象固定为 `../invariant` commit `2340fe2`；NeMo Guardrails 参考对象固定为同级 `../Guardrails`
commit `891c13f64`。对齐指在本项目 Canonical Event、Registry、MatchPlan 和 Enforcement 边界内达到相邻
的检测结果，不复制 IPL/Colang、Policy import、运行时依赖安装、远程调用或返回原始内容的接口。

Detector 对齐必须同时保留：

- 部署方固定实现和 descriptor，Policy 不能选择模型、规则文件、进程、语言包或 endpoint；
- 输入字节、调用次数、deadline、结果数量、span 和 evidence 上限；
- backend 缺失、timeout、预算耗尽、非法输出和异常显式失败，不能退化为 no-match；
- Detection 只包含有限类型、位置、置信度、遮罩和不依赖 payload 的 occurrence fingerprint；
- Detector hit 只是 fact，必须与可信 source/sink、owner、destination 或 authorization 语境组合。

## 2. 能力映射

| Invariant 能力 | 本项目能力 | 对齐方式 |
| --- | --- | --- |
| `secrets` | `secrets` | 直接升级同名实现；固定 recognizer、格式校验和误报过滤 |
| `pii` | `pii` | 同名本地多语言规则；可选 NER backend 由部署方注入 |
| `prompt_injection` | `prompt_injection` / `prompt_injection_model` | 确定性高信号事实与锁定模型 profile 分开报告 |
| `unicode` | `unicode_security` | 检测危险类别、双向/零宽字符和有限混合脚本混淆 |
| `fuzzy_contains` | `fuzzy_contains` Predicate | 有界编辑距离；不使用 LLM semantic fallback |
| `embedding_similarity` / `is_similar` | `embedding_similarity` Predicate | 纯、有限向量相似度；文本 embedding 在 Policy 执行外预计算 |
| `python_code` / `ipython_code` | `python_ast_ipython` | AST/IPython 结构归约为有限安全类别 |
| `semgrep` | `semgrep` | 固定 backend/profile；Policy 不提供语言或规则参数 |
| HTML parser | `hidden_content` | 检测隐藏 HTML、注释、不可见样式和有限编码内容 |

NeMo Guardrails 的 jailbreak heuristic/model 与 YARA injection 能力也属于当前 roadmap，但继续使用本项目
的 `jailbreak` 和 `yara_injection_signatures` Detector 合同，不引入 Colang、动态 `actions.py`、inline YARA
规则或 payload transformation。

Invariant HTML parser 还提取 link 供后续规则消费；本轮 `hidden_content` 只报告 alt/meta 等结构事实及真正
隐藏/编码内容。URL 仍由显式字段提取与 `url_host_allowed` 等能力处理，不把普通 link 自动标为 hidden fact。

## 3. 有意不对齐

- `fuzzy_contains` 不在失败后调用 OpenAI 或其他 LLM，也不吞掉异常。
- `embedding_similarity` 不允许 Policy 选择 embedding model 或远程 provider。
- Python Detector 不向 Policy 暴露任意 module/function 字符串；只报告审查过的风险类别。
- Semgrep/YARA 不接受 Policy 提供的语言、规则、文件路径、命令或进程参数。
- PII 与 Secret 检测不返回命中原文，低熵内容不能通过 fingerprint 离线枚举。
- Invariant 的 moderation、copyright 和 OCR 属于 content/compliance 或多模态后续阶段，不在本轮核心
  T01–T09 安全 Detector 对齐范围内。

## 4. 验证要求

每个能力至少具有真实本地算法或明确的 `adapter_only` backend 状态，并覆盖安全输入、攻击输入、相邻误报、
畸形输入、上限、timeout/异常、脱敏 evidence、Registry linking、MatchPlan/Decision 投影和适用 pre
Enforcement Point 的零副作用断言。外部 backend 的 fake 只验证适配合同，不能把状态提升为 `verified`。
