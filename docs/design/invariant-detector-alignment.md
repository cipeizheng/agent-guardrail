# 与 Invariant 的检测能力对照

> 本文说明本项目的检测器和条件判断如何对照 Invariant 的实现，以及本项目额外保留的输入限制、失败处理和脱敏边界。
> 相关参考：[能力状态矩阵](../capability-status.yaml)、[安全模型](../security-model.md)。

## 1. 对照基线和含义

参考对象固定为 `../invariant` 的 commit `2340fe2`；NeMo Guardrails 参考对象固定为同级 `../Guardrails` 的 commit `891c13f64`。这里的“对照”是指：在本项目的标准事件、注册表、检查计划和执行边界内，得到相近的检测结果，同时遵守本项目的输入、预算和脱敏约束。

本文中的 `profile` 指部署时固定的一组配置，`backend` 指实际执行检测的实现，`adapter` 指把外部实现限制在本项目能力接口内的包装层。

检测能力对照遵循以下生产约束：

- 部署方固定实现和 descriptor，规则不能选择模型、规则文件、进程、语言包或上游地址；
- 输入字节数、调用次数、deadline、结果数量、位置和证据都有上限；
- 后端缺失、timeout、预算耗尽、非法输出和异常都会显式失败，不会被当成“没有命中”；
- `Detection` 只包含有限类型、位置、置信度、遮罩和不依赖原始内容的 occurrence fingerprint；
- 检测命中只是一个事实，必须与可信来源、目的地或授权语境组合。

## 2. 检测能力对照

| Invariant 能力 | 本项目能力 | 对齐方式 |
| --- | --- | --- |
| `secrets` | `secrets` | 直接升级同名实现；固定 recognizer、格式校验和误报过滤 |
| `pii` | `pii` | Invariant 英文 Presidio 基线加本地校验规则；可选 NER 检测后端由部署方注入 |
| `prompt_injection` | `prompt_injection` / `prompt_injection_model` | 确定性高信号事实与锁定模型配置分开报告 |
| `unicode` | `unicode_security` | 检测危险类别、双向/零宽字符和有限混合脚本混淆 |
| `fuzzy_contains` | `fuzzy_contains` Predicate | 有界编辑距离；不使用大模型语义兜底 |
| `embedding_similarity` / `is_similar` | `is_similar` 相似度条件 | string/list、max-pair 和命名阈值对齐；部署配置选择向量模型 |
| `python_code` / `ipython_code` | `python_ast_ipython` | AST/IPython 结构归约为有限安全类别 |
| `semgrep` | `semgrep` | 固定检测后端和配置；Policy 不提供语言或规则参数 |
| HTML parser | `hidden_content` | 检测隐藏 HTML、注释、不可见样式和有限编码内容 |

NeMo Guardrails 的 YARA injection 能力映射到本项目的 `yara_injection_signatures` Detector 合同。规则由部署配置固定，Policy 通过 capability 名称引用；payload transformation 由单独的后续设计处理。

Invariant HTML parser 还提取 link 供后续规则消费；本项目的 `hidden_content` 报告 alt/meta 等结构事实及真正隐藏/编码内容。URL 由显式字段提取与 `url_host_allowed` 等能力处理，普通 link 按 URL 语义处理。

## 3. 本项目的安全边界

- `fuzzy_contains` 使用有界本地编辑距离；异常沿 capability 错误路径返回。
- `is_similar` 允许 Policy 选择 data、target 和 threshold；向量模型、上游地址与凭据属于部署 `EmbeddingProfile`/backend。
- Python Detector 只报告审查过的风险类别；Semgrep/YARA 使用部署方固定的语言、规则和进程参数。
- PII 与 Secret 检测不返回命中原文，低熵内容不会通过 fingerprint 复原。
- 多语言 NER、moderation、copyright 和 OCR 属于 content/compliance 或多模态能力，按独立能力规划和验收。

`is_similar` 的 MatchPlan 扩展映射 I09/I10/I12/I13：同一份快照内的确定性缓存、整批待提交事件绑定、显式 Registry 连接，以及有界输入/timeout/脱敏证据；威胁用途映射 T03/T04。命中是 `semantic_similarity` 事实，需要与来源、目的地或授权语境组合。

## 4. 验证要求

`verified` 与 `baseline` 能力具有真实本地算法或固定后端；`experimental` 能力具有独立真实评测路径；`adapter_only` 能力具有接口、预算和模拟后端约定。完成定义覆盖安全输入、攻击输入、相邻误报、畸形输入、上限、timeout/异常、脱敏证据、Registry 连接、MatchPlan/Decision 投影和适用检查点的零副作用断言；外部后端的模拟实现只作为适配合同证据。
