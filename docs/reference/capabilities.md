# Capability 参考

> 适合谁：使用或实现 Predicate/Detector 的 Policy 作者和部署开发者。
> 解决什么：Registry linking、有界执行、evidence 以及当前内置目录。
> 不包含什么：Rule 组合语法和未来 capability 排期。

## 1. 信任边界

MatchPlan 只保存 capability 名称、有限 Value reference、encoding 和 evidence projection，不保存 callable、
module path、import、callback 或 I/O 权限。

部署所有者在启动代码中构造 Registry，注册实现与 descriptor，再显式 linking：

```python
compiled = compile_match_plan_capabilities(
    plan,
    predicates=predicate_registry,
    detectors=detector_registry,
)
matcher = SnapshotMatcher(compiled, policy_version=3, policy_hash="...")
```

未 linking 的纯 Plan 只要 Rule 含 capability 节点，就在枚举前产生脱敏 `capability_error`。YAML 不能声明
descriptor、实现位置、模型、文件、进程或 endpoint。

Predicate 是纯、类型化、无 I/O 布尔能力。Detector 产生脱敏事实，不决定 action。可信 Detector backend
若需要模型、文件、进程或网络，这些权限必须由部署 profile 固定并隔离，Policy 不能选择具体资源。

## 2. 编译与有界执行

linking 在分析前原子验证：

- 名称、实现版本和 descriptor 一致；
- Predicate arity、静态类型、输入字节、deadline 和 evidence policy；
- Detector encoding、公开 detection type、输入字节、deadline、结果数量和 evidence policy；
- 未注册、未发布或不兼容 capability 使整个 Plan 激活失败。

Matcher 串行、确定性地调用实际达到的节点。每次逻辑调用计入 calls/input bytes；cache miss 在调用前按
descriptor deadline 预留总时间并使用异步 timeout。缓存只存在一次分析内，并绑定实现版本、规范输入与
Event/Rule 上下文。

失败映射：

- 超过 descriptor 或 MatchPlan 预算：`resource_exhausted`；
- Detector deadline：`detector_timeout`；
- Predicate deadline、实现异常、非法返回或 evidence 违约：`capability_error`。

错误只公开稳定类别、Rule ID 和 capability 名，不包含输入或异常原文。Rule 中 capability 失败会丢弃该
Rule 已暂存 Finding。

## 3. Evidence

Predicate 只能投影 condition ID、capability、可选结构位置和 Policy 静态 mask。Detector evidence 只接受
descriptor 校验后的 type、capability、span/location、`masked_evidence`、fingerprint、confidence 和实现
version。

原始输入及 Detector path 不进入 Finding。text span 可映射回原字段；canonical JSON span 只属于编码后
文本，不能冒充原始 JSON 字段位置。同一 Detector 条件最多投影 64 条 evidence，超过时显式资源失败。

## 4. 默认 Predicate

| 名称 | 参数 | 语义 | 单次输入上限 |
| --- | --- | --- | ---: |
| `number_in_range` | `value, minimum, maximum` | 有限 JSON 数值处于闭区间 | 512 B |
| `length_in_range` | `value, minimum, maximum` | 字符、数组元素或对象键数量处于闭区间 | 16 KiB |
| `url_host_allowed` | `url, allowed_hosts` | HTTP(S) 规范化 host 命中 allowlist | 8 KiB |

Range Predicate 拒绝布尔值、非有限浮点、负长度边界和 `minimum > maximum`。不适用的 Event 值返回 false；
非法策略边界进入 `capability_error`。

URL allowlist 支持精确 host 和 `*.example.test` 子域形式；wildcard 不匹配 apex。它拒绝 userinfo、控制字符、
非法端口/host 和非 HTTP(S) scheme。它不做 DNS、私网、rebind、重定向、路径或响应来源检查，因此不能
单独宣称完成 SSRF 防护。

## 5. 默认 Detector

| 名称 | detection type 摘要 | 编码 | 输入上限 |
| --- | --- | --- | ---: |
| `secrets` | private key、GitHub/OpenAI/Bearer/assigned secret | canonical JSON | 16 KiB |
| `pii` | email、北美电话、US SSN、卡号、中国身份证/手机号 | canonical JSON | 16 KiB |
| `prompt_injection` | instruction/system prompt/role/control token | text、canonical JSON | 16 KiB |
| `dangerous_command` | 文件/磁盘破坏、下载执行、反向 shell、混淆执行 | text、canonical JSON | 16 KiB |
| `unicode_security` | bidi、zero-width、format/control、有限混合脚本混淆 | text、canonical JSON | 16 KiB |

固定模式 Detector 是启发式事实，会有漏报和误报。Rule 应结合 Event kind、phase、origin、Tool 和显式
Relation；必要时用 `types_any` 限定类型。

`unicode_security` 按原始 code point 分类，普通换行、回车和 tab 不命中。混合脚本只在同一字母数字 token
同时包含 Latin 与审查过的 Greek/Cyrillic ASCII lookalike 时命中，不把普通中文或单一脚本文本标成攻击。

所有 Detector 返回 span、类型、置信度、上下文绑定 fingerprint 和遮罩，不返回命中原文。

## 6. 可选模型 Prompt Injection

`create_model_detector_registry(classifier, threshold=...)` 在默认目录外发布 `prompt_injection_model`，公开
`model_prompt_injection/model_jailbreak`，输入 16 KiB、deadline 2 秒、最多一个结果。

部署代码固定 classifier、模型 identity/version、阈值和 label mapping。内置
`TransformersPipelineClassifier` 只包装已经加载的 pipeline，不 import Transformers、不下载模型，也不把
模型输出文本写入 Detection。同步推理在线程中执行；Matcher timeout 可以停止等待，但不能强制终止底层
线程，所以需要强隔离时应由部署层提供可取消进程/服务 backend。

当前只验证 adapter 与执行合同，没有捆绑或评测真实 checkpoint，因此状态是 `adapter_only`。

## 7. 示例与状态

- `examples/policies/prompt-injection.yaml`
- `examples/policies/dangerous-command.yaml`
- `examples/policies/url-host-allowlist.yaml`
- `examples/policies/parameter-constraints.yaml`

capability 名称是 Policy 合同，修改检测语义必须提升实现 version 并补正常、攻击、边界、失败、预算、脱敏
和 Enforcement 测试。准确交付状态只在[状态矩阵](../capability-status.yaml)维护，未来顺序只在
[roadmap](../roadmap.md)维护。
