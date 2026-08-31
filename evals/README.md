# 检测组件特性评估

本目录记录第三方检测组件在锁定语料上的分类特性。代码和配置中使用 `Detector` 表示检测组件。

| 入口 | 评估对象 | 输出 |
| --- | --- | --- |
| [prompt_injection/](prompt_injection/) | 指定的提示注入检测组件与锁定的攻击载荷、良性难例 | 召回率、误报率、ROC AUC、可用阈值与分组结果 |

仓库单元测试与集成测试验证规则加载与匹配、允许/记录/阻断结果、调用检查点、输出释放、故障处理和受保护
操作。具体规则集的效果由对应应用工作负载评估。真实 Agent 对照评测的准入条件是未启用规则时存在成功
攻击样本。

## 共享库

`evals/lib/` 提供：

- `reporting.py`：不可变 run 目录、append-only index 和 latest 指针；
- `metrics.py`：Detector 分类指标；
- `detectability.py`：按内容可检测性划分第三方语料。

一次运行写入：

```text
data/benchmarks/<eval>/results/
  <UTC时间戳>-<eval>/report.json
  index.jsonl
  latest.json
```

结果目录位于 Git 跟踪范围外；每次运行创建独立 run 目录。
