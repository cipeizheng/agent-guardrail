# MatchMonitor 增量执行合同

> 状态：基于 MatchPlan v1 的 whole-pending 分析与有界增量 Finding 去重已实现；独立作者 YAML 已能
> 生成 MatchPlan。生产 Runtime/Gateway 使用无状态 pending Matcher 与 Decision 映射；MatchMonitor
> 仍是可选的进程内 committed identity 去重 SDK。Monitor 可复用已编译的可信 capability。

## 1. 两个低层入口

`core/monitor.py` 提供 `MatchMonitor`，复用相同的 `SnapshotMatcher`：

```python
monitor = MatchMonitor(plan, policy_version=3, policy_hash="...")

new_report = await monitor.analyze(committed_trace)
pending_report = await monitor.analyze_pending(pending_trace)
```

两个入口都返回 `AnalysisReport(emission=new)`，但状态提交语义不同：

| 入口 | 可见 Event | Finding 过滤 | 是否推进已见状态 |
| --- | --- | --- | --- |
| `analyze(Trace)` | 完整 committed snapshot | 去掉相同 trace 已见 identity | 整次分析无错误且状态预算允许时原子推进 |
| `analyze_pending(PendingTrace)` | committed past + 整个 pending batch | subject 必须包含 pending Event，再去掉 committed 已见 identity | 不推进；pending 仍是 tentative |

状态 key 固定为 `(trace_id, finding.id)`，不依赖 Python 对象地址。深拷贝后的相同 snapshot 不会重复
返回；append 新 Event 后只返回新 identity。不同 Trace 即使 Event/Finding ID 形状相同也互不污染。

## 2. whole-pending 与 domain

`SnapshotMatcher.analyze_pending` 先深拷贝 committed 与 pending Event，再建立一个带显式分区的不可变
snapshot：

- `visible` binding：past + pending；
- `past` binding：只枚举 committed Trace；
- `pending` binding：只枚举当前完整 batch。

所有 pending Event 在同一次命名笛卡尔积、derive、collection、条件与量词执行中可见。Rule 的
supporting binding 可以来自 past，但 `FindingTemplate.subjects`
至少一个最终 Event 必须属于 pending batch；past-only match 在 Finding/evidence 投影和对应输出预算之前
被过滤。

## 3. tentative pending 为什么不立即去重

Invariant 的 IncrementalPolicy 会在一次 `analyze_pending` 返回后立即记住错误。本项目不能复制这一点：
被 `block` 的 pending 原始 Event 不会提交到 Trace。如果第一次分析立即把 Finding 标为已见，同一工具
调用或模型输出重试时可能被去重成空 Report，继而被错误放行。

因此当前合同是：

```text
analyze_pending → tentative new Finding → 不写 dedupe state
       │
       ├─ block / error → 相同 pending 重试仍再次命中
       └─ 外层真正提交 Event → 后续 committed analyze 才可确认 identity
```

未来 Gateway 适配不能把“去重后没有新 Finding”解释成“该 pending batch 安全”。Enforcement 接入必须
基于本次完整 pending 分析结果和失败动作；在引入显式 commit/ack 协议前，不得让 tentative 结果推进
Monitor 状态。

## 4. 状态与失败原子性

默认每个 MatchMonitor 最多保存 100,000 个 Finding identity，构造参数最多可提高到实现硬上限
1,000,000。达到上限时返回脱敏 `resource_exhausted`，不返回部分 new Finding，也不改变已见集合；不做
LRU 驱逐，因为静默遗忘会使旧 Finding 不可预测地重新出现。

`analyze(Trace)` 只有在 Matcher Report 没有任何 error 时才原子加入本次所有 new key。参数错误、
capability 缺失、Rule/全局预算错误或内部错误都不会推进状态；重试仍能看到相同 Finding 和 error。
`reset()` 可以清空全部状态，`reset(trace_id)` 只清理一个 Trace。当前状态仅在进程内存中，不持久化、
不跨进程共享，也不是跨请求 Session Store。

## 5. 当前边界

- 这是低层 MatchPlan API；作者 YAML 只生成 Plan，不负责 Monitor 生命周期；
- 没有 handler、callback、Tool/LLM 执行或 I/O；
- capability 只能来自部署方显式编译的 `CompiledMatchPlan`，不能由 Monitor/YAML 动态加载；
- 生产 Finding → Decision 适配不使用 Monitor dedupe 状态；
- 没有持久状态、并发分布式协调或跨进程一致性。
