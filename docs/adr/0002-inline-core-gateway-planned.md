# ADR-0002：Inline Core，同时规划 Gateway

- 状态：Accepted
- 日期：2026-08-04

## 背景

只实现 Core 无法验证真实 Enforcement；直接实现独立 Gateway + 远程 Core 又会过早引入
服务发现、认证、网络失败和部署复杂度。

## 决策

- Core 与 Gateway 从接口设计第一天同时考虑。
- MVP 中 Core 以内嵌库方式运行在 Inline Adapter 和 Gateway 进程内。
- 先实现模拟 Agent 与 GuardedToolExecutor，再实现 OpenAI 非流式 Gateway。
- 提供稳定 `/v1/evaluate` 模型，为未来远程 Core 保留边界。
- 单容器是默认部署拓扑。
- 多实例或多语言需求出现前不拆分 Core 服务。

## 结果

优点：

- 可尽早验证 Agent 与 Gateway 两条接入路径。
- 本地部署简单。
- Core 判断无额外网络延迟。
- 未来仍有拆分路径。

代价：

- 每个 Gateway 实例各自加载 Policy/Detector。
- 重型 Detector 暂时与 Gateway 共享资源。
- Policy 热更新需要实例协调，留待后续。
