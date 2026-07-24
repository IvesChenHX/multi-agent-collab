# 发现记录

## 输入

- 用户要求：根据已讨论的 token 优化方案调整流程体系。
- 仓库文件：`AGENTS.md`、`.agents/config.yaml`、`.agents/workflows/feature-development.yaml`、`.agents/agents/*.md`。
- 所有权配置：`.agents/ownership.yaml`。

## 项目事实

- 当前仓库是多 Agent 协作规范仓库，不包含已识别的业务前端或后端实现。
- `.agents/ownership.yaml` 中 `docs` owner 覆盖 `README.md`、`AGENTS.md`、`docs/**`、`tasks/**` 和 `.agents/**`。
- 当前默认策略在 `AGENTS.md`、`.agents/config.yaml` 和 `.agents/workflows/feature-development.yaml` 中均偏向进入完整多 Agent 流程。
- 当前运行时提供了多 Agent 工具，但工具规则要求只有用户明确要求 sub-agent、delegation 或 parallel agent work 时才允许 spawn。

## 本次影响范围

命中 owner：`docs`。

允许修改：

- `AGENTS.md`
- `.agents/config.yaml`
- `.agents/workflows/feature-development.yaml`
- `.agents/agents/discovery.md`
- `.agents/agents/planner.md`
- `.agents/agents/qa.md`
- `.agents/agents/reviewer.md`
- `tasks/TASK-0002-token-optimization/**`

禁止修改：

- 业务代码路径
- 未授权的前端、后端、数据和基础设施实现路径

## 结论

本任务是协作规范和工作流配置优化，不涉及业务功能。可由主 Agent 在降级执行下直接修改 docs owner 文件，并保留阶段记录。
