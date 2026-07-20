# 验收标准

- `AGENTS.md` 明确新增 token 优化方向，包括任务分级、上下文复用、短格式阶段输出和日志摘要规则。
- `.agents/config.yaml` 将默认编排策略表达为按风险自动选择，而不是无条件全量子 Agent 流程。
- `.agents/workflows/feature-development.yaml` 支持问答、轻量、标准和高风险任务模式，并定义各模式需要的记录。
- 角色规则至少覆盖 Planner、Discovery、QA、Reviewer 的低 token 行为要求。
- 本次任务记录写明 `delegation_status`，不得声称实际启动了子 Agent。
- 所有新增或修改的中文正文保持 UTF-8 可读字符，不写成 `\uXXXX`。
- 不修改业务代码，不删除用户已有改动。
