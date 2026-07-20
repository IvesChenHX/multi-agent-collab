# 计划

## 状态

ready

## delegation_status

- 状态：`blocked_by_runtime_policy`
- 原因：当前运行时多 Agent 工具规则要求只有用户明确要求 sub-agent、delegation 或 parallel agent work 时才允许 spawn。本次用户要求优化流程规范，但未明确要求启动子 Agent。
- 降级方式：主 Agent 按 Discovery、Product、Planner、Architect、QA、Reviewer、Integrator 阶段化记录执行，不声称实际子 Agent 已启动。

## 任务模式

标准文档维护任务。命中单一 `docs` owner，不涉及业务代码、API 契约、数据库、权限、构建或部署。

## 实现线

- Frontend Implementer：不适用；无前端实现变更。
- Backend Implementer：不适用；无后端实现变更。
- 其它执行角色：主 Agent 以阶段化角色执行方式修改协作规范、工作流配置和任务记录。

## 允许修改路径

- `AGENTS.md`
- `.agents/config.yaml`
- `.agents/workflows/feature-development.yaml`
- `.agents/project-context.md`
- `.agents/agents/*.md`
- `tasks/TASK-0002-token-optimization/**`

## 禁止越界路径

- 业务代码路径
- 前端、后端、数据和基础设施实现路径
- 与 token 优化无关的文档或配置

## 步骤

- [x] Discovery：确认现有流程配置、所有权和运行时限制。
- [x] Product：确认本任务为协作规范维护，PRD 不适用但保留验收口径。
- [x] Planner：定义 docs owner 范围、允许修改路径和降级执行方式。
- [x] Architect：设计任务分级、上下文复用、短记录和验证摘要规则。
- [x] Implementation：修改规范、配置和角色规则。
- [x] QA：检查验收标准、UTF-8 可读中文和 diff 范围。
- [x] Reviewer：检查降级状态真实性、越界风险和 token 优化覆盖。
- [x] Integrator：执行最终仓库状态和配置一致性检查。

## 风险

- 过度轻量化可能削弱高风险任务质量门禁。
- 配置和人读规范若不一致，后续执行者可能选择错误任务模式。

## 风险控制

- 低风险任务降低记录量，高风险任务保留完整流程。
- 机器配置和 `AGENTS.md` 同步修改。
- Reviewer 必须检查任务模式选择是否被滥用。
