# 多 Agent 协作开发体系

这套体系以“风险证据”决定协作强度，默认减少角色交接、任务文档和重复验证。它适用于普通单体项目、前后端项目和 monorepo，也保留高风险与完整审计能力。

## 默认工作方式

新任务使用 `.agents/workflows/evidence-driven-development.yaml`：

```text
Triage -> Execute -> Verify -> Close
```

Discovery、Product、Planner、Architect、QA、Reviewer 和 Integrator 是按需能力，不是每个任务都必须经过的固定流水线。

## 规则分层

- `AGENTS.md`：跨角色边界和硬门禁。
- `.agents/config.yaml`：模式、门禁和记录字段的机器配置。
- `.agents/workflows/evidence-driven-development.yaml`：状态转换与能力触发。
- `.agents/ownership.yaml`：路径 owner 候选和默认实现角色；任务 `scope` 才是最终授权。
- `.agents/agents/*.md`：单个角色的允许动作、禁止动作和交接方式。
- `.agents/project-context.md`：项目稳定事实，不保存流程规则。

主 Agent 是 `task.md` 的唯一整合者。并行 Agent 返回结构化结果，或写入已授权的独立交接文件，不同时修改 `task.md`。

## 五种任务模式

- `ask`：问答和只读分析，不创建任务目录。
- `quick`：单 owner、局部可逆、低风险修改，不创建任务目录，结果在最终回复留痕。
- `standard`：普通开发任务，默认只维护 `tasks/{task_id}/task.md`。
- `high_risk`：数据、安全、公共兼容、跨服务一致性或生产回滚等高风险任务，要求独立 Review、针对性测试和回滚方案，但文档仍按需创建。
- `audit`：用户或外部治理明确要求完整审计时，才使用完整阶段文档和角色链。

跨 owner 或前后端同时修改不再自动等于高风险；如果契约稳定、边界清楚且验证路径明确，使用 `standard` 即可。

## 文档策略

`standard` 和 `high_risk` 的单一事实源是：

```text
tasks/{task_id}/task.md
```

其中按需记录模式、范围、决策、变更、验证、findings 和实际分派。不适用的小节直接省略。

以下文件仅在确有独立价值时创建：

- `prd.md`：复杂产品规则或多个用户场景。
- `architecture.md`：契约、数据、安全、跨服务或重大设计决策。
- `test-report.md`：大型测试矩阵或独立 QA 证据。
- `review.md`：独立审查或可执行 findings。
- 前后端实现记录：实现线真正并行并需要独立交接。
- ADR：长期、跨任务且难回退的架构决策。

旧的 `.agents/workflows/feature-development.yaml` 只保留迁移入口。恢复历史任务时保留旧记录只读，使用当前规则重新 Triage 后切换到新状态机。

## 子 Agent 策略

只在以下情况下分派：

- 独立工作单元能真正并行。
- `standard` 及以上业务代码已指定专用实现角色。
- ownership 需要隔离实现者。
- 高风险任务需要独立 Reviewer 或 QA。
- 用户明确要求多 Agent、并行或审计流程。

不要为了对应角色列表依次启动多个 Agent。分派受运行时策略限制时必须如实记录，不得假装已启动。

## 修复和验证

- 先跑目标测试，再跑受影响模块检查。
- 只有共享契约、构建或环境联动变化时才跑全量集成。
- 修复实现细节后只重跑受影响检查。
- 只有风险面发生变化才回到 Architect 并重新执行相关 Review / Integration。
- 同一根因连续两轮未解决时停止机械循环，重新诊断或请求人工决策。

## 目录

```text
.
├── AGENTS.md
├── .agents/
│   ├── config.yaml
│   ├── ownership.yaml
│   ├── project-context.md
│   ├── agents/
│   └── workflows/
│       ├── evidence-driven-development.yaml
│       └── feature-development.yaml  # legacy
├── tasks/
└── docs/adr/
```

完整规则见 `AGENTS.md`，机器配置见 `.agents/config.yaml`。
