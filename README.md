# 多 Agent 协作开发体系

这是一套可放入任意项目的多 Agent 协作开发体系，适合新项目，也适合已经开发到一半、目录结构不标准的项目。

它结合了两类方案的优点：

- 当前项目式规则：强路径边界、P1/P2/P3 质量门禁、自动修复循环、主 Agent 集成验证。
- 团队协作机制：任务文档、ADR、角色定义、状态流转、测试报告和审查报告留痕。

## 推荐使用方式

1. 将本目录内容复制到目标项目根目录。
2. 让发现 Agent（Discovery）先扫描项目，生成 `tasks/{task_id}/discovery.md`，并根据真实项目结构更新 `.agents/ownership.yaml`。
3. 让产品 Agent（Product）生成 `tasks/{task_id}/prd.md`，明确产品范围、业务规则和验收口径。
4. 按 `AGENTS.md` 和 `.agents/workflows/feature-development.yaml` 执行任务；进入执行流程后默认开启子 Agent，由 Planner 将实现工作分流到前端、后端或显式指定的其它角色。

## 目录结构

```text
.
├── AGENTS.md
├── .agents/
│   ├── config.yaml
│   ├── ownership.yaml
│   ├── agents/
│   │   ├── discovery.md
│   │   ├── product.md
│   │   ├── planner.md
│   │   ├── architect.md
│   │   ├── frontend-implementer.md
│   │   ├── backend-implementer.md
│   │   ├── qa.md
│   │   ├── reviewer.md
│   │   └── integrator.md
│   └── workflows/
│       └── feature-development.yaml
├── tasks/
│   └── TASK-0001-example/
│       ├── brief.md
│       ├── acceptance.md
│       ├── discovery.md
│       ├── prd.md
│       ├── plan.md
│       ├── architecture.md
│       ├── implementation.md
│       ├── frontend-implementation.md
│       ├── backend-implementation.md
│       ├── test-report.md
│       └── review.md
└── docs/
    └── adr/
        └── README.md
```

## 核心原则

- 先发现项目事实，再分配角色和目录边界。
- 先定义产品需求，再拆解工程任务；PRD 说明做什么和怎么验收，ADR 说明技术方案为什么这样选。
- Product 负责 PRD，Planner 负责拆任务，Architect 负责技术方案和 ADR，三者不能互相替代。
- 固定流程，不固定目录名。
- 进入执行流程后默认开启子 Agent；主 Agent 负责显式说明分派的角色、边界、允许修改路径、输入文档和预期输出。
- 子 Agent 只能修改任务授权范围内的文件。
- 每个任务必须在 `plan.md` 里写清楚允许修改路径、禁止越界路径和对应 owner。
- 实现阶段按 ownership 分为前端实现线、后端实现线或 Planner 显式指定的其它实现线。
- 前后端同时变更时，先由 Architect 固定接口契约，再允许并行实现。
- Reviewer 只审查和反馈，不直接修业务代码。
- 未授权跨 owner 修改业务代码按 P1 处理，必须回退给正确 owner 修复。
- Integrator 负责跨模块启动、联调、构建、测试和环境问题判断。
- 所有关键过程必须落到 `tasks/{task_id}`，方便恢复上下文和追责。

## 什么时候需要人工介入

- 同一个 P1 问题连续 3 轮没有解决。
- 目录归属不清，且修改会跨越多个模块边界。
- 集成验证依赖外部账号、生产数据、私有网络或人工审批。
- 任务目标和验收标准互相冲突。
