# 架构方案

## 输入

- `brief.md`
- `acceptance.md`
- `discovery.md`
- `plan.md`

## 设计目标

减少低风险任务的 token 消耗，同时不削弱跨 owner、跨前后端、权限、数据库、公共契约和部署类任务的质量门禁。

## 方案

### 任务分级

新增四类任务模式：

- `ask`：纯问答、解释或只读分析，不创建任务目录。
- `light`：单 owner、低风险、验收清楚的任务，使用单文件轻量记录。
- `standard`：一般执行任务，使用必要阶段文档，但各阶段只写新增结论。
- `high_risk`：跨 owner 或高风险任务，使用完整多 Agent 流程和完整阶段门禁。

### 上下文复用

引入 `.agents/project-context.md` 作为项目基线候选文件。Discovery 首次或结构变化时维护基线；普通任务只记录本次增量发现和影响范围。

### 短格式阶段输出

阶段文档统一限制为“输入、阶段结论、授权边界、输出给下一阶段、阻塞项”。禁止复制上一阶段完整正文。

### 日志和审查摘要

测试和集成记录只保留命令、结果、关键错误摘要和完整日志位置。Reviewer 只列 findings、验收覆盖和残余风险，不复述实现过程。

### 子 Agent 策略

默认按风险启用子 Agent。运行时要求用户显式授权时，必须降级执行并记录 `delegation_status`。低风险 docs owner 任务允许主 Agent 直接修改协调性文件。

## 回滚方案

如新策略导致执行标准不清，可回退本次对 `AGENTS.md`、`.agents/config.yaml` 和 `.agents/workflows/feature-development.yaml` 的修改，恢复原全量流程优先策略。
