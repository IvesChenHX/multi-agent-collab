# 统一任务归档

## mode

- `standard`：需要同步顶层协议、机器配置、状态机、项目基线、使用说明和现有任务记录。
- 只涉及 `docs` owner 的协调性文件，不涉及业务代码、公共 API、数据、安全或部署。

## scope

- 目标：为 `standard` 及以上任务建立项目级统一台账，使任务在创建时登记、执行中更新状态、进入终态时统一归档。
- owner：`docs`；执行者：主 Agent。
- 允许修改：`.gitignore`、`AGENTS.md`、`.agents/config.yaml`、`.agents/workflows/evidence-driven-development.yaml`、`.agents/project-context.md`、`README.md`、`tasks/index.yaml` 和本任务记录。
- 验收：任务台账具有唯一权威来源；现有任务均可定位；终态归档不移动任务目录；Close 门禁要求同步台账；YAML、引用、UTF-8 和 diff 检查通过。

## decisions

- 使用 `tasks/index.yaml` 保存项目级任务实例状态；单任务的范围、决策和证据仍由各自 `task.md` 保存。
- 归档采用“台账终态标记”，不移动任务目录，避免任务链接和结构化交接路径失效。

## changes

- 新增 `tasks/index.yaml`，集中登记现有任务、本任务状态、结果摘要和归档时间，并以 `next_task_number` 统一分配后续编号。
- `AGENTS.md` 增加 Triage 登记、状态同步和 Close 归档硬门禁，明确归档不移动任务目录。
- `.agents/config.yaml` 定义台账字段、编号、类型和归档策略；workflow 定义初始登记、状态持久化和终态触发，避免重复定义状态机。
- `.gitignore` 只放行统一台账，详细任务目录继续作为本地证据，保证归档可版本化且不依赖本地目录。
- 项目基线和 README 增加统一入口与目录说明。

## verification

- PyYAML 解析通过：`.agents` 下 4 个 YAML 和 `tasks/index.yaml` 均可解析，config 与 workflow 版本和引用一致。
- 台账约束检查通过：5 条记录的字段完整、编号唯一且 `next_task_number` 连续；任务状态来自 workflow，终态均有 `archived_at`，活动状态不得提前归档。
- 自包含归档检查通过：每条记录均有非空摘要，不依赖被 `.gitignore` 忽略的本地任务目录。
- 忽略规则检查通过：`git status --short --untracked-files=all` 可发现 `tasks/index.yaml`，详细任务记录仍命中 `tasks/*`。
- UTF-8 严格解码和无 BOM 检查通过；未发现替换字符或新增的 Unicode 转义文本。
- `git diff --check` 通过；LF/CRLF 提示来自仓库行尾设置，不是空白错误。

## findings

- 未发现 P1/P2。
