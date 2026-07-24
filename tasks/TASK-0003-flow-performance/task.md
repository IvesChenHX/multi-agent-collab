# 流程性能与角色边界优化

## mode

- `standard`：同时调整顶层协议、机器配置、ownership、九个角色契约、工作流和说明文档，需要交叉一致性验证。
- 只涉及 `docs` owner 的协调性文件，不涉及业务代码、API、数据、安全或部署。

## scope

- 目标：减少固定阶段、重复文档和重复验证，同时保持角色边界、ownership、P1/P2、高风险独立审查和真实验证门禁。
- 允许修改：`AGENTS.md`、`.agents/config.yaml`、`.agents/ownership.yaml`、`.agents/project-context.md`、`.agents/workflows/*.yaml`、`.agents/agents/*.md`、`README.md` 和本任务记录。
- 验收：每类规则只有一个权威来源；角色具有明确的负责/禁止/交接边界；活动配置不引用旧文档链；状态和关闭门禁一致；UTF-8 与结构检查通过。

## decisions

- `AGENTS.md` 管跨角色边界，config 管机器模式和门禁，workflow 管状态转换，ownership 管路径映射，角色文件只管单角色契约。
- 主 Agent 是 `task.md` 唯一整合者；并行 Agent 返回结构化结果或写授权的独立交接文件。
- `quick` 和协调性文件允许主 Agent直接执行；`standard` 及以上业务代码若已指定实现角色，必须分派，运行时不支持时需用户明确授权。
- legacy workflow 只保留迁移入口，不继续维护旧式固定文档链。

## changes

- 顶层协议新增权威来源表和九类跨角色边界矩阵。
- 九个角色统一为“职责、输入、输出、允许、禁止、交接”契约，移除重复触发条件和直接回写 `task.md`。
- config 增加 authority、关闭状态、任务记录 steward 和并发写限制，并统一高风险 required gates。
- ownership 改用 `task.md#scope` 作为最终授权，补充执行角色、冲突处理和 shared owner。
- 新 workflow 使用 `triage/executing/verifying/fixing/complete/blocked/accepted_risk` 状态，显式描述修复、重验和关闭转换。
- legacy workflow 压缩为只读历史迁移入口；project context 只保留项目事实。
- README 同步规则分层、记录整合和分派策略。

## verification

- YAML 无依赖结构检查通过：4 个 YAML 文件无 BOM、Tab、替换字符或奇数缩进。
- 引用检查通过：默认 workflow 为 `evidence-driven-development`，所有 workflow agent 和 ownership 实现角色均可解析到角色文件或保留值。
- 九个角色契约均包含职责、输入、允许、禁止和交接，结构检查通过。
- 活动规则残留检查通过：未发现 `light`、`plan.md`、`risk_based`、旧式默认子 Agent 或直接回写 `task.md`。
- UTF-8 可读检查通过：协议与 `.agents` 共 16 个文件无替换字符。
- `git diff --check` 通过；LF/CRLF 提示来自仓库行尾设置，不是空白错误。
- 环境未提供标准 YAML 解析器，因此 YAML 验证为结构和引用检查，未执行第三方 schema 解析。

## findings

- 未发现 P1/P2。
- legacy 历史任务保留原阶段文档只读，恢复时必须重新 Triage，避免旧规则进入新任务。
- 标准 YAML 解析器缺失属于验证工具限制；当前 YAML 仅使用简单映射和列表，结构检查未发现异常。

## delegation

- 未启动子 Agent：用户要求继续优化协议，且本任务全部属于同一 `docs` owner 的协调性文件，可由主 Agent直接修改。
