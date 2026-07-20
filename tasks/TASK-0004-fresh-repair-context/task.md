# 返工轮次使用全新 Agent 上下文

## mode

- `standard`：需要同步人类规则、机器配置、状态转换、角色契约和使用说明。
- 只涉及 `docs` owner 的协调性文件，不涉及业务代码、公共 API、数据、安全或部署。

## scope

- 目标：Review、QA 或集成验证发现 P1 或未接受的 P2 后，返工必须在新的 Agent 实例或同角色的新独立对话中执行，不续写原实现或上一轮返工对话。
- 允许修改：`AGENTS.md`、`.agents/config.yaml`、`.agents/workflows/evidence-driven-development.yaml`、`.agents/agents/frontend-implementer.md`、`.agents/agents/backend-implementer.md`、`.agents/agents/reviewer.md`、`README.md` 和本任务记录。
- 验收：workflow 明确新建返工上下文的转换门禁；机器配置可表达返工轮次和最小交接输入；前后端角色可接收结构化返工包；同 owner 可合并 findings、不同 owner 可安全并行；YAML、引用、UTF-8 和 diff 检查通过。

## decisions

- 新鲜度约束针对“执行上下文”而不是角色名称：允许继续使用 Frontend/Backend Implementer 角色，但不得续写原实现对话或上一轮返工对话。
- 每次 Verify 返回 Fix 都创建新的返工轮次；主 Agent 只传任务记录路径、finding 证据、授权路径、适用决策/契约和失效验证，不回放完整历史对话。

## changes

- `AGENTS.md` 的 Fix 状态改为强制全新执行上下文，并定义按 owner 聚合、跨 owner 并行、轮次结束和运行时阻塞规则。
- 机器配置新增 `orchestration.repair_rounds`，workflow 的 `verify_to_fix` 增加按 owner 建立新上下文和准备结构化交接的门禁。
- 前后端 Implementer 接收结构化返工包并在轮次交接后退出；Reviewer 输出可被新上下文直接消费的稳定 finding 信息。
- README 增加返工轮次的使用说明。

## verification

- PyYAML 解析通过：4 个 YAML 文件均可解析；config/schema/workflow 版本、默认 workflow、返工上下文禁用项、结构化交接字段和 Verify→Fix 门禁的语义断言通过。
- 引用检查通过：workflow capability 和 ownership 默认实现角色均可解析到 9 个现有角色契约或允许的保留值。
- 跨文件规则检查通过：协议、config、workflow、前后端 Implementer、Reviewer 和 README 的 7 个关键约束均存在。
- UTF-8 严格解码通过：8 个变更文件无 BOM 或无效字符。
- `git diff --check` 通过；LF/CRLF 提示来自仓库行尾设置，不是空白错误。
- 仓库没有业务构建或运行命令，本次仅修改协作协议，因此未执行业务测试。

## findings

- 未发现 P1/P2。

## residual_risks

- 本仓库提供协议和机器可读门禁，不包含独立的编排执行引擎；宿主运行时必须读取并遵守这些规则。运行时无法创建全新返工上下文时，策略要求任务进入 `blocked`。
