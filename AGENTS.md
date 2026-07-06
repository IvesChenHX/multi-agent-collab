# 多 Agent 协作开发规范

## 0. 运行时优先级和降级执行

本规范定义项目内的协作流程，但不能覆盖运行环境、平台策略或工具安全规则。若当前运行环境未提供子 Agent 工具，或工具规则要求“只有用户明确要求 subagent / 多 Agent 时才能 spawn”，主 Agent 不得违反工具规则，也不得声称已经启动实际子 Agent。

出现上述限制时，主 Agent 必须进入降级执行：

- 在回复和 `tasks/{task_id}/plan.md` 中记录 `delegation_status`，说明子 Agent 未实际启动的原因。
- 仍按工作流阶段顺序产出任务文档；可由主 Agent 以“阶段化角色执行”的方式依次完成 Discovery、Product、Planner、Architect、QA、Reviewer 和 Integrator 的记录，但必须保留每个阶段的输入、输出、边界和结论。
- 降级执行不是轻量流程，不能以“无法启动子 Agent”为理由跳过 `prd.md`、`plan.md`、`architecture.md`、`test-report.md` 或 `review.md`。
- 对本应由 Frontend Implementer、Backend Implementer 或其它实现 Agent 修改的业务代码，若没有用户明确授权主 Agent 代执行，主 Agent 必须停在计划或架构阶段并请求确认。
- 对任务文档、协作规范、工作流配置、ownership 配置和集成记录等协调性文件，主 Agent 可在计划授权范围内直接修改。
- Reviewer 必须检查 `delegation_status` 是否真实，不得把“阶段化角色执行”误写成“实际子 Agent 已执行”。

## 1. 适用范围

本规范适用于任意软件项目，包括但不限于前端、后端、全栈、移动端、数据工程、脚本工具、单体仓库和 monorepo。

不要假设项目一定存在 `/frontend`、`/backend`、`src`、`server` 等固定目录。所有目录边界必须通过 Discovery 阶段识别，并记录到 `.agents/ownership.yaml`。

## 2. 标准角色

- Discovery：扫描项目结构、技术栈、命令、目录边界和已有规范。
- Product：定义产品需求、用户场景、业务规则、范围边界和验收口径。
- Planner：澄清需求、拆解任务、定义交付物和验收路径。
- Architect：设计模块边界、接口契约、数据流、风险和回滚思路。
- Frontend Implementer：负责前端、客户端 UI、浏览器侧状态、样式、路由、API 调用和前端测试。
- Backend Implementer：负责服务端 API、业务服务、权限、任务调度、服务端数据访问、迁移和后端测试。
- QA：执行验收标准、补充边界测试、记录测试结果和复现路径。
- Reviewer：代码审查，优先发现 bug、回归、安全、性能和测试缺口。
- Integrator：执行跨模块集成验证，包括启动、构建、联调、配置和核心流程。

所有角色都必须以当前阶段的输入文档和 `.agents/ownership.yaml` 作为授权上限；进入计划后的执行、验证和集成阶段还必须以 `tasks/{task_id}/plan.md` 作为授权上限。未被授权的文件、模块、职责和流程阶段不得擅自修改或代替其它 Agent 完成。

## 3. 主 Agent 职责

主 Agent 负责协调流程、分配子 Agent、维护任务文档、处理前后端实现分流、跨模块配置和执行最终集成验证。

默认执行策略：

- 除非用户明确要求不启用子 Agent、只做问答、只做只读分析或任务明确不需要执行流程，主 Agent 进入任务执行时默认开启并分派匹配阶段的子 Agent。
- 默认开启子 Agent 不需要再次请求用户确认，但主 Agent 必须在执行前显式说明已开启的子 Agent、任务边界、允许修改路径、输入文档和预期输出。
- 如果运行时工具策略不允许自动启动子 Agent，必须按第 0 节降级执行，并把未启动原因写入任务文档。
- 子 Agent 的执行顺序必须遵守当前工作流；需要并行执行时，必须先满足架构契约、owner 和允许修改路径已经稳定的前置条件。
- 对极小型、无文件修改、无验证流程的任务，主 Agent 可以直接处理；直接处理时必须简要说明未开启子 Agent 的原因。

主 Agent 不应直接修改已归属给某个子 Agent 的业务代码，除非：

- 该文件未被 `.agents/ownership.yaml` 归属。
- 修改属于跨模块配置、任务文档、工作流配置或集成脚本。
- 子 Agent 连续修复失败，且用户明确授权主 Agent 介入。

## 4. 动态所有权

每个任务开始前必须确认 `.agents/ownership.yaml` 是否覆盖本次影响范围。

确认影响范围后，默认进入子 Agent 分派；Planner 必须把命中的 owner 和流程阶段映射到对应子 Agent，主 Agent 只负责协调、记录和集成。

如果项目结构未知，流程必须先进入 Discovery：

```text
Discovery -> Product -> Planner -> Architect -> [Frontend Implementer / Backend Implementer] -> QA -> Reviewer -> Integrator
```

如果项目结构已知且任务很小，可以复用最近一次 Discovery 结果，但必须确认影响范围没有变化。

### 4.1 轻量任务判定

只有同时满足以下条件，任务才可以按轻量流程处理：

- 只命中单一 owner。
- 不修改 API 契约、数据库、SQL、权限、安全、调度、部署、构建、公共模块或跨端共享模型。
- 不同时影响前端和后端实现线。
- 不需要新增迁移、数据修复、跨服务联调或第三方集成。
- 验收方式清楚，且可通过一次本地检查、单元测试、构建或人工验证完成。

只要出现以下任一情况，就不得再视为“极小型修补”，必须回到 Planner / Architect 明确边界和方案：

- 前端筛选、展示、路由或 API 调用扩展到了后端 API、权限、SQL 或数据访问层。
- 修改同时命中 web、backend、data、infra 或未归属路径中的两个及以上 owner。
- 需要变更公共契约、字段语义、错误码、鉴权、兼容性或回滚方案。
- `.agents/ownership.yaml` 对影响范围覆盖不足或存在多 owner 冲突。

### 4.2 产品需求

Product 必须在 Planner 拆任务前产出 `tasks/{task_id}/prd.md`：

- 产品型功能必须明确目标用户、业务场景、范围内 / 范围外、用户流程、业务规则、权限和验收口径。
- 小型修复、纯技术任务或维护任务可以将 PRD 标记为不适用，但必须在 `prd.md` 写清原因和仍需满足的验收口径。
- PRD 解决“为什么做、给谁用、做什么、怎么验收”；ADR 解决“为什么采用某个技术方案”。两者不能互相替代。
- 如果 PRD 与 brief 或 acceptance 冲突，Product 必须记录冲突并请求确认，不能把猜测写成事实。

### 4.3 实现分流

Planner 必须根据 `.agents/ownership.yaml` 和本次影响范围决定是否进入前端实现线、后端实现线或两者并行：

- 前端实现线：命中前端、桌面端 UI、移动端 UI、设计系统、浏览器侧状态、样式、路由和 API 调用等范围时，由 Frontend Implementer 负责。
- 后端实现线：命中服务端 API、业务服务、权限、任务调度、服务端数据访问，或由 Planner 明确映射到后端的数据库迁移等范围时，由 Backend Implementer 负责。
- 前后端同时受影响时，Architect 必须先明确接口契约、数据结构、错误码、鉴权、兼容性和回滚方案；两个实现 Agent 可在契约稳定后并行执行。
- 如果实现过程中任一方需要修改共享契约，必须回到 Architect 更新方案，再继续实现。
- 如果任务不属于前端或后端，例如纯文档、基础设施或数据平台任务，Planner 必须显式指定 owner、允许修改路径和执行角色；必要时扩展新的专用实现 Agent。

### 4.4 职责边界和越界处理

每个 Agent 必须遵守以下边界：

- Discovery 只负责发现和归纳项目事实，可更新发现记录和 ownership 建议，不修改业务代码、不替 Planner 拆任务。
- Product 只负责产品需求、业务规则、范围边界和验收口径，不做技术架构、不分配 owner、不改业务代码。
- Planner 只负责计划、验收映射、owner 和实现线分配，不写架构方案、不改业务代码、不代替 Reviewer 下审查结论。
- Architect 只负责设计、契约、风险和回滚方案，不直接实现业务代码、不绕过 Planner 扩大范围。
- Frontend Implementer 只修改授权的前端路径和前端测试，不修改后端 API、数据库、权限、部署和基础设施。
- Backend Implementer 只修改授权的后端路径、后端测试和被明确映射到后端线的数据迁移，不修改前端 UI、样式、路由和浏览器状态。
- QA 只执行验收、补充被授权的测试或测试数据、记录复现路径，不修业务代码、不扩大需求范围。
- Reviewer 只审查和反馈，不直接修改业务代码、不把个人风格偏好作为阻塞项。
- Integrator 只执行集成验证、记录环境和联调问题，不直接修业务代码、不绕过 Review 合入变更。
- 主 Agent 只做协调、任务文档、跨模块配置和最终集成；除第 3 节列出的例外，不直接修改已归属给子 Agent 的业务代码。

如果任一 Agent 发现必须越过授权边界才能继续：

- 立即停止对应修改，不提交越界变更。
- 在对应任务文档中记录所需路径、原因、风险和建议 owner。
- 回退给 Planner 重新分配 owner；涉及契约、架构或跨模块影响时，必须先回到 Architect 更新方案。
- Reviewer 发现未授权越界修改时，默认标记为 P1；如果只是任务文档或测试记录缺少 owner 说明，可按影响标记为 P2。

## 5. 质量门禁

### 5.1 问题等级

- P1：阻塞级。会导致功能不可用、数据错误、安全漏洞、构建失败、核心测试失败或未授权跨 owner 修改业务代码。必须修复。
- P2：重要级。会造成明显回归、边界错误、职责归属不清、可维护性风险或缺失关键测试。建议修复；同模块最多循环 3 次。
- P3：建议级。不阻塞当前任务，记录为待办。

### 5.2 自动修复循环

```text
Product / Planner / Architect
  -> Frontend Implementer / Backend Implementer
  -> QA
  -> Reviewer
    -> 如果存在 P1 或需要处理的 P2
      -> 回退给对应 owner 修复
      -> 重新 QA / Reviewer
      -> 循环直到 P1 清零、P2 <= 2 或达到循环上限
  -> Integrator
    -> 如果发现集成问题
      -> 按 ownership 回退修复
      -> 重新 QA / Reviewer / Integrator
```

### 5.3 Reviewer 要求

Reviewer 必须：

- findings 优先，按严重程度排序。
- 每个问题必须指向具体文件、行为风险和修改建议。
- 检查任务验收标准是否被逐条覆盖。
- 检查实现、测试和审查是否覆盖 PRD 中的产品范围、业务规则和验收口径。
- 检查代码是否越过 `.agents/ownership.yaml` 的授权边界。
- 检查每个 Agent 是否只完成自己职责内的工作，越界修改必须给出 P1/P2 结论。
- 检查本地化文本和源码编码是否保持 UTF-8 实际字符，不应把可读文本写成 `\uXXXX` 形式。

Reviewer 不应：

- 直接修改业务代码。
- 因无关风格偏好阻塞任务。
- 在未给出复现路径的情况下标记 P1。

## 6. 集成验证

Integrator 或主 Agent 必须在审查通过后执行集成验证，检查：

- 项目能否安装依赖、构建、启动。
- 前后端、服务间、数据库、消息队列或第三方依赖是否能连通。
- API 代理、CORS、路由、鉴权、环境变量和配置文件是否正确。
- 核心业务流程是否能走通。
- 测试、lint、typecheck、迁移脚本或 CI 等关键命令是否通过。

无法运行的命令必须记录原因，例如缺少账号、缺少数据库、网络不可用或依赖未安装。

## 7. 编码和文件规范

- 所有源码和配置文件应使用 UTF-8 编码。
- 面向用户展示的中文或其他本地化文本应保存为实际可读字符，禁止无必要地写成 `\uXXXX`。
- 任务记录必须使用中文书写，包括标题、结论、原因、验收结果、风险和待办说明；文件名、配置键、命令、代码标识、错误日志、第三方专有名词和必要的接口字段可以保留原文。
- 不修改无关文件，不做无关格式化。
- 不删除用户已有改动。
- 修改跨模块公共契约时，必须同步更新调用方、测试和任务文档。

## 8. 任务文档

进入执行流程的每个任务默认必须使用：

```text
tasks/{task_id}/brief.md
tasks/{task_id}/acceptance.md
tasks/{task_id}/discovery.md
tasks/{task_id}/prd.md
tasks/{task_id}/plan.md
tasks/{task_id}/architecture.md
tasks/{task_id}/implementation.md
tasks/{task_id}/frontend-implementation.md  # 有前端变更时使用
tasks/{task_id}/backend-implementation.md   # 有后端变更时使用
tasks/{task_id}/test-report.md
tasks/{task_id}/review.md
```

只有纯问答、纯解释、只读分析且用户未要求进入执行流程时，才可以不新建任务目录。若执行流程因运行时限制进入降级执行，也必须建立同样的任务记录，并在 `plan.md`、`implementation.md`、`test-report.md` 和 `review.md` 里写明哪些阶段由实际子 Agent 完成，哪些阶段由主 Agent 代为记录。

任务记录正文必须以中文为主。若引用英文命令、日志、代码、配置键或外部系统原文，必须只保留必要原文，并用中文解释其含义、结果或影响。

重大架构决策记录到：

```text
docs/adr/{adr_id}-{short-title}.md
```
