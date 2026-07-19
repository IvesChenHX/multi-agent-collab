# v6 Alpha 内部收口与 Pilot-ready 候选报告

> 结论：本阶段的定位是 **Alpha 内部收口 / Pilot-ready 候选**，不是 Gate 2 或 Gate 3 通过声明。报告中的实现与验证结论仅来自当前 Task 的结构化 Result；最终 commit、tree、diff、policy 一致性以及独立审查结论须在冻结后补录。

## 1. 阶段身份与边界

| 项目 | 当前记录 |
| --- | --- |
| Task | `TASK-01KXXHKS63XE2A30229824FX0N-v6-alpha-pilot-ready` |
| 前序 Task | `TASK-0006-v6-governance-core`；当前 Task 是其正式 successor，并记录 `supersedes` |
| 模式 | `high_risk` |
| 目标 | 收敛 `RV6-001..017`，把治理内核推进到可进入真实 Pilot 的候选状态 |
| 起草时状态 | `executing`；机器可读 `task.yaml` 和 Event replay 是状态事实源 |
| 候选代码 subject | **冻结后补录：commit/tree/diff digest** |
| 冻结 policy / ownership | 以当前 Task 的 `policy_ref`、`ownership_ref` 与批准后的 Scope Contract 为准；最终一致性在冻结后复核 |

本阶段继续遵守设计包的产品边界：实现 local-first、Git-native 的治理内核、CLI 与运行时适配 seam；不建设模型调度器、分布式队列、凭据托管、自动合并、生产部署或完整 Web/TUI 编排平台。

## 2. 阶段目标

本阶段不是增加一组文档约定，而是把 Alpha 中仍会破坏可信闭环的缺口落实为机器约束：

1. 冻结 policy、ownership、runtime profile 与 workflow 语义，避免运行逻辑和 digest 漂移；
2. 让 Task/Event/Run/Result 写入具备 lease、revision、idempotency 与 event-first 恢复语义；
3. 让 Scope、Git diff、Work Unit、Evidence、Review、Risk Acceptance 与 Close 使用一致的 fail-closed 接口；
4. 覆盖 YAML、路径、symlink/junction、submodule、LFS、Unicode/case、迁移与外部 artifact 等高风险边界；
5. 补齐 Doctor、audit bundle、Schema lock、构建与 CI 的可诊断、可恢复和供应链门禁；
6. 保留真实 Pilot、跨平台托管 CI、正式发布和原生只读 L2 审查为外部门禁，不用本地模拟结果替代。

## 3. 已录入的实现结果

以下三项 Work Unit 已有 `outcome=succeeded` 的结构化 Result。它们表示实现结果已被收集，不等同于最终 Task Close 或 Gate 2 通过。

### 3.1 Frozen Policy、Task Journal 与 Evidence/Close

Result：`RESULT-01KXXHSZRPJ5YKMQ9MCQHQZH12`

- policy digest 改为基于冻结来源，并纳入选定 runtime profile；状态与终态语义由 workflow 驱动；
- Task 写入收敛到持久 lease、expected revision、guard、event-first 与 projection replay；
- authority、review independence、risk acceptance 和 Close 判定改为 fail closed；
- Result intake、workspace equivalence 与 Evidence promotion 使用结构化证明，而不是调用方自报布尔值；
- Result 同时约束 Task Scope、Work Unit 允许路径、owner 与当前 Git surface。

### 3.2 Path/YAML/Git 安全、迁移与权威示例

Result：`RESULT-01KXXHTEMXPCT29MAV3AFAMWFJ`

- 对不可信 YAML、repo-relative 路径、大小写与 Unicode 归一化执行受限解析和路径校验；
- 补强 rename/delete/untracked/symlink/submodule/LFS 与 workspace subject 处理；
- 修复迁移输出穿越、重复映射、非 mapping 输入、输出越界与 untracked 文件 TOCTOU；
- v5 迁移继续保留 `metadata_only` / `unverifiable` 语义，不伪造历史 Evidence；
- tracked `examples/v6` 调整为可 replay 的权威示例，并补充治理 workflow。

### 3.3 Doctor、Audit、Schema lock 与发布/CI 加固

Result：`RESULT-01KXXHTR2PNYB2M57BQTRFXC2B`

- Doctor repair-safe 改为先生成冻结修复计划，只处理可证明的临时文件、lease 和 projection replay；
- audit bundle 增加外部 trust anchor、资源限制与读取期间身份校验；
- Schema lock 使用 canonical LF 和显式 SchemaSet，启动、validate/build 路径增加一致性检查；
- 构建后检查、governance PR 与 release workflow 增加本地可验证门禁；
- 对 repo 外 symlink/reparse escape 采取 fail-closed 行为。

### 3.4 CLI 集成、全链路验证与报告

Work Unit：`WU-01KXXHV2CF6FRH4Z108JB3N4PA`
Result：`RESULT-01KXXHV2CF6FRH4Z108JB3N4PB`（是否已提交及其 revision 以 Event stream 为准，本报告不自行充当状态事实源）

- CLI 已接入 frozen runtime policy、Task lineage、转换 shape preflight、Scope owner cancellation/supersede authority 与 successor 校验；
- Run 注册会冻结 commit baseline、worktree/branch identity 及可选 provider/model；Run finish 强制显式 revision 与 idempotency key；
- Result CLI 会在任何路径拼接前拒绝不可信 ID，并从冻结 Run 重新计算结构化 `ResultIntakeProof`，随后由 `ResultService` 独立重验；
- Evidence promotion 使用单次结构化 workspace equivalence proof；Doctor apply 强制 preview plan digest；audit bundle verification 强制外部 digest 或 trust anchor；
- 本节代码、回归测试和报告已完成本地主控制器验证。最终 commit/tree/diff/policy、commit-bound Evidence 与原生只读 L2 Review 仍需冻结后记录，不能由本节替代。

## 4. RV6 风险收敛矩阵

“已实现”仅表示对应变更已进入上述 Result；最终状态仍受集成验证、冻结 Evidence 和独立 Review 约束。

| 风险 | 本阶段收敛面 | 当前判定 |
| --- | --- | --- |
| `RV6-001` | workflow/config/ownership/runtime profile 驱动的冻结 policy | 已实现，待冻结复核 |
| `RV6-002` | lease、revision、idempotency、event-first 与 actor authority | 已实现，待全链路验证 |
| `RV6-003` | Review actor/provider/model/runtime/只读与 commit 参与校验 | 核心 fail closed 已实现；原生只读 L2 仍待外部能力 |
| `RV6-004` | security/data/compliance/independence 不可豁免规则 | 已实现，待最终 Review |
| `RV6-005` | 治理敏感路径由批准 Scope/审批表达，不依赖 schema 外字段 | 已实现，待 Scope Guard 复核 |
| `RV6-006` | Close 统一重算 subject、policy、Scope、Evidence、Review、Finding 与 waiver | 已实现，待 commit-bound E2E |
| `RV6-007` | tracked `examples/v6` 可校验、可 replay | 已实现，待全套验证 |
| `RV6-008` | v5 converter 输出与 Event replay 一致 | 已实现，待迁移回归 |
| `RV6-009` | 扫描、来源 digest、状态/owner 映射和回滚矩阵 | 已实现，待真实迁移样本 |
| `RV6-010` | dirty/index/untracked workspace 绑定和结构化 promotion proof | 已实现，待 commit promotion E2E |
| `RV6-011` | Task 创建原子性、持久 lease 与 ABA 防护 | 已实现，待故障注入/全套验证 |
| `RV6-012` | Result 同时校验 Task Scope、WU path/owner 和 Git diff | 已实现，待集成 Result |
| `RV6-013` | submodule/LFS/symlink/case/Unicode 与受限 YAML | 已实现；真实跨平台 symlink/LFS 待外部 CI |
| `RV6-014` | plain-terminal handoff 使用冻结 policy identity | 待集成全链路确认 |
| `RV6-015` | PR Task ID、current subject 与 CI Evidence gate | 本地 CI 门禁已实现，托管 CI 待外部执行 |
| `RV6-016` | Doctor 仅按冻结计划修复已知安全目标 | 已实现，待 recovery 演练 |
| `RV6-017` | Doctor 诊断、audit 独立验证、Schema lock 与 build hook | 已实现，待最终构建/打包验证 |

## 5. 已有验证证据

以下命令和结果按三个结构化 Result 原样归纳；不同集合可能重叠，不能把通过数简单相加为唯一测试数。

| Result | 已记录验证 |
| --- | --- |
| Core | `core-targeted`: 65 passed；`lifecycle-close`: 7 passed；`source-commit-security`: 4 passed；`git diff --check`: clean（仅 CRLF notices） |
| Edge | `edge-targeted`: 49 passed, 1 skipped；`git diff --check`: clean（仅 CRLF notices） |
| DevEx | `devex-targeted`: 42 passed, 2 skipped；Schema bundle 与 lock 一致；wheel/sdist post-build checks 通过；`git diff --check`: clean（仅 CRLF notices） |
| Integration | 主控制器扩大目标集 39 passed；全量 `pytest` 190 passed, 3 skipped；总覆盖率 92.92%，通过 90% 门槛 |

本地主控制器的补充验证结果：

- `mac validate --json`：`ok=true`；5 个 v5 Task 保守报告 `LEGACY_TASK_UNVERIFIABLE` warning，未伪造历史验证；
- `mac doctor --json`：`ok=true`；Schema lock、compiled policy、repository validation、event replay、private/log/path 风险检查通过；可选诊断仍报告当前 CRLF-era frozen policy/ownership row digest 与 canonical HEAD digest 不同，以及 5 个 legacy Task 尚未迁移。独立的 executable-equivalence 校验对当前 Task 的 policy 与 ownership 均返回 true；这些可选诊断不等同于 Gate 2 迁移完成；
- Scope Guard：当前 workspace 全部变更均在批准的 Scope v3 内，无 issue；`git diff --check` 通过，仅有 Windows LF/CRLF notice；
- Secret scan：扫描 117 个变更或新增文件，5 个命中均为已审核的实现语句或安全测试 fixture，unexpected hit 为 0；
- 离线构建：`multi_agent_collab-0.6.0a1-py3-none-any.whl` 与 `multi_agent_collab-0.6.0a1.tar.gz` 构建成功；本次临时产物 SHA-256 分别为 `4A056782885F104B739F060A6CB7640D197D41E87320E15234823EA5F0CE88A6`、`9B9FB5E1CF0121B000B2412586C783925C8F2D6131CEB5ABF396D641C4B506DC`。

当前 Windows 主机缺少创建部分真实 symlink fixture 的能力，因此 Edge 的 1 个 skip、DevEx 的 2 个 skip 不能写成通过。真实目录/文件 symlink、Git LFS 对象可取回、Linux/macOS/特权 Windows 行为需要托管或等价外部环境补证。

本表也不替代最终全套测试、性能指标、secret scan、Scope Guard、commit-bound Evidence 或独立 Review。最终验证记录应绑定冻结后的代码 subject，不能沿用冻结前的测试结论直接 Close。

## 6. 尚未完成的门禁

| 门禁 | 状态 | 继续所需输入/外部条件 |
| --- | --- | --- |
| 最终集成与 commit-bound Evidence | 本 Task 内待完成 | 冻结 commit/tree/diff/policy，重跑受影响验证并录入 Evidence |
| 原生只读 L2 Review | `waiting_external` | 能证明 fresh context、不同模型/运行时、只读权限且未参与实现的 Reviewer；当前本地 profile 不得冒充 |
| 三个真实项目、至少 30 个任务 | `waiting_input` | 小型单体、前后端/monorepo、高风险服务各一个；每个项目 owner、测试命令和治理元数据许可 |
| Observe/Advisory Pilot 数据 | `waiting_external` | 真实使用者、scorecard、误报/漏报、人工与治理耗时、恢复和满意度记录 |
| 托管跨平台 CI | `waiting_external` | Linux、macOS、Windows runner，真实 symlink/LFS/文件系统与权限行为 |
| 外部身份与审批可信度 | `waiting_input` | 人类 risk acceptor、Security Reviewer、CI/provider identity 和 trust anchor |
| Gate 2 | **未通过** | 完成真实 Pilot 退出标准后才可决策 |
| Gate 3 / v1 正式发布 | **未开始 / 未通过** | Gate 2、安全评审、迁移和回滚演练、支持矩阵、SBOM、签名/provenance、安装升级回滚及至少一个项目 Enforced 两周 |

因此，本报告不能作为开启全仓 `enforced`、生产部署、正式发布、兼容性承诺或“v1 ready”的依据。

## 7. 回滚与恢复说明

### 7.1 本阶段代码回滚

- 本阶段在隔离分支/工作树中实施；最终候选提交冻结前，不覆盖主工作树中的用户改动。
- Scope Contract 已记录基线 commit；候选提交冻结后补录最终 subject 与 diff digest。
- 若候选未通过最终验证，可放弃隔离分支，或对冻结后的候选提交执行 Git revert；不要用破坏性 reset 覆盖用户工作。
- 若独立 Review 后发生代码漂移，按实际失效 surface 重验并重新冻结，不沿用旧 Evidence。

### 7.2 Task/Event 恢复

- `events/*.json` 是恢复来源，`task.yaml` 是投影；projection 缺失或 event-first 中断由 replay/Doctor 重建。
- revision gap、损坏 Event、错误 policy digest 或无法证明的 workspace 等价均 fail closed，不能用人工描述改写为通过。
- Doctor repair-safe 只应用 digest 匹配的冻结计划，不审批 Scope、不接受风险、不改变业务结论。

### 7.3 v5 迁移回滚

- 迁移先只读扫描，再写独立 v6 输出；重复执行不得产生重复 Task。
- 历史证据不足时保留 `legacy_integrity: metadata_only` 与 `verification_status: unverifiable`。
- 迁移不删除 v5 历史；真实项目切换前必须创建备份/迁移前 tag，回滚使用 Git revert 或切回该 tag。
- 安装、升级、迁移与回滚的真实项目演练仍属于后续 Pilot/Gate 3 Evidence，本阶段没有宣称完成。

## 8. 下一会话：Gate 2 Pilot 输入

下一阶段应创建独立 successor Task/会话，引用本阶段冻结后的 commit、报告与开放门禁。开始前至少需要：

1. 三个 Pilot 项目的仓库、owner、主要路径、敏感路径、稳定测试/lint/build 命令；
2. 每个项目提交治理元数据的许可、数据分级、日志保留规则及迁移/回滚窗口；
3. 真实 runtime profile，明确 fresh context、只读、并行、artifact、网络与取消能力，缺失能力保守降级；
4. 人类 Scope Approver、Risk Acceptor、Security Reviewer 和最终 Gate 2 决策人；
5. 托管 CI runner、身份来源和 audit bundle trust anchor；secret 仅通过环境或 broker handle 注入；
6. `pilot-scorecard.csv` 的采集责任和每周复盘节奏。

## 9. 下一会话：Gate 2 执行与退出标准

建议保持设计包的渐进采用顺序：

1. Week 0：三个项目只运行 Observe，完成 owner、命令、敏感路径与 runtime profile 扫描；
2. Week 1–4：Advisory，每个项目完成至少 10 个真实任务，记录误报、漏报、Evidence 缺口、amendment、人工干预、恢复和治理耗时；
3. Week 5–6：只对通过 `PILOT-READINESS` 的项目评估小范围 Enforced；任何严重误报、scope 漏报或 runtime 能力虚报都退回 Advisory；
4. Week 7：形成 findings-first 的 Gate 2 决策报告；失败时回到设计 Gate，不通过堆功能掩盖指标。

Gate 2 退出至少要求：

- 3 个真实项目、至少 30 个真实任务；
- 0 ID 冲突、0 无 Evidence 完成、0 已知 scope 漏报；
- Advisory 无严重误报，quick 升级判断可接受，Scope Guard 与 commit/workspace Evidence 绑定稳定；
- event replay 恢复在 Pilot 样本中成功，等待外部依赖后可按状态机恢复；
- standard 治理耗时中位数不高于 8%，quick 常用路径额外步骤不超过 1 条命令；
- high-risk 样本具备正/负测试、授权 Scope、回滚/恢复和真实独立 Review；
- 开放 finding、waiver、跳过项和外部依赖均结构化记录，没有用“文档已说明”替代机器门禁。

至少一个项目 Enforced 两周、安全与供应链发布门禁属于 Gate 3 / v1 条件，不能提前写入本阶段或 Gate 2 的通过结论。

## 10. 冻结后补录项

在本阶段最终交接前，由主控制器补录或链接以下机器事实：

- 候选 commit、tree、diff digest；
- 冻结 policy/ownership/runtime profile digest 的一致性检查；
- Integration Result 与最终全套验证摘要；
- 当前有效 Evidence、Scope Guard、secret scan、rollback verification；
- 最终 findings-first Review 及其 independence 证明；
- Task 的最终状态。若原生只读 L2 或其他不可替代门禁仍缺失，应保持 `waiting_external`/`waiting_input`，不得强行 Close。
