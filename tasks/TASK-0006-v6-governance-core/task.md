# TASK-0006-v6-governance-core

## mode

- 模式：`high_risk`。
- 触发证据：本任务会替换公共治理协议、状态机、权限与 ownership、安全边界、任务存储格式和 CI 门禁，并包含 v5 → v6 迁移与回滚要求。
- 必要门禁：Architect、独立 Reviewer、针对性测试、跨模块集成验证、迁移与回滚验证。

## scope

### 设计权威与产品边界

- 唯一设计输入：`multi-agent-collab-v6-design-package/**`。
- 严格落实设计包中的 Goals、Non-goals、数据模型、状态机、CLI/API、错误码、权限、安全、迁移、测试、运维和发布约束；不得衍生新产品能力，不得删减首期必须能力。
- 设计包作为只读输入，不在本任务中修改。
- 保留用户已有的 `multi-agent-collab-deep-feasibility-plan-v3.md` 和 `.idea/**`，不得覆盖或清理。

### 验收标准

1. `delivery/implementation-backlog.csv` 中适用于单仓库实现的 Gate 0、Alpha、Pilot、v1 交付物均有代码、测试或明确外部门禁证据。
2. `delivery/requirement-traceability.csv` 的 G-01 至 G-10 均能定位到实现与可重复验证；需要真实试点、签名基础设施或外部 owner 决策的项目不得伪造通过。
3. 实现 Task/Event/Scope/Evidence/Finding、event-first 原子写、投影重放、revision/lease、完整状态机、Git scope guard、workspace/commit/policy evidence、runtime profile、handoff/result、迁移与 CI。
4. CLI 命令、JSON 输出和退出码与设计包一致；Schema 使用 JSON Schema 2020-12，跨文件不变量可确定校验。
5. Scope、安全路径、独立审查、risk acceptance、non-waivable gate 与 Close Engine 具备负向安全测试。
6. v5 扫描只读；迁移支持 dry-run、重复执行与回退，不伪造历史 Evidence。
7. 设计包自校验、项目目标测试、受影响模块测试和跨模块集成验证通过；无法在本地完成的三个真实项目试点、跨平台 CI、发布签名等外部门禁必须如实标为阻塞或待外部执行。

### owner、执行者与允许路径

- `platform`：Backend Implementer；允许修改 `pyproject.toml`、`src/**`、`tests/**`、`schemas/**`、`migration/**`、`scripts/**`、`Makefile`、`.gitignore`、`examples/**`。
- `devex`：DevEx/CI Implementer；允许修改 `pyproject.toml`、`uv.lock`、`src/mac/cli/**`、`src/mac/adapters/runtime/**`、`tests/cli/**`、`tests/operations/**`、`tests/adapters/**`、`.github/**`、`scripts/ci/**`、`scripts/release/**`、`docs/release/**`、`README.md`。
- `security`：Security Implementer；允许修改 `schemas/evidence.schema.json`、`schemas/finding.schema.json`、`schemas/approval.schema.json`、`schemas/risk-acceptance.schema.json`、`src/mac/domain/**`、`src/mac/application/**`、`tests/security/**`、`tests/review/**`、`tests/risk/**`、`tests/reporting/**`；与 platform 重叠文件由主 Agent 串行分派，禁止并发写入。
- `governance`：主 Agent 负责协调性文件整合；允许修改 `AGENTS.md`、`.agents/**`、`README.md`、`docs/**`、`tasks/**`。
- `review`：独立 Reviewer；只读审查全部 diff、设计追踪与验证证据，不修改实现。
- `integration`：Integrator；只读执行跨模块、迁移、CLI、CI 配置与发布门禁验证。
- 禁止路径：`multi-agent-collab-v6-design-package/**`、`multi-agent-collab-deep-feasibility-plan-v3.md`、`.idea/**`。

### 外部门禁责任

| 门禁 | 外部 owner | 证据位置 | 环境 | 当前状态 |
| --- | --- | --- | --- | --- |
| Gate 0 试点项目、owner、预算与 Stop/Go 签署 | Product/Repo Owner | `docs/pilot/gate-0-decision.md` | 三个真实项目 | 待外部输入 |
| Linux/macOS/Windows、Python 3.11–3.13 | DevEx/Repo Owner | GitHub Actions run | 托管 CI | 待推送后执行 |
| 三项目、至少 30 个真实任务与 branch protection | Product/Repo Owner | `docs/pilot/gate-2-report.md` | 真实试点仓库 | 待外部执行 |
| 至少一个项目 Enforced 两周 | Product/Repo Owner | `docs/pilot/gate-3-report.md` | 真实试点仓库 | 待外部执行 |
| PyPI/GitHub Release、SBOM、Sigstore/OIDC provenance | DevEx/Security Owner | 发布产物与 attestation | 外部发布基础设施 | 待外部授权与凭据 |

### 依赖与执行顺序

1. 设计与安全契约确认。
2. Schema/validator/稳定错误协议。
3. Task/Event store、投影、revision/lease 与生命周期。
4. Scope/ownership/Git guard。
5. Evidence/review/risk/Close。
6. Runtime handoff/result、迁移、报告、CI 与发布加固。
7. 独立集成验证与最终审查；发现 P1/P2 时按 owner 创建全新返工上下文。

## decisions

- 2026-07-17 用户明确授权主 Agent 在当前上下文跨 Platform、Governance/Security、DevEx owner 修复 `RV6-001..017`。该用户指令解除此前因线程上限导致的跨 owner 实现阻塞；任务恢复为 `repairing`。主 Agent 验证仍仅为 L0，不能替代最终 L2 Review。
- 当前 v5 规则继续约束本次变更，直到 v6 实现通过验证；本任务仍使用 `TASK-0006` 台账编号，不能用尚未落地的 v6 规则反向证明自身完成。
- 首期遵守设计包的 local-first、Git-friendly、Python 3.11+、无 daemon 边界。
- 依据用户“严格按照设计包落地，不要衍生或者精简”的明确授权，采用设计包默认 Gate 0 参数：task 元数据提交 Git、`report.md` 默认不提交、终态不 reopen、quick 为 5 文件/200 行、high-risk 最低 L2、raw log 默认保留 30 天且不提交、Python 3.11+、v1 支持 Linux/macOS/Windows、每事件一文件、显式 policy rebase、CI 签名可选、CODEOWNERS 仅作候选、初始治理等级 `advisory`。
- 数据分类采用设计默认：task 文本 `internal`、raw log `confidential`、源码按项目策略、secret 禁止、用户 PII `restricted`；不可豁免 gate 至少包括 approved scope、当前代码/策略 evidence、high-risk 最低独立审查和数据完整性。
- 13 个 v6 持久状态和 docs/05 的 `waiting_external → executing` 转换必须完整实现；`blocked` 不进入 v6 状态集合。
- 根目录 `schemas/**` 是 Schema 唯一源码；构建时通过打包配置映射为 `mac/schemas` 资源，不维护第二套可漂移源码。
- v6 候选实现先按 `advisory` 运行；当前 TASK-0006 全程仍由 v5 规则治理。真实试点通过前不得切为 `enforced`。
- 真实三项目试点、签名发布和各平台托管 CI 属于外部执行门禁；本任务实现其机制与配置，但不伪造外部结果。

## delegation

- 主 Agent：Triage、任务记录和最终状态整合。
- Architect `/root/v6_architecture`：已完成只读交接，确认不可变公共契约、安全、兼容与回滚约束，并指出 `uv.lock`、Gate 0 与外部门禁缺口。
- Planner `/root/v6_planning`：已完成只读交接，把完整 backlog 映射到路径、owner、依赖与验证责任，并指出 DevEx/Security/Product owner 缺口。
- 曾误向已完成 Architect 的同一上下文发送实现 follow-up，发现违反 Architect 禁止实现边界后立即中断；该上下文未作为实现证据，实际实现改由全新专用上下文承担。
- Backend/Platform Implementer `/root/v6_platform_impl`：实现 Schema、validator、event store、state、scope、evidence、Close、迁移与附近测试。
- DevEx/CI Implementer `/root/v6_devex_impl`：实现 runtime adapters、doctor 测试、CI、发布工程与支持文档；不得修改 Platform 源码。
- Security Implementer/Test Author `/root/v6_security_tests`：独立编写 threat、review、risk 与 audit 负向 corpus；不得修改业务实现。

## changes

- 主 Agent：迁移 `AGENTS.md`、`.agents/config.yaml`、workflow、ownership、runtime profiles、角色契约和项目基线为 v6 候选治理配置；保留 v5 文件到 `.agents/legacy/**`。
- Platform Implementer：实现 15 个 Schema、完整 CLI、事件存储/投影/revision/lease、状态机、ownership/Scope/Git、Evidence/Review/Risk/Close、runtime/result/handoff、migration、doctor/report/audit bundle、示例与核心测试。
- DevEx/CI Implementer：实现 plain-terminal/agtx/Conductor adapters、跨平台 CI、PR governance、release/SBOM/Sigstore 配置、发布脚本、`uv.lock` 和运维文档。
- Security Test Author：新增 49 个负向安全、独立性、风险和审计 case；未修改业务实现。
- 主 Agent：新增 Gate 0/2/3 诚实外部证据模板；真实 Pilot/CI/发布结果仍未伪造。

## verification

- `.venv\\Scripts\\python.exe -m pytest`：`105 passed, 1 skipped`；唯一 skip 为当前 Windows 权限无法创建 symlink；核心覆盖率 `93.33%`，达到 `>=90%`。
- `.venv\\Scripts\\mac.exe validate --repo . --json`：失败，v5 任务目录被错误报告为缺少 v6 `task.yaml`/`scope-contract.yaml`；该证据触发 FND-R1-001，仓库级 validate 与迁移双读证据失效。
- Round 2 后全量：`111 passed, 1 skipped`，核心覆盖率 `93.33%`；根仓库 validate `ok=true` 且只有 6 条 legacy warning；wheel/sdist 构建成功。
- Integrator `/root/v6_integration_verify`：迁移幂等、baseline、Schema lock、wheel 安装、workflow YAML 和无 Evidence fail-closed 通过；标准 lifecycle/Close 成功路径、event-first 冲突安全和 workspace Scope 失败，触发 Round 3。
- Round 4 独立 Integrator 增量复验：真实进程退出码 success=0、validate=3、transition=4、Scope=6、Evidence/Gate=7；孤儿 Run validate=3；Work Unit `ready → running → completed`、删除投影后 Event 重放恢复；未完成 required WU 的 Close=7，伪造 terminal 后 validator=3。目标 `3 passed`、相邻 `18 passed`，未发现 P1/P2/P3。

## findings

- `FND-R1-001`（P1 / compatibility / block_close / confirmed，owner: platform）：`mac validate --repo . --json` 对 `tasks/TASK-0001...TASK-0006` 的 v5 目录返回 `TASK_FILE_MISSING`，没有按 MIG-003 双读契约将 v5 元数据标为 legacy warning。风险是实际 v5 仓库无法进入 v6 advisory，G-01/G-09 与迁移验收不成立。修复后必须重跑目标测试、全量 pytest、根仓库 validate 与 migration dual-read。
- `FND-R1-001` 处置：已由全新 `/root/v6_repair_r1_platform` 修复。目标测试 `7 passed`，全量 `107 passed, 1 skipped`，根仓库 validate `ok=true` 且仅有 6 条不可验证 legacy warning；状态 `resolved`。
- `FND-R2-001`（P2 / compatibility / block_close / confirmed，owner: platform）：`scripts/capture_v5_baseline.py` 只读取当前工作区；治理文件已迁为 v6 后无法从 `HEAD` 或指定 Git ref 生成真实 v5 policy digest，导致 GOV-002 不可复验。必须支持显式 source ref、记录 resolved commit/ref，并保留工作区捕获模式；不存在 ref/文件时稳定失败，禁止静默用当前文件替代。
- `FND-R2-001` 处置：已由全新 `/root/v6_repair_r2_baseline` 修复。新增 `--source-ref`、resolved commit 绑定和稳定失败语义；目标测试 `4 passed`、全量 `111 passed, 1 skipped`；状态 `resolved`。
- `FND-R3-001`（P1 / correctness / block_close / confirmed，owner: platform）：ready Work Unit 被 `dependencies_complete` 错误拒绝，标准 Task 无法 `ready → executing`。必须允许依赖已完成且当前 WU 为 ready 的正常执行，并保留未完成依赖的拒绝。
- `FND-R3-002`（P1 / policy / block_close / confirmed，owner: platform）：CLI 自己写入的 Task/Run/Event/Evidence 元数据被业务 Scope/Ownership 当作越界，导致有效 Evidence 后仍无法 scope clean/Close。必须把当前 task 的治理元数据按机器策略区分，不得放宽对其它 Task 或业务路径的检查。
- `FND-R3-003`（P1 / data / block_close / confirmed，owner: platform）：`run register` 在 expected revision 冲突前写入 Run JSON，留下无 Event 引用的孤儿；validator 也未检出孤儿。所有写命令必须先校验 lease/revision/guard，再落实体与 Event；跨文件不变量必须拒绝孤儿 Run/Result/Evidence。
- `FND-R3-004`（P1 / policy / block_close / confirmed，owner: platform）：新 `.gitignore` 取消忽略用户既有且本任务禁止修改的 `.idea/**`，它们进入 workspace digest/Scope 并造成误报。`.idea/` 属于生成的 IDE 元数据，应继续忽略，且不得修改其内容。
- `FND-R3-005`（P2 / compatibility / block_close / confirmed，owner: platform）：不存在 Task 的 `--json` 命令泄露 Rich traceback/exit 1；缺参时输出富文本而非稳定 JSON。叶命令必须返回规定 error envelope 与退出码。
- `FND-R3-006`（P2 / correctness / block_close / confirmed，owner: platform）：`mac init` 生成 workflow 有 8 个不可达状态 warning。默认 workflow 必须覆盖完整设计转换，并由 validate 证明 13 状态可达。
- `FND-R3-001..006` 处置：已由全新 `/root/v6_repair_r3_integration` 修复。Round 3 目标测试 `7 passed`，真实 standard lifecycle 到 `completed`，全量 `118 passed, 1 skipped`，核心覆盖率 `94.25%`，根仓库 validate exit 0；状态均为 `resolved`。

### Round 4 独立集成复验新增 findings

- `FND-R4-001`（P1 / security / block_close / confirmed，owner: platform）：CLI 使用 `standalone_mode=False` 时吞掉叶命令抛出的 `typer.Exit`，导致 JSON 已返回 `ok=false`，操作系统进程退出码仍为 0。已复现 `mac scope check current --workspace --json` 有 8 个 Scope 错误却 exit 0，以及包含孤儿 Run 的 `mac validate --json` 返回 `RUN_EVENT_MISSING` 却 exit 0。该问题可让 CI/安全门禁静默通过；必须统一传播设计包规定的业务退出码，并覆盖成功 0、校验 3、状态 4、Scope 6、Evidence/Gate 7。
- `FND-R4-002`（P1 / data_integrity / block_close / confirmed，owner: platform）：真实 lifecycle 可在唯一 Work Unit 仍为 `ready` 时把 Task 关闭为 `completed`，validator 也返回通过。必须让运行/结果生命周期以 event-first 原子方式推进相关 Work Unit，且 Close/validator fail-closed 校验所有 required Work Unit 已完成，禁止用手工改写实体规避。
- `FND-R4-001..002` 处置：已由全新 `/root/v6_repair_r4_close_exit` 修复。Round 4 目标测试 `3 passed`，相邻回归 `31 passed`，全量 `121 passed, 1 skipped`，核心覆盖率 `94.35%`；根仓库 validate `ok=true / exit 0`。独立 Integrator 已按上述真实进程矩阵重验且未发现 P1/P2/P3；状态 `resolved`。

### Round 5 最终独立 Reviewer findings

- Reviewer `/root/v6_architecture` 与全部实现者不同、全程只读；首个详细报告被平台安全过滤器拦截，随后仅返回去敏 findings 摘要。审查证据：全量 `121 passed, 1 skipped`、覆盖率 `94.35%`；根仓库 validate 通过并有 6 条 legacy warning；设计包示例 validate 失败；Schema 与 lock 15/15 digest 一致；迁移合法性/replay 两项失败；脏工作区 Evidence 绑定复现失败。结论：15 个 P1、2 个 P2，拒绝 Close。
- `RV6-001`（P1 / governance）：运行时状态机与 policy compiler 使用硬编码语义，未由冻结 workflow/config/ownership 单一事实源驱动，存在 policy digest 与实际执行漂移。
- `RV6-002`（P1 / governance）：多条 Scope/WU/Evidence/Finding/Approval 写命令绕过 lease、revision、idempotency 或 event-first，actor 权限可由调用参数自报。
- `RV6-003`（P1 / governance/security）：Review L2 未验证 actor/provider/model/runtime/只读能力/commit 参与；判定所需字段不在严格 Run Schema，缺失时 fail-open。
- `RV6-004`（P1 / governance/security）：Risk Acceptance 未按 confirmed security/data/compliance/independence 强制不可豁免，仅依赖 Finding `invalidates` 字符串交集。
- `RV6-005`（P1 / governance）：Scope Guard 依赖 Scope Schema 不允许的 `governance_sensitive_approved`，合法治理批准无法以 schema-valid 形式表达。
- `RV6-006`（P1 / governance/platform）：终态 validator/report 未复用完整 Close Engine 重算当前 subject、policy、Scope、Evidence、Review、Finding、waiver 与 actor 权限。
- `RV6-007`（P1 / platform）：原样 `examples/v6` 被当前 replay/validate 拒绝，权威示例与实现不兼容。
- `RV6-008`（P1 / platform/migration）：v5 converter 生成违反 Schema 的 Scope，且 `task.yaml` 与同一 Event replay 不一致。
- `RV6-009`（P2 / platform/migration）：v5 scan 未完整覆盖状态、角色/workflow 引用、ownership ambiguity、逐实体源路径/digest 与可验证回滚矩阵。
- `RV6-010`（P1 / platform/evidence）：dirty workspace 的命令 Evidence 可错误绑定旧 HEAD；promotion 未证明 tree/index/untracked/special-path 与目标 commit 等价。
- `RV6-011`（P1 / platform/storage）：Task 创建 Event/projection 与 Scope 分开写，故障可留下半创建 Task；过期 lease 接管不是原子 compare-and-replace。
- `RV6-012`（P1 / platform/scope）：Result 仅检查 Task Scope，未同时检查 Work Unit allowed paths、owner 与实际 Git diff。
- `RV6-013`（P1 / platform/security）：submodule/LFS/symlink/case/Unicode 与不可信 YAML 的边界/subject/受限解析不完整。
- `RV6-014`（P1 / devex/integration）：plain-terminal adapter 读取 `policy_ref.digest`，而 Task 契约使用 `combined_digest`，handoff 会丢失冻结策略身份。
- `RV6-015`（P1 / devex/integration）：PR Task ID 解析会丢失合法 slug，CI 未真正执行其声明的 current commit-bound Evidence gate。
- `RV6-016`（P1 / devex）：doctor repair-safe 以宽泛扩展名删除 Task 树文件，未证明目标是已知原子写临时产物。
- `RV6-017`（P2 / devex/governance）：doctor 诊断矩阵、audit bundle 独立 verify、Schema lock 在启动/validate/build 的强制核验不完整。

## residual_risks

- Round 5 已按 Platform、Governance/Security、DevEx/Integration owner 使用全新上下文返工 `RV6-001..017`；Round 6 另修复 Schema bundle fallback 与 `mac init` 默认 ownership 兼容回归。目标与相邻回归通过，但默认全量仍被 Schema lock fail-closed。
- 首次最终 L2 Reviewer 产生 `FND-L2-001..003`：actor/runtime provenance 自报、orphaned CAS 无恢复、Schema lock stale。Round 7 已完成可信实体/Event 关联与 CAS recovery 返工；第二次 L2 增量审查确认 `FND-L2-002` 已解决。
- `FND-L2-001` 仍为 `partial`：公共 CLI 已拒绝 actor/provider/model/read-only/commit participation 自报，但当前 application verifier port 本身没有不可伪造的外部信任根；普通 Python 调用者仍可注入 verifier/context。该项继续阻断 approved scope、independent review 与 Close。
- `FND-L2-004`（blocker / compatibility+governance / block_close / confirmed，owner: platform+devex，status: open）：为堵住自报，`mac scope approve`、`approval record`、`finding waive` 与 Close 当前无实际生产 verifier 时始终返回 `EXTERNAL_AUTHORITY_REQUIRED`，删减了设计包要求的首期 CLI 能力。需要用户选择签名/OIDC、OS principal 映射或受信 runtime/human-gate adapter 等外部信任机制；在未选择前不得擅自扩展公共契约。
- `FND-L2-003`（blocker / policy_integrity / block_close / confirmed，owner: governance+security，status: waiting_external）：`approval.schema.json`、`common.schema.json`、`run.schema.json` 与 `.agents/schemas.lock.json` 三个摘要不一致。安全审批已拒绝自动更新治理锁；必须获得用户明确治理授权后机械重建并重新执行默认全量、`mac validate`、migration/examples 与 release gate。
- Gate 0 试点 owner/预算、托管跨平台 CI、三项目 30 Task、Enforced 两周、正式发布/签名仍需外部完成。
- Windows symlink case 因当前权限跳过，需托管 Windows CI 或具备 symlink 权限的环境验证。
- `pathspec` 当前发出 GitWildMatch API deprecation warning；语义测试已通过，但升级前需迁移到新 API。

### 返工轮次

- Round 1 `/root/v6_repair_r1_platform`：修复 FND-R1-001；只修改 repository/migration 与对应测试；完成。
- Round 2：为 FND-R2-001 创建全新 Platform Repair 上下文；只允许修改 baseline 工具与对应测试。
- Round 2 `/root/v6_repair_r2_baseline`：修复 FND-R2-001；只修改 baseline 工具与目标测试；完成。
- Round 3：Integrator 产生 FND-R3-001..006；同属 platform owner，创建全新上下文统一修复，必须重跑标准 lifecycle、revision 冲突、Scope/Close、JSON error、init validate 与失效测试。
- Round 3 `/root/v6_repair_r3_integration`：仅修改授权的 CLI/Git/Repository/Result/Scope/State 与回归测试，完成 FND-R3-001..006。
- Round 4：独立 Integrator 新增 FND-R4-001..002；同属 platform owner，必须由全新返工上下文修复 CLI 退出码传播与 Work Unit/Close 数据完整性，并重跑对应真实 CLI 生命周期、目标测试与全量测试。
- Round 4 `/root/v6_repair_r4_close_exit`：仅修改授权的 CLI/Event/Repository/Result/State 与邻近测试；实现者验证与独立 Integrator 增量复验均完成。
- Round 5：最终 Reviewer 产生 `RV6-001..017`。主 Agent 已按 owner 规划全新 Platform、Governance/Security、DevEx/Integration 返工上下文；新建线程被运行时硬限制阻止，未产生任何 Round 5 业务代码修改，任务进入 `blocked`。
- Round 5/6：在后续可用的全新上下文中完成 `RV6-001..017`、Schema fallback 与 init ownership 返工；目标/相邻回归通过，默认全量覆盖率 `91.41%`，锁更新前全量未通过。
- Round 7：完成 `FND-L2-001` 的 CLI fail-closed/verified Event 关联返工（40 项窄回归）和 `FND-L2-002` CAS recovery 返工（16 项窄回归）。
- 第二次 L2 增量审查：`FND-L2-002 resolved`；`FND-L2-001 partial`；`FND-L2-003 open/waiting_external`；新增 `FND-L2-004 open`。任务进入 `waiting_input`，等待用户选择外部 authority verifier 信任根并明确授权是否更新治理 Schema lock。
