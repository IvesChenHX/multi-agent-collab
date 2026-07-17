# Multi-Agent Collaboration Governance Core

本仓库正在按 `multi-agent-collab-v6-design-package/` 落地 v6：一个 local-first、Git-friendly、供应商中立的多 Agent **治理内核**。它负责 task/event、scope、ownership、evidence、review、risk、runtime handoff 和可重复验证，不负责托管模型、TUI、通用 CI/CD、完整工作流调度或安全沙箱。

当前默认治理等级是 `advisory`。真实三项目试点、跨平台托管 CI、PyPI/GitHub Release、Sigstore/OIDC 发布和 enforced 两周均是外部门禁；仓库中存在实现或 workflow 配置不代表这些门禁已经通过。

## 运行边界

- Python 3.11–3.13，Git 2.39+；
- Linux、macOS、Windows 11 PowerShell 为 v1 目标平台；
- 每次 CLI 调用完成一个事务，无 daemon；
- standard/high-risk/audit 元数据进入 Git，raw log 默认进入 `private/` 或外部 artifact store；
- high-risk 缺少最低独立 Review 时 fail closed；
- Agent 或外部 runtime 的“成功”不是 evidence，也不是 Task Close。

## 开发检出

项目尚未发布到 PyPI。开发环境使用锁文件：

```bash
uv sync --locked --extra test
uv run --frozen mac --help
uv run --frozen mac doctor --json
uv run --frozen mac validate --json
uv run --frozen pytest
```

发布后安装、升级和回滚分别见 [install](docs/release/install.md)、[upgrade](docs/release/upgrade.md) 与 [rollback](docs/release/rollback.md)。

## v6 命令面

```text
mac init
mac doctor
mac validate
mac policy compile
mac classify
mac task new|show|list|transition|cancel|supersede|rebuild
mac scope propose|approve|amend|check
mac work-unit new|ready|show
mac run register|finish|inspect
mac result submit|validate
mac evidence record|promote|invalidate|list
mac finding open|resolve|waive|list
mac approval record|verify
mac handoff build|collect
mac report render|bundle
mac index build
mac migrate v5-to-v6
```

所有命令支持 `--json`；写命令支持 `--idempotency-key` 与 `--expected-revision`。CI 禁止交互式补参。稳定退出码为 0、2–11 和 20，具体含义以设计包 `docs/09-cli-api-and-exit-codes.md` 为准。

## Runtime adapters

- `plain-terminal`（stable）：生成自包含 handoff、导入标准 Result；没有 launch/inspect/cancel。
- `agtx`（experimental）：映射 work unit、worktree 与 artifact；agtx 管 session，MAC 管 gate。
- `Conductor`（experimental）：把选定 work unit DAG 编译为 workflow；Conductor 管执行，MAC 仍判定 Close。

运行时能力不足时使用人工 handoff 和确定性等待状态，不能自审或静默降级 gate。

## CI 与发布

- `Cross-platform CI`：Linux/macOS/Windows × Python 3.11–3.13 的 validate/test/build；
- `Governance PR`：使用 PR base/head 执行 repository validate、scope check 与 commit-bound evidence 校验；
- `Release`：矩阵重验、wheel/sdist、hash、CycloneDX SBOM、Sigstore provenance/SBOM attestation、GitHub Release 与 PyPI trusted publishing。

初始 `advisory` 只报告 governance finding；切为 `enforced/regulated` 后缺 task、scope 或 evidence 必须阻塞。外部配置和真实执行要求见 [release process](docs/release/release-process.md)。

## 文档

- [支持矩阵](docs/release/support.md)
- [兼容策略](docs/release/compatibility.md)
- [安全说明](docs/release/security.md)
- [数据保留与隐私](docs/release/data-retention.md)
- [发布流程](docs/release/release-process.md)
- [人类硬门禁](AGENTS.md)

v5 → v6 迁移始终先只读扫描；历史缺证据时保留 `metadata_only/unverifiable`，不得生成伪造 evidence。任务具体 scope、验证、外部门禁和残余风险以对应 task 记录为准。
