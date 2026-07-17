# 安装

## 支持前提

- Python 3.11–3.13；
- Git 2.39+；
- Linux、macOS 或 Windows 11 PowerShell；
- 能写入项目内治理目录；`private/` 应保持在 Git 之外。

当前仓库尚未完成 PyPI/GitHub Release 外部门禁，因此不能把下面的发布安装命令视为已经可用。发布完成后，优先使用隔离工具安装固定版本：

```bash
uv tool install "multi-agent-collab==X.Y.Z"
```

或：

```bash
pipx install "multi-agent-collab==X.Y.Z"
```

从已下载的 wheel 安装前，先核对 `SHA256SUMS`，并在 GitHub CLI 支持 attestation 的环境中验证 provenance：

```bash
gh attestation verify multi_agent_collab-X.Y.Z-py3-none-any.whl --repo OWNER/REPO
uv tool install ./multi_agent_collab-X.Y.Z-py3-none-any.whl
```

开发检出只用于开发和验证，不等同于发布安装：

```bash
uv sync --locked --extra test
uv run --frozen mac --help
```

## 安装后检查

在目标仓库运行：

```bash
mac doctor --json
mac validate --json
```

`doctor` 只检查环境。需要修复安全临时状态时使用 `mac doctor --repair-safe`；该命令不得接受风险、批准 scope 或改变任务业务状态。若仓库仍是 v5，先按[升级与迁移](upgrade.md)执行只读扫描。

## 卸载

卸载 CLI 不删除项目内 task/event 元数据，也不删除 `private/`：

```bash
uv tool uninstall multi-agent-collab
```

项目数据的删除属于独立的数据保留决策，见[数据保留与隐私](data-retention.md)。
