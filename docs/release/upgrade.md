# 升级与迁移

CLI 使用 SemVer；Schema、policy format 和 runtime profile 各自带版本。升级不能隐式重写仓库状态。

## 升级前

1. 确认工作区没有未解释的变更，并备份 `tasks/`、`.agents/` 和重要的 `private/` 外部证据。
2. 记录当前 CLI 版本、policy/ownership digest 和 Git commit。
3. 运行 `mac validate --json` 与 `mac doctor --json`，保存真实结果。
4. 遇到 breaking change 时，先阅读 release notes、迁移器和[回滚说明](rollback.md)。

安装目标版本后再次运行 `doctor` 和 `validate`。最近两个 major schema 只读兼容，最近一个 major 支持写入与迁移；超过该窗口必须先安装中间版本，不得直接改文件绕过迁移器。

## v5 → v6

迁移必须先扫描、后写入：

```bash
mac migrate v5-to-v6 --scan --report migration-report.json
```

扫描是只读操作。写入迁移前创建独立分支和 `pre-v6-migration` tag，暂停新的 v5 standard/high-risk 任务，再执行经 owner 确认的迁移。迁移必须满足：

- 重复运行不生成重复任务；
- 每个产物保存 source path 与 digest；
- v5 文件不被迁移器删除；
- 缺失详细证据的历史任务标记 `legacy_integrity: metadata_only` 和 `verification_status: unverifiable`；
- `blocked` 由人判断映射为 `waiting_input`、`waiting_external` 或 `failed`，不能机械映射；
- 不创建伪造的 passed evidence。

切换期 CI 双读 v5/v6：v5 只读、新任务只写 v6。真实样本的重复迁移与回滚演练未完成前，不得删除 legacy workflow 或切换为 enforced。
