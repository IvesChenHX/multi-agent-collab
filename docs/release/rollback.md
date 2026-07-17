# 回滚

回滚分为 CLI 回滚和仓库数据回滚，两者必须分别验证。

## CLI 版本回滚

安装前一个已知可用版本：

```bash
uv tool install --force "multi-agent-collab==PREVIOUS_VERSION"
mac doctor --json
mac validate --json
```

旧 CLI 只能按其兼容窗口读取新 Schema。若新版本已经写入旧版本不支持的格式，不得继续写入；先恢复迁移前数据或使用支持该 Schema 的版本导出诊断信息。

## v5 → v6 数据回滚

迁移前必须存在 `pre-v6-migration` tag 和独立迁移分支。迁移器只新增 v6 目录并调整治理配置，不删除 v5 文件。发生问题时：

1. 停止所有写入和外部 run；
2. 保存失败诊断、迁移报告及当前 commit；
3. 切回迁移前 tag 或对迁移 commit 执行可审查的 Git revert；
4. 恢复不在 Git 中的 `private/` 证据引用；
5. 用旧版本执行只读验证；
6. 抽样比对任务数量、legacy ID 与原始报告。

不得用删除事件或手工改 projection 的方式回滚。若 event 已写而 projection 未写，使用 safe repair 重放；revision gap 或损坏 event 必须 fail closed，保留原文件并交由人工恢复。

## 发布回滚

PyPI 版本不可原地覆盖。发现发布缺陷时应停止推广、标记受影响版本、发布修复版本，并在 GitHub Release 中记录兼容和数据影响。已经生成的 provenance、SBOM 与签名不得替换或伪造；新构建必须产生新的 digest 和 attestation。
