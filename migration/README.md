# v5 → v6 迁移工具说明

`migrate_v5.py` 是设计包中的参考迁移器：

- 默认只扫描；
- `--apply` 写入独立输出目录，默认 `tasks-v6/`；
- 保留 v5 ID 为 `legacy_id`；
- 不生成验证通过的 Evidence；
- 缺少详细任务记录时标记 `metadata_only`；
- v5 `blocked` 默认映射为 `failed`，并要求人工分类；
- 重复运行根据 legacy ID 跳过已有任务。

它没有修改当前仓库配置、workflow 和 `.gitignore`，这些应在正式 PR 中由独立迁移步骤完成。

```bash
python migration/migrate_v5.py /path/to/repo --scan-report report.json
python migration/migrate_v5.py /path/to/repo --apply --output tasks-v6
```
