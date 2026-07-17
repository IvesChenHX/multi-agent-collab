# 数据保留与隐私

## 数据分类与默认保留

| 数据 | 分类 | 默认位置 | 默认保留 |
| --- | --- | --- | --- |
| task 文本与治理元数据 | internal | Git 仓库 | 随项目历史长期保留 |
| task event | internal/按内容升级 | Git 仓库 | 长期保留 |
| CLI diagnostic | 不含任务内容 | 用户本地目录 | 7 天 |
| raw run log | confidential | `private/` 或外部 store | 30 天 |
| secret | 禁止 | 不得写入上述位置 | 不保留 |
| 用户 PII | restricted | 仅经批准的 store/manifest | 按项目政策 |

源码按项目自身策略分类。原始日志不得记录 secret、完整模型隐藏推理或未经批准的敏感源码片段。`private/` 不提交 Git；重要原始证据应配置外部 artifact store，同时在 Git 中只保留 digest、引用和 retention metadata。

## Telemetry

默认关闭。启用时只允许 CLI/version、command 类型、duration、error code、mode 和匿名计数；不得发送 task 标题、路径、源码、prompt、result 或 evidence 内容。

## 删除、归档与恢复

- 删除本地 raw log 不删除 Git 中的 digest/引用；过期引用必须标记不可取回，必要时重跑 evidence；
- 大量 event 可做 signed compaction/export，但原始事件只能归档，不能静默删除；
- audit bundle 必须含 redact manifest、artifact digest 和 bundle digest，可选签名；
- 卸载 CLI 不删除项目元数据；
- 合规项目的强制保留、中心身份撤销和外部归档需要企业 CI/身份/artifact 系统，local-only CLI 不能替代。
