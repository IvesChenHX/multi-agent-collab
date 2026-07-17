# 兼容策略

## 版本边界

- CLI：SemVer；
- task projection：当前 v6 使用 `schema_version: 6`；
- 其它 JSON Schema、runtime profile 和 policy format：按各自字段独立版本化；
- 最近两个 major schema 支持只读；
- 最近一个 major 支持写入与迁移；
- breaking change 必须提供迁移器与回滚说明。

读取兼容不代表旧 CLI 可以写新格式。遇到未知字段、revision gap、非法引用或不支持的 schema 时必须停止写入，不得静默丢字段。

## 平台

v1 目标是 Python 3.11–3.13、Git 2.39+、Linux x86_64/arm64、macOS arm64/x86_64、Windows 11 PowerShell。仓库配置了托管矩阵，但只有对应 GitHub Actions run 成功后才能声明平台通过。

## Runtime adapters

| Adapter | 等级 | 兼容承诺 |
| --- | --- | --- |
| plain-terminal | stable | 自包含 handoff 与标准 Result collect；无进程控制 |
| agtx | experimental | work unit/worktree/artifact 映射；agtx 管 session，MAC 管 gate |
| Conductor | experimental | 选定 work unit DAG 编译；Conductor 执行，MAC 判定 Close |

experimental adapter 的宿主协议变化不允许破坏 core task/event store。失败时回退到 plain-terminal handoff；外部 trace 只保存引用和 digest，供应商专有字段不进入核心格式。

## v5

迁移期支持 v5 只读、v6 写入。历史缺少 scope/verification 时保留 `metadata_only/unverifiable`，不能将 v5 终态重解释为 v6 verified。legacy workflow 保留一到两个版本周期后，只有试点和回滚门禁通过才能清理。
