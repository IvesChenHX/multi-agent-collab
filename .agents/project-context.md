# 项目上下文基线

- 项目：`multi-agent-collab` v6，供应商中立的 local-first、Git-native 开发治理内核。
- 实现语言：Python 3.11+；正式支持目标为 Python 3.11–3.13、Linux/macOS/Windows。
- 产品边界：规则、Task/Scope/Event/Run/Result/Evidence/Finding/Approval、Scope Guard、Close、Runtime Handoff、迁移、报告和 CI；不托管模型循环、DAG、凭据、沙箱、自动合并或部署。
- 存储：每个 Event 独立文件，Event 是恢复来源，`task.yaml` 是投影；ULID 去中心化创建，不维护可写中心编号器。
- 规则：`AGENTS.md` 是人类策略；`.agents/config.yaml`、workflow、ownership、runtime profiles 和 `schemas/**` 是机器契约；活动 Task 冻结 policy/ownership digest。
- 默认采用等级：`advisory`。真实 Gate 2 前不得切换 `enforced`。
- 默认 quick 阈值：5 个文件、200 行、单 owner、目标验证；治理、安全、数据、公共契约、生产和跨服务变化必须升级。
- 默认 high-risk 独立性：L2；audit：L3。
- 原始日志默认不提交，保留 30 天；Telemetry 默认关闭；secret 禁止写入治理元数据。
- v5 历史位于 `.agents/legacy/**` 与 `tasks/index.yaml`，迁移期双读、只写 v6；缺少详细证据的任务只能标记 `metadata_only/unverifiable`。
- v1 仍需外部完成：三项目/30 任务 Pilot、托管跨平台 CI、至少一个项目 Enforced 两周、正式 Security Review、PyPI/GitHub Release、SBOM/Sigstore/OIDC provenance。
