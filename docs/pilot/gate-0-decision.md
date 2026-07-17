# Gate 0 决策记录

## 已由本任务采用的设计默认值

用户要求严格按 `multi-agent-collab-v6-design-package/**` 落地且不得增删，因此本候选实现采用以下默认值：

- 产品定位：治理内核，不是完整 Agent 编排器；
- local-first、Git 元数据、Python 3.11+；
- Task Event 每事件一文件，`task.yaml` 为可重建投影；
- v5 历史允许 `metadata_only/unverifiable`，禁止伪造 Evidence；
- quick：5 文件、200 行、单 owner、目标验证；
- high-risk：最低 L2 Review，fail closed；
- 不可豁免：批准后的 Scope、当前代码/策略 Evidence、最低独立审查、数据完整性；
- 初始采用等级：`advisory`；
- task 元数据提交 Git，`report.md` 与 `private/` 默认忽略；
- raw log 默认保留 30 天，Telemetry 默认关闭；
- 支持目标：Linux/macOS/Windows，Python 3.11–3.13。

## 数据分类

| 数据 | 分类 | Git | 默认保留 |
| --- | --- | --- | --- |
| Task/Scope/Event/Finding/Approval 元数据 | internal | 是 | 项目历史期 |
| Result 与 command 摘要、artifact digest | internal | 是 | 项目历史期 |
| 原始日志 | confidential | 否 | 30 天，可配置 |
| 源码 | project_policy | 按项目策略 | 按项目策略 |
| secret/token | prohibited | 禁止 | 不保存 |
| 用户 PII | restricted | 默认禁止 | 由外部保留策略决定 |

## 尚待 Product/Repo Owner 外部确认

- [ ] 三个真实试点项目及各自 owner；
- [ ] Pilot Developer 与正式 Human/Security Reviewer；
- [ ] 实施预算；
- [ ] Stop/Go 负责人；
- [ ] 外部 artifact retention、身份与签名基础设施；
- [ ] Gate 2/3 的最终批准人。

这些项目未完成前只允许 `observe/advisory`，不得把候选实现声明为 v1 生产就绪。
