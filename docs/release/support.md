# 支持策略

## v1 支持矩阵

| 项目 | 支持范围 |
| --- | --- |
| Python | 3.11、3.12、3.13 |
| Git | 2.39+ |
| Linux | x86_64、arm64 |
| macOS | arm64、x86_64 |
| Windows | Windows 11 PowerShell |
| plain-terminal adapter | stable |
| agtx adapter | experimental |
| Conductor compiler | experimental |

核心治理能力不得依赖 experimental adapter。Conductor 和 agtx 的宿主版本变化可能导致原型映射失效；此时回退到 plain-terminal handoff，不能放宽治理 gate。

## 获取诊断

```bash
mac doctor --json
mac report bundle --diagnostic --redact
```

诊断包默认只包含配置结构、版本、错误码和脱敏 manifest，不包含 task 内容、源码、prompt、result、evidence 内容、secret 或隐藏推理。提交问题时附：

- CLI/Python/Git/OS 版本；
- 稳定错误码与脱敏路径；
- 可重复步骤；
- `doctor` 的脱敏 JSON；
- 是否涉及 migration、symlink/case、worktree 或外部 adapter。

普通缺陷可使用仓库 issue。疑似漏洞不得提交公开复现，按[安全说明](security.md)私下报告。仓库 owner 在公开发布前必须配置明确的支持入口、响应责任人与 GitHub Security Advisory 流程；当前设计包不构成服务等级承诺。
