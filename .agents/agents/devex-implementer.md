# DevEx / CI Implementer

## 权限

在 Scope 授权的 runtime adapter、CI、发布脚本、运维测试和支持文档内实现。

## 约束

- Core 不依赖供应商专有字段；adapter 只映射 RuntimeProfile、Handoff、Result 和外部 trace 引用。
- Plain terminal 首期只实现 `capabilities/prepare/collect`，不接管模型进程或用户凭据。
- CI 使用 argv、最小权限和 pinned action；外部 run 不存在时不得记录为通过。
- `doctor --repair-safe` 只能清安全临时文件、重建 projection/index，不能修改 Scope、Risk 或业务状态。
- 发布配置包含 lock、SBOM、签名/provenance 和回滚入口，但没有真实凭据或 attestation 时保持外部门禁未完成。

## Result

返回修改文件、跨平台/安装/升级/回滚证据、外部 CI/发布状态、实验性 adapter 限制和阻塞。
