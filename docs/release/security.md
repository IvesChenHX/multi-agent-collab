# 安全说明

仓库内容、task 文本、prompt、result 和外部日志均视为不可信数据。只有经过验证的 policy、scope、CI identity、runtime adapter 或人工 Reviewer 才能提供治理事实。

## 默认安全边界

- CLI 默认不执行任意 shell；命令证据保存 argv，禁止 `eval`；
- plain-terminal adapter 只 build/collect，不启动、检查或取消进程；
- handoff 明确分隔权威治理上下文与不可信任务文本；
- Agent 自报“通过”不是 evidence，外部 runtime 成功也不是 Task Close；
- secret 禁止进入 Git task 元数据、handoff、result、evidence 和 raw log；
- raw log 默认放在 `private/` 或外部 artifact store；
- high-risk 缺少所需独立审查时 fail closed；
- risk acceptance 不能覆盖 approved scope、当前 commit/policy evidence、high-risk 独立审查或数据完整性；
- path traversal、symlink/junction、case、Unicode、submodule、rename old/new path 均必须在 scope guard 中处理；
- telemetry 默认关闭，并禁止上传标题、路径、源码、prompt、result 或 evidence 内容。

## 供应链

发布 workflow 使用最小 job 权限、隔离 build/publish、locked dependencies、wheel/sdist hash、CycloneDX SBOM、GitHub OIDC/Sigstore attestation 和 PyPI trusted publishing。只有真实 workflow run 产生的 URL、bundle 和 artifact digest 才是发布证据；仓库内配置文件本身不是通过证明。

验证已发布 artifact：

```bash
sha256sum --check SHA256SUMS
gh attestation verify ARTIFACT --repo OWNER/REPO
```

## 漏洞报告

优先使用仓库的 GitHub Security Advisory 私下报告，提供影响版本、攻击前提、脱敏复现和建议缓解。不要在公开 issue、task 元数据或日志中放入 secret、漏洞利用载荷或敏感源码。若仓库尚未启用私下报告，联系 repo/security owner；公开发布前必须补齐可用的私下渠道。
