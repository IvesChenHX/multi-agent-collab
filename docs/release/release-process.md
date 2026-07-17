# 发布流程

`.github/workflows/release.yml` 为候选发布提供以下真实门禁：

1. Linux/macOS/Windows × Python 3.11–3.13 测试与 repository validation；
2. tag 与 `project.version` 的 SemVer 一致性；
3. 从同一 tag 构建 wheel/sdist；
4. 生成 CycloneDX SBOM 和 `SHA256SUMS`；
5. 使用 GitHub OIDC 生成 Sigstore 签名的 build provenance 与 SBOM attestation；
6. 在受保护的 `release` environment 创建 GitHub Release；
7. 在受保护的 `pypi` environment 通过 trusted publishing 上传 Python distributions。

## 首次启用

repo owner 必须配置：

- `release` 与 `pypi` environments、所需 Reviewer 和 tag 保护；
- PyPI trusted publisher 与准确项目名；
- GitHub Actions 的 artifact attestation 支持；
- branch protection 中所需的 `Governance PR` job；
- 私下安全报告和支持入口。

这些外部配置、真实三项目试点、30 个任务、Gate 2、至少一个项目 enforced 两周、安全审查和迁移/回滚演练未完成时，不得标记 v1 Release Readiness 通过。

## 发布步骤

1. 确认 Definition of Done、release checklist 和独立安全审查真实完成。
2. 确认 `uv.lock` 与 `pyproject.toml` 同步，工作区无未提交文件。
3. 更新 release notes；明确 agtx/Conductor 仍为 experimental。
4. 创建与 `project.version` 一致的 annotated tag 并推送。
5. 观察全部 verify/build/attest/publish jobs；失败不得手工伪造产物补过。
6. 下载 artifact，核对 hash、SBOM、Sigstore bundles 和 GitHub attestation。
7. 分别演练全新安装、升级和回滚，并保存真实 evidence。

workflow 配置存在不代表 CI、签名、PyPI 或 GitHub Release 已经通过。只有外部 run URL、artifact digest、attestation 与演练记录构成证据。
