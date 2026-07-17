# Gate 3 / v1 发布报告

状态：`waiting_external`。

## 必需证据

- Gate 2 通过；
- 至少一个项目 Enforced 连续运行两周；
- Linux/macOS/Windows 与 Python 3.11–3.13 托管 CI；
- 正式 Security Owner 关闭 threat review，无已知 P0/P1；
- install/upgrade/rollback 演练；
- PyPI/GitHub Release、wheel/sdist hash、SBOM、Sigstore/OIDC provenance；
- 支持、漏洞报告、数据保留、兼容与弃用策略发布。

本地 fixture、内部自检或未发布 workflow 不能替代上述证据。
