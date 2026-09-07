# M0-04 CI 与分支保护运行手册

## CI 门禁

`.github/workflows/ci.yml` 在 `main` 的 push、面向 `main` 的 pull request 以及手工触发时运行。稳定门禁名为 `m0-04-required`，只有以下任务全部成功时才成功：

- `quality`：gofmt、go vet、经 SHA-256 校验的 golangci-lint 2.13.2、PowerShell 语法、actionlint 1.7.12、Oxlint、单测和构建；
- `dependency-scan`：固定版本 govulncheck 1.7.0、pnpm audit、Trivy 仓库扫描和 CycloneDX 源码 SBOM；
- `package-*`：Linux/Windows 版本化二进制、前端包、manifest 和 SHA-256；
- `image`：固定基础镜像 digest 的容器构建、OCI 版本标签、镜像 SBOM 和 Trivy 扫描。

所有第三方 Action 使用完整提交 SHA；标签只作为旁注。工作流默认只有 `contents: read` 权限，不读取部署 Secret，也不发布镜像。

## 本地等价命令

```powershell
./scripts/lint.ps1
./scripts/security-scan.ps1
./scripts/package.ps1
./scripts/generate-sbom.ps1
```

生成物位于被 Git 忽略的 `artifacts/`。二进制内嵌 `VERSION`、完整 Git commit 和提交时间；manifest 和 `SHA256SUMS` 记录同一版本身份。

## 应用分支保护

首次 CI 成功且仓库套餐支持分支保护后，由拥有仓库管理权限的人员执行：

```powershell
./scripts/apply-branch-protection.ps1 -Repository AreamSaber/model-integrity-inspector
```

脚本把 `.github/branch-protection/main.json` 应用到 `main`，随后读取远端配置并确认 `m0-04-required` 已成为必需检查。策略同时要求分支为最新、至少一次批准、最后一次推送后重新批准、解决全部对话，并禁止强推和删除。

仅预览请求而不修改远端：

```powershell
./scripts/apply-branch-protection.ps1 -Repository AreamSaber/model-integrity-inspector -Preview
```

## 当前外部前置条件

2026-09-07 已创建私有仓库 [AreamSaber/model-integrity-inspector](https://github.com/AreamSaber/model-integrity-inspector)，本地 `origin` 已指向该仓库，`main` 已推送。GitHub CLI 已登录 `AreamSaber`，远端确认账号具有 `ADMIN` 权限。

GitHub 分支保护 API 当前返回 HTTP 403：`Upgrade to GitHub Pro or make this repository public to enable this feature.` 因此缺少的是私有仓库的套餐能力，分支保护尚未应用。仓库保持私有；启用支持该功能的套餐后，再运行上述脚本并回读验证。CI 中的聚合检查失败不能代替 GitHub 服务端的强制合并限制。

Docker 镜像构建、OCI 标签验证、镜像 SBOM 和 Trivy 扫描已在 GitHub 托管 runner 上实际执行；本地未安装 Docker 不再阻塞取得这些验收证据。CI 运行证据见 `docs/reviews/M0-04-review.md`。M0-04 提交最终审核前，仍须完成 M0-03 正式批准、CI 验收以及分支保护应用和回读。
