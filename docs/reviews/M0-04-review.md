# M0-04 实施与审核记录

计划编号：M0-04  
负责人：OPS/SEC  
依赖：M0-03（当前待审核）  
当前状态：进行中

## 目标

建立提交可触发的 CI、静态检查、依赖漏洞扫描、版本化制品、CycloneDX SBOM、容器镜像构建和强制合并门禁。

## 已实现

- GitHub Actions 对 `main` push、pull request 和手工触发；
- `m0-04-required` 聚合门禁，任一质量、扫描、打包或镜像任务失败则失败；
- Go、PowerShell、GitHub Actions 和 TypeScript/React 静态检查；
- govulncheck、pnpm audit 与 Trivy 仓库/镜像扫描；
- Linux/Windows 版本化制品、内嵌版本/完整 commit/提交时间、manifest 和 SHA-256；
- Syft 1.51.1 CycloneDX 源码与镜像 SBOM；
- 固定 digest 的 Node/Go 容器构建阶段和 OCI 版本标签；
- GitHub `main` 分支保护策略模板、应用与回读脚本；
- Dependabot 对 Actions、Go、npm 和 Docker 的每周更新检查。

## 供应链锁定

| 工具/Action | 锁定版本 |
|---|---|
| golangci-lint | 2.13.2，Windows/Linux amd64 官方归档 SHA-256 固定 |
| govulncheck | 1.7.0，Go module checksum 验证 |
| actionlint | 1.7.12，Windows/Linux amd64 官方归档 SHA-256 固定 |
| Syft | 1.51.1，Windows amd64 官方归档 SHA-256 固定 |
| Trivy | 0.74.0 |
| GitHub Actions | 全部使用官方 release 对应的完整 40 位 commit SHA |
| Docker build stages | Node 24.19.0 / Go 1.26.7 多架构 manifest digest 固定 |

## 本地验证

本地已确认：

- gofmt、go vet、golangci-lint、PowerShell parser、actionlint 和 Oxlint 通过；
- Go/React 测试、TypeScript 检查和 Vite build 通过；
- govulncheck 无已知可达漏洞；pnpm audit 无已知漏洞；
- 脏工作树会被 package/SBOM 脚本拒绝，避免旧 commit 标记未提交源码；
- 分支保护 Preview 请求结构及必需检查名称正确。

最终提交后运行：

```powershell
./scripts/verify-m0-04.ps1
```

验证器会重新执行静态检查、漏洞扫描、版本化打包和本地 CycloneDX SBOM，并核对 manifest、文件哈希、CI SHA pin、Docker 基础镜像 digest 与分支保护策略。

## 尚未关闭的外部条件

1. M0-03 仍为“待审核”，尚未满足 M0-04 的正式依赖状态；
2. 本地仓库没有 `origin`，无法产生真实 push/pull request CI 运行记录；
3. 当前环境没有 GitHub CLI/管理权限，分支保护尚未应用和回读；
4. 当前环境没有 Docker，镜像构建和 Trivy 镜像扫描只能在远端 CI 首次运行后形成证据。

## 当前结论

仓库内实现和本地可验证部分完成，但远端 CI、镜像任务和分支保护尚无真实运行证据，且 M0-03 依赖仍待批准。因此 M0-04 保持“进行中”，暂不提交最终审核。
