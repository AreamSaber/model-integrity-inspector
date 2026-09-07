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

在实现提交 `42243d859cd721540cc7a47ad75b02ee0b75a1f3` 上运行：

```powershell
./scripts/verify-m0-04.ps1
```

验证器重新执行静态检查、漏洞扫描、版本化打包和本地 CycloneDX SBOM，并核对 manifest、文件哈希、CI SHA pin、Docker 基础镜像 digest 与分支保护策略。实际结果：

```text
M0-04 local verification passed.
CI: triggers=push+pull_request, actionlint=passed, actions=15-sha-pinned, gate=m0-04-required
Quality: gofmt=passed, go-vet=passed, golangci-lint=passed, powershell=passed, oxlint=passed, tests=passed
Security: govulncheck=passed, pnpm-audit=passed, trivy=ci-defined
Artifacts: version=0.1.0-dev, commit=42243d859cd7, manifest=verified, checksums=present, sbom=cyclonedx
External: origin=missing, docker=missing, branch-protection=not-verified-locally
Task status: M0-03=pending-review, M0-04=in-progress
```

制品证据：

- Windows amd64 二进制 SHA-256：`8820e453ebe7b5201d241ca00f927292c3e357bdc081edbe6277cda763d3e05d`；
- Web ZIP SHA-256：`75357800e7b31a859fa1f54a243ca3f0ef96e5fd9bf6585f9f63d3d4ce55a14f`；
- manifest SHA-256：`6511bc1399345adb59a9f609336d26e735cd56c0c0ab58f40a17070cc9d922b4`；
- CycloneDX 1.7 源码 SBOM：123 个组件，SHA-256 `3baeca1da2d192f914b2e5feca5ecde9a3394217cdbfbf6bd1f2bbbd24600ec8`。

上述本地验证提交（`42243d859cd721540cc7a47ad75b02ee0b75a1f3`）的关键实现 SHA-256：

```text
4d51b7798e04926a94c01af49a3318efbc05fed1251e4e9142dc45ec89d66e03  .github/workflows/ci.yml
9a599ebf2b256bd9201b6e6950e7efc46dd7d631f77a06943eaeea86876b04c1  .github/branch-protection/main.json
6c69ce2b92ed2e9ce74b3997270e807f2185cfa9a1af915b419a58f1b113acb9  Dockerfile
361fe3107d3a761a03a25d0f1c6bab39458b9664ec875ba9cd3762271e584305  scripts/lint.ps1
366f4eb66aae8e8b29578015a29efc2b38bd3b53548d527bbffe9ac2d2c559b4  scripts/security-scan.ps1
5a127c20146e7f24dd236edbe06bb94f5e83d699567e6db5b91b3dcfb4bf76a4  scripts/package.ps1
2381436f0cc00de4803dd4e807c9da72ca573ce36fcd9ea7b5ce2de727475d9b  scripts/generate-sbom.ps1
5e199a630a68c7eb779cbad8c6e6f30dc0bf9de6f61ff45d9b9441b3788a5861  scripts/verify-m0-04.ps1
08fa6bceef71cbc6a3dcd7c632bb7e91b2176adc9cdea4deb6ec8c352946aa69  web/package.json
e928e623c42234e35352a9f7deaa8d537d8ce7c3378e7d4b6dc8615b6f473ebb  web/pnpm-lock.yaml
```

## 远端验证（2026-09-07）

- 已创建私有仓库 [AreamSaber/model-integrity-inspector](https://github.com/AreamSaber/model-integrity-inspector)，配置 `origin` 并推送 `main`；GitHub CLI 登录账号为 `AreamSaber`，仓库权限为 `ADMIN`。
- [首次 push CI](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34071845489) 在提交 `5871477753656af9b09fdf79457466f9abb30e49` 上运行：Linux/Windows 打包、依赖扫描、镜像构建、镜像 SBOM 和 Trivy 镜像扫描通过；Linux runner 上 actionlint 调用 ShellCheck，发现变量未加引号及重复输出重定向，质量任务失败，`m0-04-required` 随之失败。
- 提交 `b8593440cdd972a32d403db4348d078f78c818fb` 修复了以上 ShellCheck 问题；未关闭检查或降低扫描阈值。该提交的工作流文件 SHA-256 为 `7dd97ef63e1eddfc43164fcb71e85e617caa2d2c97d81669d055495be9d6b83a`。
- [修复后的 push CI](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34073862307) 已完成且结论为 `success`：`quality`、`dependency-scan`、`package-ubuntu-24.04`、`package-windows-2025`、`image`、`m0-04-required` 六项任务全部通过。
- [真实 pull_request 运行记录](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34071928955) 由 Dependabot PR 触发，证明 PR 事件已接入；该运行使用修复前的工作流且结果为失败，不作为成功构建证据。未合并这些依赖升级 PR。

成功运行上传了以下四个制品。表中摘要由 GitHub Artifacts API 返回，表示上传制品归档的 SHA-256；不是归档内单个二进制或 SBOM 文件的摘要。

| 制品（共同提交：`b8593440cdd972a32d403db4348d078f78c818fb`） | 归档 SHA-256 |
|---|---|
| Windows 包 | `2fa9176a0970649e69694ca500ad235f5b9e5939bd8b812747e4d4fbee213aef` |
| Linux 包 | `5fa1b24de6d49708cc72216e9faf4ceb9964a364840c5355788c6f3692bc982a` |
| 源码 CycloneDX SBOM | `96e6371d55997cc47a3b287013011030327ab867ee19cfd44285fc1cbdd307c7` |
| 镜像 CycloneDX SBOM | `15137ba31a40262b5cde211da32f1a982454c5d638ca75e3ece3cdf9f416089c` |

分支保护读取请求 `GET /repos/AreamSaber/model-integrity-inspector/branches/main/protection` 返回 HTTP 403：`Upgrade to GitHub Pro or make this repository public to enable this feature.` 这是私有仓库的套餐能力限制；账号已登录且拥有管理权限。分支保护尚未应用，仓库保持私有。

## 尚未关闭的外部条件

1. M0-03 仍为“待审核”，尚未满足 M0-04 的正式依赖状态；
2. 当前账号套餐不支持该私有仓库的分支保护，需要具备该能力后应用并回读策略，才能满足“CI 失败阻止合并”的服务端强制要求。现有聚合任务会正确报失败，但不能代替分支保护。

## 当前结论

仓库已连接 GitHub，远端 CI 六项任务全部通过，版本化制品、源码/镜像 SBOM、镜像构建与扫描已有真实运行证据。本地未安装 Docker 不再阻塞这些验证。分支保护仍受私有仓库套餐限制，M0-03 依赖仍待批准，因此 M0-04 保持“进行中”，暂不提交最终审核。
