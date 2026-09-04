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

关键实现 SHA-256：

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

## 尚未关闭的外部条件

1. M0-03 仍为“待审核”，尚未满足 M0-04 的正式依赖状态；
2. 本地仓库没有 `origin`，无法产生真实 push/pull request CI 运行记录；
3. 当前环境没有 GitHub CLI/管理权限，分支保护尚未应用和回读；
4. 当前环境没有 Docker，镜像构建和 Trivy 镜像扫描只能在远端 CI 首次运行后形成证据。

## 当前结论

仓库内实现和本地可验证部分完成，但远端 CI、镜像任务和分支保护尚无真实运行证据，且 M0-03 依赖仍待批准。因此 M0-04 保持“进行中”，暂不提交最终审核。
