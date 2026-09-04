# Model Integrity Inspector

Model Integrity Inspector（模型真实性检测系统）是一个独立部署的模型 API 完整性检测工具。本仓库当前进入 M0-04 工程交付基线阶段，提供可编译的 Go 单一制品骨架、React + TypeScript 管理端、双数据库迁移目录、规则目录、测试入口、CI、安全扫描、SBOM 和部署目录。

## Toolchain

- Go 1.26.7（`.go-version` 与 `go.mod` 锁定）
- Node.js 24.19.0（`.nvmrc` 锁定）
- pnpm 11.19.0（`web/package.json` 锁定）

Windows 环境可先运行 `./scripts/bootstrap-toolchain.ps1`，在仓库私有且被忽略的 `.tools/` 中安装经 SHA-256 校验的 Go。Node/pnpm 由开发环境提供，不进入仓库制品。

## One-command verification build

```powershell
./scripts/build.ps1
```

该命令安装锁定的前端依赖、执行前端测试与生产构建、运行全部 Go 测试，并生成 `artifacts/mii.exe`。

## Quality, security, and packaging

```powershell
./scripts/lint.ps1
./scripts/security-scan.ps1
./scripts/package.ps1
./scripts/generate-sbom.ps1
```

CI 定义位于 `.github/workflows/ci.yml`，稳定合并门禁为 `m0-04-required`。分支保护的应用方法见 `docs/operations/M0-04-CI-AND-BRANCH-PROTECTION.md`。

## Run locally

```powershell
./scripts/run-server.ps1
./scripts/run-worker.ps1
./scripts/run-web.ps1
```

Server 默认监听 `127.0.0.1:8080`，提供 `/health`、`/ready` 和 `/version`。前端开发服务器默认监听 `127.0.0.1:5173`。当前 Worker 仅验证角色启动与优雅退出，数据库 Job 实现在 M1-06 交付。

## Repository boundaries

- `cmd/mii`：唯一 Go 可执行入口，通过 `APP_ROLE=server|worker|all` 切换运行组件。
- `internal/integrity`：领域和应用模块；禁止从其他业务项目导入源码。
- `web`：React + TypeScript + Vite 管理端。
- `migrations/sqlite`、`migrations/postgresql`：双数据库迁移；M1-01 开始加入正式 schema。
- `rules`：版本化规则、模板和 tokenizer 包；M3 开始发布实际 bundle。
- `tests`：集成、契约和 mock upstream 测试资产。
- `deploy`：单机与 Docker Compose 交付资产。

设计与验收基线见根目录 PRD、TECH SPEC、开发计划和 `docs/architecture`。
