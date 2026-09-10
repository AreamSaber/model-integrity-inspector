# Model Integrity Inspector

Model Integrity Inspector（模型真实性检测系统）是一个独立部署的模型 API 完整性检测工具。当前集成分支正在开发 V1.0，主线推进到 M6-05 备份恢复；尚不是完整候选版或正式发行版。

实际应用已验证初始化、登录、目标配置、受控 TLS 预检、预算确认、Worker 检测、分析与证据下钻，以及 JSON/HTML/CSV 报告生成和下载。使用 Go 后端、嵌入式 React + TypeScript 管理端、SQLite/PostgreSQL 和数据库 Job 队列，不依赖其他业务项目源码。

当前仍在补齐完整备份恢复、可信基线评分与规则生命周期、报告其余能力、独立算法校准、部署运维及系统验收。算法仍为开发/未校准状态，不能把测试场景通过当成真实性认证或正式算法验收。各任务的真实证据、已知缺陷和下一步见 [持续开发台账](docs/project/V1.0-持续开发台账.md)，以其顶部最新记录为准；原计划中的正式审核状态与开发进度分别记录。

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

本地 SQLite 必须使用 `all` 角色，在同一进程中运行 Server 和 Worker；不要用独立的
`server`/`worker` 角色连接默认 SQLite 配置。先完成上述构建，并在当前进程环境安全设置
32～256 字节的 `MII_SETUP_TOKEN`，用于首次初始化；不要把真实 token 写入仓库或命令示例。
以下命令假定没有其他 `MII_*` 配置覆盖，且当前目录是本仓库：

```powershell
$env:APP_ROLE = 'all'
# 仅首次运行：安全创建主密钥；已有密钥不会被覆盖。
./artifacts/mii.exe keygen
./artifacts/mii.exe run
```

默认使用 `./data/mii.db`、`./data/integrity-master.key` 和 `./reports`，只在本机回环地址
`http://127.0.0.1:8080` 提供管理端及 `/health`、`/ready`、`/version`。主密钥需单独保管；
不要删除已有密钥来解决启动失败。非回环部署需要 HTTPS origin 和相应部署配置。

可通过 `--config` 或 `MII_CONFIG` 选择严格 YAML 配置；配置相对路径基于该文件目录。
PostgreSQL 可使用独立 Server/Worker 角色，需要显式配置数据库、主密钥和共享报告目录；
`run-server.ps1`/`run-worker.ps1` 仅选择角色，不自动建立这些依赖。前端单独开发可运行
`./scripts/run-web.ps1`（默认端口 5173），但不能代替真实后端集成验证。完整干净环境安装、
Compose 交付和恢复演练仍在开发，不将上述开发启动方式当成正式部署验收。

## Repository boundaries

- `cmd/mii`：唯一 Go 可执行入口，通过 `APP_ROLE=server|worker|all` 切换运行组件。
- `internal/integrity`：领域和应用模块；禁止从其他业务项目导入源码。
- `web`：React + TypeScript + Vite 管理端。
- `migrations/sqlite`、`migrations/postgresql`：双数据库版本化迁移、校验和与升级测试；已应用的迁移不得原地改写。
- `rules`：版本化开发规则、模板和 tokenizer 资源；正式校准与发布准入尚未完成。
- `tests`：集成、契约和 mock upstream 测试资产。
- `deploy`：单机与 Docker Compose 交付资产。

设计与验收基线见根目录 PRD、TECH SPEC、开发计划和 `docs/architecture`。
