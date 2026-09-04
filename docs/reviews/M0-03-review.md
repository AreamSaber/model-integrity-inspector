# M0-03 审核记录

计划编号：M0-03  
负责人：TL/BE  
依赖：M0-02（已通过）  
当前状态：待审核

## 开发目标

初始化独立 Git 代码仓库和与已批准架构一致的工程目录，使 Go 后端、React 前端和测试工程均可运行，并提供一条命令完成本地验证构建。

## 实际交付物

- Git `main` 分支仓库，以及 `.gitignore`、`.gitattributes`、`.editorconfig`；
- `cmd/mii` 单一 Go 入口和 `APP_ROLE=server|worker|all` 运行角色；
- `internal/integrity` 领域模块边界及可运行的 API/Worker 骨架；
- `web` React + TypeScript + Vite 工程和锁定依赖；
- `migrations/sqlite`、`migrations/postgresql`、`rules`、`tests`、`deploy`、`config` 目录；
- `scripts/build.ps1` 一键验证构建，以及测试、运行和工具链脚本；
- 根目录 `README.md`、`.go-version`、`.nvmrc`、`VERSION` 和 `go.mod`。

## 工具链冻结

| 工具 | 版本 | 锁定位置 |
|---|---:|---|
| Go | 1.26.7 | `.go-version`、`go.mod` toolchain |
| Node.js | 24.19.0 | `.nvmrc`、前端 engines |
| pnpm | 11.19.0 | `web/package.json#packageManager` |
| React / React DOM | 19.2.8 | `web/package.json`、`pnpm-lock.yaml` |
| TypeScript | 7.0.2 | `web/package.json`、`pnpm-lock.yaml` |
| Vite | 8.2.2 | `web/package.json`、`pnpm-lock.yaml` |
| Vitest | 4.1.11 | `web/package.json`、`pnpm-lock.yaml` |

Go 官方 Windows amd64 压缩包由 `scripts/bootstrap-toolchain.ps1` 校验固定 SHA-256 后解压到被 Git 忽略的 `.tools/`；`-Force` 会清除缓存并重新下载，校验失败也会自动重新下载一次并再次校验。下载的工具链不是项目源码或发布制品。所有构建、测试和运行脚本都会精确校验 Go、Node.js 与 pnpm 版本，版本不符立即失败。

## 自动验证证据

执行命令：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-m0-03.ps1
```

验证覆盖：

- Git 仓库、`main` 分支、有效基线提交和必要文件已跟踪状态；
- 28 个必要目录和 17 个必要文件；
- PowerShell 换行策略一致性和 9 类 Secret 忽略哨兵路径；
- Go、Node.js、pnpm 版本与冻结版本精确一致；
- Go 仅包含本项目模块，无第三方或其他业务源码模块；
- 前端直接依赖均为精确版本，锁文件无 `file:`、`link:`、`workspace:` 或 Git 依赖；
- 前端测试、TypeScript 检查、Vite 生产构建、Go 测试和 Go 二进制构建；
- M0-01、M0-02 状态保持已通过，M0-03 未越过审核。

实际成功摘要：

初始代码基线提交：`2ec221ae4bfa1f93618c9822a6344d7814268a73`（84 个跟踪文件）。

```text
M0-03 verification passed.
Repository: git=initialized, branch=main, head=present, required-files=tracked
Structure: required-directories=28, required-files=17
Toolchain: Go=go1.26.7 windows/amd64, Node=v24.19.0, pnpm=11.19.0
Dependencies: Go modules=1, frontend direct versions=exact, local business sources=none
Repository policy: PowerShell=CRLF, secret-ignore-canaries=9
Build: frontend-test=passed, frontend-build=passed, go-test=passed, mii-binary=present
Task status: M0-01=passed, M0-02=passed, M0-03=pending-review
```

关键交付物 SHA-256：

```text
a2d58446e9eb1973ee463b429724360bd10cea9a9c53c4f28ab43327b1d93468  go.mod
daac45b08822d7645e04aab8839dd553986ff0f89a1895bdde3ef002f296017b  cmd/mii/main.go
1f8330f98d08bc3b16eef05cecfeb988d0f6d799a9b9a386cdbfe8c5b8bc6cfb  internal/app/app.go
7daece24686fbb8b5fac38ffaca9503799a8b17c693f952873bcfa6988ea81e6  internal/integrity/api/handler.go
74cb0f7129aa84429df4f8d76b858679c9e39227040e697dc22f6ecc51a17ce3  internal/platform/runtime/role.go
28e057472601d81101b3ca72a4a5d3abcc23b062ad04bb24b1c5221cdb42be81  web/package.json
ff6100ab0e645181a4103063d37b18f034e99409b665e237b404f424bed5fd33  web/pnpm-lock.yaml
b938ec1f4c13272d8b957ea7ff7655b6ffe0087ca88d71f2c15d4b0f8d3fd1e4  .editorconfig
954c821287ee151c7a070d740b2bde9bb391f49ebcb8917a13920964ceaa7a25  .gitattributes
0d1f00b8f49f9f06c07f8a7d225d9b4352b30078a56ec2181dd61dcf28a8cc0e  .gitignore
7e4bf5e6ec5a8f49698afc9833d3222d5a3158c9124bdcf364a2c10f8ae2df06  scripts/toolchain.ps1
94737edba975e7d6dab4672611507f19b06a70251ba0e87fde91856a358f9533  scripts/bootstrap-toolchain.ps1
4af52dbd0b659f89d1415ac8d567a57b9b4ef70636fb2bf75b385a5058cf17cb  scripts/build.ps1
5c7be87bc68f0cab23b58091895e16e46b6f4f7e486c982bd60c3c1a7b08fee4  scripts/verify-m0-03.ps1
```

## 运行冒烟证据

| 对象 | 结果 |
|---|---|
| Server | `APP_ROLE=server` 启动成功；`GET /ready` 返回 `{"role":"server","status":"ready"}`；`GET /version` 返回 `0.1.0-dev`。 |
| Worker | `APP_ROLE=worker` 启动成功，保持运行直到收到取消信号。 |
| Web | Vite 8.2.2 开发服务器启动成功；首页返回 HTTP 200 且包含 React root。 |

## 安全与数据影响

- 当前骨架不创建数据库、不生成主密钥、不接受 API Key，也不调用外部模型 Endpoint。
- `.env`、`.key`、`.pem`、`.p12`、`.pfx`、Java keystore、`secrets/`、数据库、运行数据、报告、工具链缓存、依赖和构建输出均被 Git 忽略。
- API 只提供无敏感信息的工程状态端点；M1 起再实现认证、数据库、Secret 和检测能力。
- 未导入任何其他业务项目的源码、数据库结构或私有 SDK。

## 审核通过标准完成情况

| 标准 | 状态 | 证据 |
|---|---|---|
| 独立代码仓库 | 已完成 | Git 仓库已初始化，当前分支 `main`，有效 `HEAD` 存在且必要交付物均已跟踪。 |
| Go 后端可运行 | 已完成 | 单一 `mii` 制品构建成功，Server/Worker 冒烟通过。 |
| React 前端可运行 | 已完成 | Vitest、TypeScript、Vite build 和开发服务器冒烟通过。 |
| 测试工程可运行 | 已完成 | `go test ./...` 与 `vitest run` 通过。 |
| migration/rules/tests/deploy 目录 | 已完成 | 双数据库与各责任目录已建立并说明后续里程碑边界。 |
| 一条命令完成本地构建 | 已完成 | `scripts/build.ps1` 完成依赖恢复、前端测试/构建、Go 测试/构建。 |
| 无其他业务源码依赖 | 已完成 | Go module 和前端 lockfile 检查通过。 |
| TL 审核 | 待完成 | 当前保持待审核，未提前标记已通过。 |

## 已知限制

- 当前为工程骨架，不宣称已经实现数据库、认证、Job、Secret、检测或报告功能。
- 双数据库正式 migration 属于 M1-01，Mock upstream 与数据集属于 M0-07，Compose 可运行交付属于 M6-03。
- 环境未预设个人或组织 Git 身份，因此初始基线使用明确的自动化身份 `Codex Bootstrap <codex-bootstrap@localhost>`；未冒充用户，仓库发布前可按组织提交签名策略补充签名。

## 审核整改复核

| 优先级 | 原问题 | 整改与防回归 |
|---|---|---|
| P1 | 仓库没有基线提交，验证器接受空仓库 | 创建初始基线提交；验证器要求有效 `HEAD`，并逐项检查 17 个必要文件已被 Git 跟踪。 |
| P2 | 工具链版本只记录、不强制 | 集中定义精确版本；解析器、构建和 M0-03 验证均在版本不符时立即失败；前端 engines 改为精确版本。 |
| P2 | EditorConfig 与 Git 属性的 PowerShell 换行策略冲突 | 两处统一为 CRLF；验证器同时检查两份规则。 |
| P2 | Secret 忽略范围不足 | 增加 PEM、P12/PFX、Java keystore 和 secrets 路径规则；验证器检查 9 个哨兵路径。 |
| P3 | 工具链缓存损坏后无法自动恢复 | `-Force` 主动清除缓存；校验失败自动重新下载一次，二次失败时删除不可信归档并终止。 |

## 审核结论

工程结构、依赖锁、构建、测试和三类运行冒烟证据齐全，提交 TL 审核。批准前 M0-03 保持“待审核”，M0 Gate 仍未通过。
