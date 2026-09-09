# M6 PostgreSQL 原生工具 CI 接线记录

状态：独立 CI 接线与离线契约已实现；真实 Linux 任务的首次远端结果仍待集成提交后验证。本记录不表示 M6、完整备份/恢复流程或最终安全审核完成。

## 范围与执行环境

新增 `pg-backup-native` 必需任务，不替换已有任务。原有 19 个展开后的任务完整保留，新增后为 20 个：quality、6 个 repository race、6 个 Worker race、PostgreSQL identity/API race、dependency-scan、2 个 package、image、required，再加本任务。旧任务的超时、race 参数、分片、打包和镜像构建步骤未改变。

工具容器与独立数据库 service 使用同一个既有固定镜像：

```text
postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af
```

任务运行于 `ubuntu-24.04`，上限 25 分钟；容器安装的仅为 checkout/setup-go 需要的 `ca-certificates curl git gzip tar`，不安装或升级 PostgreSQL，不改变宿主系统依赖。沿用现有 checkout/setup-go 完整提交 SHA 和 Go `1.26.7`。

显式 `shell: bash`，因为 GitHub 容器任务的默认 run shell 是 `sh`。[GitHub 容器任务说明](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)

容器启用 `--init`，为原生子进程取消/父进程退出测试提供信号转发与孤儿进程回收环境；这不替代测试对整个子进程树退出的断言。[Docker init 说明](https://docs.docker.com/reference/cli/docker/container/run/#specify-an-init-process)

数据库 service 名为 `postgres`，使用该任务私有网络，不新增宿主端口映射或主机卷。容器通过 service 标签作为 hostname 连接，遵循 GitHub 容器任务的网络模型。[GitHub PostgreSQL service 示例](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers)

`mii_test_owner`、`mii_ci` 及由 run ID/attempt 组合的口令仅是临时 CI 合成 fixture。初始化角色必须实际具有 `CREATEDB`，用于集成测试创建独占源库和目标库。明文连接只用于这个隔离 service，绝不构成放宽生产 Dump TLS、目标地址或权限策略的依据。完整 DSN 在 shell 内构造，不 echo，不作为 GitHub step env 的完整 URL 展示；本任务不使用生产密钥。

## 必需证据与门禁

root 后续集成时将专有 job 的 DSN 明确改为 `MII_TEST_PG_BACKUP_DSN`，不再使用
General suite 的环境变量；该 job 已有独占 PostgreSQL service。原四类通用
race job 的 `MII_TEST_POSTGRES_DSN` 不变。完整 job 变异测试增加错用旧环境变量
反例，现35项；root全contracts三轮0.645s、策略165项、race分片87项及actionlint
通过。这是离线接线证据，不是新Linux job的运行结果。

测试前实际检查：Go 精确版本、Linux、空 `GOFLAGS`、两个工具的绝对可执行路径、`pg_dump`/`pg_restore` 精确 `18.6`（允许 Debian 发行后缀）、真实服务 `server_version_num=180006` 和当前角色 `CREATEDB`。路径固定为 `/usr/lib/postgresql/18/bin/pg_dump`、`/usr/lib/postgresql/18/bin/pg_restore`；任何前置失败会终止任务。

最终命令：

```sh
go test -p 1 -tags pgbackup_integration ./internal/integrity/pgbackup ./internal/integrity/repository -run '^(TestPostgresDump|TestPGBackupTLS|TestNativeProcess)' -count=1 -timeout=10m
```

两个 package 顺序运行，保留测试内部并发行为；测试不使用缓存，上限仍为 10 分钟。选择的三个族均有实际测试源码：导出/恢复与 TLS 使用 `pgbackup_integration` 标签；原生进程族使用既有 `windows || linux` 标签，也继续参加原有质量/打包测试。进程辅助入口 `TestNativeProcessHelper` 单独存在不算覆盖证据。

`m0-04-required` 保持原检查名称，新增 `needs.pg-backup-native.result` 的精确环境绑定，并加入原有逐项 `success` 检查。失败、取消、跳过和空结果都不能通过；不改变 main 分支保护配置。

PowerShell 策略检查实际任务和实际执行步骤，并保持旧版本、race、工具与分支保护契约。新增 Go 契约使用 YAML 解码比较完整 job，拒绝额外环境、条件、步骤、重复键、工具/镜像漂移、遗漏测试族、吞掉失败、延长上限及门禁断开；同时 AST 检查三个族的真实测试声明与显式 `Skip`/`Skipf`/`SkipNow`。这些静态检查防止静默漏接，不能替代真实工具执行，也不能证明任意未来测试函数体的语义正确。

## 本地验证记录

本单元只运行不接触数据库的验证，没有启动/停止 PostgreSQL，没有安装本地系统依赖，没有 Git 写操作或手动触发远端 CI。

| 命令 | 结果 |
| --- | --- |
| `.tools/go/bin/go.exe test ./tests/contracts -count=3` | 完整三轮 PASS，最终一次 package 时间 `0.667s` |
| `.tools/go/bin/go.exe vet ./tests/contracts` | Windows PASS |
| `.tools/golangci-lint/golangci-lint.exe run ./tests/contracts`（PATH 前置固定 Go） | Windows PASS，`0 issues` |
| 相同 vet/lint，设置 `GOOS=linux CGO_ENABLED=0` | Linux 目标静态检查 PASS，`0 issues`；不是 Linux 运行证据 |
| `./scripts/tests/test-m0-04-policy.ps1` | `165 cases` PASS，离线无远端修改 |
| `./scripts/tests/test-race-shards.ps1` | 原有 `87 cases` PASS，使用模拟执行器，不运行 DB 测试 |
| `.tools/actionlint/actionlint.exe .github/workflows/ci.yml` | PASS |
| `git diff --check`（仅本单元已跟踪文件） | PASS |

真实首轮 lint 曾对 Go 契约中的公开合成口令模板报 `G101`；仅对该常量增加带 fixture 边界说明的单行 `#nosec G101` 后重跑通过，没有关闭规则、降低阈值或省略检查。

## 交接与未完成项

交付文件为 `.github/workflows/ci.yml`、`scripts/ci-policy.ps1`、`scripts/tests/test-m0-04-policy.ps1`、`tests/contracts/replay_netns_test.go`、`tests/contracts/pg_backup_ci_test.go` 及本记录。仓储导出测试、TLS/原生实现和其测试属于并行开发单元，本单元未修改。

后续由集成人审阅并提交完整源文件集合、推送实际 CI；必须取得新 `pg-backup-native` 和原有全部必需任务的真实成功结果后，才可补充远端证据。离线通过不等于 PostgreSQL 工具集成已在 Linux 上通过；本文件也不授权生产恢复、数据库替换或最终发布。
