# M6 PostgreSQL 原生备份测试实例隔离

日期：2026-09-09。状态：受管 helper 的固定实例选择及离线契约已实现；新的 Backup cluster 实际初始化、启动和组合回归由 root 后续执行。本记录不代表真实数据库测试已通过，也不代表完整备份/恢复或 M6 完成。

## 为什么需要独立 cluster

前一单活 owned database fixture 已去除同一备份测试同时保留源/目标库导致的额外同步工作。root 随后报告：独立 dump 三轮曾以 16.690 秒全部通过，但新旧 audit/snapshot/dump 组合三轮耗时 161.907 秒，最终仍 FAIL；其中 3 次 RoundTrip/Exact 源库 DROP 在原 10 秒期限内等待 `CheckpointDone` / `CheckpointStart`。

同一个 PostgreSQL cluster 的检查点处理多个数据库的待同步工作。因此先运行 General 的审计套件，仍可能给后续新库 DROP 增加与该备份无关的实例级同步工作。独立数据库名称不是独立检查点边界。这里隔离 cluster 的数据、WAL、检查点和进程状态，不关闭 fsync、不增加原产品或测试期限、不请求更高生产权限。

上述数据库运行时间/失败来自 root 的真实测试交接；本脚本实施单元没有重跑数据库测试。此前源码与日志依据见 `M6-PG-DUMP-FIXTURE-NOTES.md`。

## 固定实例映射

| 项目 | General（默认） | Backup（显式选择） |
| --- | --- | --- |
| runtime | `.tools/test-postgres` | `.tools/test-postgres-backup` |
| 示例端口 | 15432，保留既有默认及显式自定义端口语义 | 显式 `-Port 15433`；不能省略端口或使用 15432 |
| data | runtime 下的 `data` | 自己 runtime 下的 `data` |
| 状态及凭证 | runtime 下的 `runtime.json`、`password.txt`、`dsn.txt` | 同名文件，但属于独立 runtime |
| 日志 | runtime 下的 initdb/server/start/stop 日志 | 自己 runtime 下的完整独立日志 |
| DSN 环境变量 | `MII_TEST_POSTGRES_DSN` | `MII_TEST_PG_BACKUP_DSN` |
| `Action Test` | 保留普通 repository 测试流程与 finally stop | 明确拒绝，要求显式 tagged 测试命令 |

只有 `General` / `Backup` 两个受限 Instance 值，不接受调用方 runtime/data/bin 自定义路径。两个实例仅共享固定 PostgreSQL 工具文件，不共享数据库目录、生成的随机密码或控制状态；合成角色名仍为 `mii_test_owner`，不会读取生产凭证。

## 启动前保护与兼容性

- 原 General V1 状态文件缺少 `instance` 字段仍可使用；新状态记录 instance。Backup 必须有匹配的 Backup 标记、固定 data 路径及原端口，不能接受从 General 复制来的状态。
- 所选实例状态检查及端口检查先于 bootstrap、目录/ACL/密码写入和 initdb。另一实例的固定状态文件仅只读检查：无论它是否运行，登记端口都不可被另一实例复用；损坏或错属目录的 peer 状态拒绝继续。
- 对尚未运行的所选实例，Windows TCP listener 快照若发现目标端口已被监听，则在初始化前拒绝。经过现有 PID、进程路径和 `pg_ctl status -D` 检查的已运行所选实例可以复用自己的 listener。
- 无受管状态但已存在的 Backup runtime 目录会被拒绝，不自动覆盖、删除或重新初始化。若首次初始化中途失败并留下此目录，需要先调查并由负责人决定后续处置，不能靠再次 Start 隐式重建。
- 保留 `.tools` 路径约束、junction/symlink 拒绝、ACL 收紧、生产环境拒绝、非空未知 data 拒绝、凭证缺失拒绝、loopback/SCRAM、后台 Hidden 窗口以及原 pg_ctl 30 秒/辅助进程 40 秒等待界限。无 fsync/full_page_writes/synchronous_commit 关闭选项、无 FORCE 清理、无系统服务/注册表/系统 PATH 修改。
- 端口只读预检不是跨进程原子端口预留；后续原生启动仍必须成功。隔离实例也不隔离物理磁盘或操作系统调度，不能据此承诺任意主机负载下必定满足 10 秒期限。

开发前和离线验证后均只读确认 `D:\Tokens-Test\Tokens-Test\.tools\test-postgres-backup` 不存在；本单元没有创建该目录。General 的现存进程和数据库没有被本单元重启、停止或修改。

## 后续实际使用（本单元未执行）

首次创建前，负责人仍需检查固定 Backup 目标不存在且 15433 未被占用，然后显式运行：

```powershell
./scripts/test-postgres.ps1 -Action Start -Instance Backup -Port 15433
```

helper 仅输出 ignored DSN 文件路径，不输出 DSN 或密码内容。root 完成 Go fixture 的必需独立环境变量接线后，在同一个测试 shell 内从 Backup 文件读取 `MII_TEST_PG_BACKUP_DSN`，不 echo；General 的 `MII_TEST_POSTGRES_DSN` 保持从 General 文件读取，二者不得互相回退或覆盖。显式真实工具测试命令形如：

```powershell
go test -p 1 -tags pgbackup_integration ./internal/integrity/pgbackup ./internal/integrity/repository -run '^(TestPostgresDump|TestPGBackupTLS|TestNativeProcess)' -count=1 -timeout=10m
```

PG 工具的既有绝对路径、精确版本、权限与缺环境必须失败等前提仍由真实测试检查；本 helper 不把普通 Go 测试冒充原生工具测试。Linux CI 的独立 job service 与新环境变量接线由 root 负责，不在本次脚本修改范围内。

停止或查询 Backup 时也必须明确实例和原端口：

```powershell
./scripts/test-postgres.ps1 -Action Status -Instance Backup -Port 15433
./scripts/test-postgres.ps1 -Action Stop -Instance Backup -Port 15433
```

## 离线验证及尚待验证

`scripts/tests/test-postgres-instance.ps1` 从真实脚本 AST 提取三个纯策略函数和真实参数声明，不 dot-source 默认会执行 Test 的完整入口。50 项覆盖固定映射、默认值、非法 Instance/端口、Backup 普通 Test 拒绝、旧 General 兼容、错实例/目录/端口状态、双向 peer 端口冲突、未归属 listener 拒绝、已运行实例复用以及启动前检查顺序和原保护保留。测试未执行 initdb、pg_ctl、psql、Go 或任何文件系统写操作。

实际执行 `1..3 | ForEach-Object { & ./scripts/tests/test-postgres-instance.ps1 }`：三轮均为 `50 cases` PASS，合计 wall time 0.422 秒。两个修改/新增 PowerShell 脚本均通过 PowerShell Parser，无语法错误。

尚待 root：实际启动新 Backup cluster；确认 fsync 保持启用且与 General 为不同实例；接入必需的新 DSN；在不放宽原期限或断言的情况下重跑组合测试；执行全仓/远端门禁与 Git 集成。不得把当前离线策略 PASS 写成实际 PostgreSQL 或组合套件 PASS。

## root 后续实际结果

root完整读取脚本/测试/本文并重跑50项PASS，然后再次确认Backup绝对目标不存在、
15433无listener、原General进程26484仍为固定postgres.exe，执行上述Start成功。
实际SQL设置为180006/on/on/15433（版本/fsync/synchronous_commit/端口）。
新fixture真实连接检查同时配置的General/Backup的实际system_identifier不同；
指向同一个Backup cluster的另一种URL scheme反例仍被拒绝，不创建数据库。

完整原组合 `go test -tags pgbackup_integration ./internal/integrity/repository
-run '^(TestPostgresSnapshot|TestSnapshotAudit|TestAuditSnapshot|TestPostgresDump)'
-count=3 -v -timeout=5m` 终态 **108.814s PASS**。包括实际导出/新库恢复、
服务端锁等待取消、非超级用户独立会话、身份/权限错误和控制连接恢复；没有
降低旧数据量、次数、测试选择、DROP/取消时限或失败断言。Backup复查无fixture
数据库残留；原General保留的历史残留另行登记，不将本次结果扩大为全产品验收。

实例脚本、fixture与Linux专有job均已使用独立MII_TEST_PG_BACKUP_DSN；旧通用
CI/race的MII_TEST_POSTGRES_DSN不变。Linux原生新job及全产品测试仍待运行。
