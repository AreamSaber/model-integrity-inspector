# M6-05：同一只读快照内的完整迁移历史清单

2026-09-09。新增私有仓储单元已实现并完成真实 SQLite/PostgreSQL 专项；不是物理 schema 认证、完整 backup inventory、可下载备份或恢复成功。正式审核仍待 V1.0 统一审核，不改变 SYS-008 原范围和批准记录。

## 依据与范围

完整读取 ADR-0002、M6-BACKUP-MANIFEST-NOTES、现有 `migrate.go`、`migrations/migrations.go`、`audit_snapshot.go`、`snapshot_audit_inventory.go` 及真实专用只读事务夹具；沿用前一全 inventory 梳理所读取的备份实施计划。当前编译迁移链为 1～21，最后一项 `system_maintenance`。旧迁移、`SchemaStatus`、PostgreSQL snapshot 外层以及其他生产文件均未改动。

仅新增：

- `internal/integrity/repository/snapshot_migration_inventory.go`
- `internal/integrity/repository/snapshot_migration_inventory_test.go`
- 本说明。

## 私有接口与一致性

`Store.snapshotMigrationInventory(ctx, tx)` 返回私有 `snapshotMigrationInventory`，内部 `entries` 按 version 顺序保留独立拥有的 `version/name/checksum`。fmt、slog 固定脱敏，JSON/YAML 序列化拒绝；不对业务层暴露 SQL、连接或通用备份权限。

- 只接受调用方持续持有的真实 `*sql.Tx`、活跃 deadline 和匹配方言。拒绝 nil、typed-nil、裸池、裸连接、弱 PG 隔离或可写 PG 事务。
- `NewDB` 清除调用者无关 Where/Limit/Order/Select，不改变底层事务，不查询 Store 池，不开始/结束事务，也不获取迁移锁或执行迁移。
- PostgreSQL 实际核验 READ ONLY + REPEATABLE READ/SERIALIZABLE。SQLite `query_only` 仅作补充：可信调用者仍必须在本次 BeginTx 之前通过专用连接 Raw 核验 native `IsReadOnly("main")`，并持续独占该连接；本单元不声称 query_only 能证明物理只读。
- 用 `migrations.ForDialect` 获取嵌入的原始迁移链，并调用现有 `verifyHistory(..., requireCurrent=true)`，精确核验全部版本、名称、checksum、`applied` 状态。不会接受已知前缀、自动补缺或更新 checksum。
- 迁移列表成功不要求或证明系统已初始化，不要求或证明审计、维护授权、其他业务表、物理约束/触发器、数据库文件或外部反回滚锚点有效。
- `applied_at` 不属于 manifest 的迁移字段，本单元仅核验其强制非 NULL，不把任意 SQLite timestamp 字符串载入 Go，也不认证时间值或历史顺序。原数据库备份仍保留该列真实值；物理 schema/业务恢复验证是后续独立工作。

## SQL 端资源边界与错误

迁移硬上限沿用 `backupmanifest.MaxMigrations=4096`。实际查询最多 `min(私有 cap, 编译迁移数)+1` 行；当前为 22 行。额外一行用于拒绝较长/较新链，不会把截断的 21 行前缀返回为成功。私有测试 cap 只能收紧生产政策。

- version 在 SQL 内限制到 1～4096，否则投影为无效 0；SQLite 同时要求存储类型为 integer，避免 BLOB/TEXT/REAL 经自动转换成为合法版本。
- name/checksum/status 分别限制为 64/64/7 个编码字节；超长、NULL 或 SQLite 非 TEXT 值在 SQL 内投影为单字节换行哨兵，不先把大值载入 Go 再检查。Unicode 按编码字节而非字符数计算。
- 任何查询、验证、超限或取消失败均返回 `entries=nil`，不会返回先前读到的部分行。成功前再次检查 context。
- 缺 context/deadline、错误句柄或只读前置不满足：`ErrConfiguration`；精确迁移历史不匹配：`ErrSchemaMismatch`；查询失败、关闭的事务、取消：`ErrUnavailable`；实际行数超过收紧 cap 或编译链超过固定政策：私有 `errSnapshotMigrationLimit`，固定文本 `SNAPSHOT_MIGRATION_LIMIT`。不传播数据库错误正文或 verifyHistory 的包装文字。

这些数量/字节上限是拒绝策略，不是已经验收的生产数据库容量。不能从历史 checksum 完整推导物理 schema 未被修改。

## 真实回归

6 个顶层测试均使用现有 eachDatabase 创建的临时 SQLite 文件或 General PostgreSQL 独立 schema；没有启动/停止实例，没有读取或修改 Backup cluster。真实 SQLite 夹具在 BeginTx 前验证驱动 native physical RO；不是 mock 或用 query_only 替代。

1. 与真实编译链逐项相等；传入污染 Where/Limit/Order/Select 后仍返回完整顺序。只有 driver、没有任何 Store 数据库池的实例仍成功，证明本路径不回退到 live 池。方法结束后原事务仍可执行 SELECT。
2. 第一个快照读完后，另一真实 Store/连接提交最后一个 checksum 的变更；旧快照再次读取仍为原链，新只读快照明确失败。修改先前 owned entries 不污染重读结果；测试恢复主动修改的 checksum 后，独立比较全部原始 SchemaVersion（含 applied_at）无其他变化。
3. 正常历史表先实际拒绝 version=NULL/0/-1/重复、name/checksum/status/applied_at 的 NULL，以及非法 status。随后仅在隔离 fixture 中将原历史表重命名保留，创建同列无约束表，真实构造空链、缺首/中/尾、多号、重复、名称/checksum/status 错误、全部五列 NULL、非正及最大 int64 版本；每项失败且零结果。结束时恢复原约束表，不修改旧迁移源码。
4. SQLite 额外真实写入 REAL/BLOB version，以及与合法文本逐字节相同的 BLOB name/checksum/status；全部拒绝，不能因自动字符串/数字转换误认为正常历史。
5. 实际 64/65、64/65、7/8 字节字段投影分别保留完整限内值/返回无效哨兵；限内文本仍须后续精确历史比较，不因长度合格获得可信性。name/checksum/status 各实际写入 1 MiB 值后，SQL 查询返回的字段明确只为 `"\n"`。22 个三字节中文字符也因 66 字节超过 64 而失败。
6. 实际迁移行超过私有 cap，必须返回 limit 与零集合；恰好 cap 成功，0/-1/超过4096的 cap 拒绝。额外插入由固定递归 SQL 生成的 4,097 行，通过实际查询后 callback 观察只有编译数+1（当前22）行进入 Go，然后因历史过长失败。
7. 真实查询已返回行后触发取消，或通过测试 callback 注入含 canary 的查询错误：必须 ErrUnavailable/零集合，不能泄漏原文。另覆盖调用前取消、真实事务已 Rollback、裸连接/typed-nil、弱 PG 隔离/RW、SQLite 缺补充 query_only。
8. 未迁移数据库调用失败，独立查询证明没有创建 `schema_migrations`。fmt/slog/JSON/YAML 对值与指针均验证私有表示。

查询错误 callback 只用于终态故障注入，不冒称真实网络掉线。上述取消包括实际读完后的取消，不冒称专门验证了长时间数据库锁等待的中断时延。

## 执行证据与交接

初版生产文件 `go test ./internal/integrity/repository -run '^$'` 编译通过。首次 6 个顶层测试真实双库单轮 **6.000s PASS**；Windows vet/lint 均通过。

补充精确 scalar 边界测试后，第一次三轮命令 **编译失败**：新增测试局部 `ctx` 未使用。修为 `_` 后才实际运行以下最终命令，失败命令不计为通过证据：

```powershell
$env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText('D:/Tokens-Test/Tokens-Test/.tools/test-postgres/dsn.txt').Trim()
& .tools/go/bin/go.exe test ./internal/integrity/repository -run '^TestSnapshotMigrationInventory' -count=3 -timeout=5m
```

最终真实 SQLite/PostgreSQL 三轮 **exit 0 / 15.189s PASS**，没有 Skip；测试 terminal 4646 已终态。General 数据库独占时段已交还 root，没有遗留运行中的数据库测试。

Windows `go vet ./internal/integrity/repository`、`golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...` 最终 **exit 0 / 0 issues**。Linux `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 的 test binary 交叉编译、vet、lint 最终亦 **exit 0 / 0 issues**，terminal 91849 已终态；生成的专有临时交叉编译二进制已清理。这不构成 Linux 原生测试或 race 证据。

root 集成需检查 `postgresSnapshotError` 的闭集保留：新增 `errSnapshotMigrationLimit` 应由 root 统一接线；`ErrSchemaMismatch` 是否保留为独立分类也由该外层统一处理。本单元没有修改共享 `postgres_snapshot.go`，现有外层可能把这些错误归一为不可用，不能声称已提供产品错误映射。

### Root 集成终态（优先于上段原交接状态）

root 完整读取三个交付文件、现有迁移比较器、只读事务夹具与 PG 外层后，新增
`snapshot_migration_integration_test.go`，先运行闭集回归得到 **0.089s FAIL**：
DATABASE_SCHEMA_MISMATCH 被误归一为 DATABASE_UNAVAILABLE。随后仅将
ErrSchemaMismatch 与 errSnapshotMigrationLimit 加入 PG 外层允许保留的精确错误集合；
任意包装文字仍剥离，取消优先级以及原 dump cleanup 不确定性优先级不变。

真实 PG 集成覆盖合法导出快照读取完整迁移链、实际改坏 isolated ledger checksum、
紧缩 cap，包含调用者包装错误及吞错两种路径：失败须持续阻止后续 use，返回零集合，
外层仍失败；结束后借出的对象失效，服务端独立实际重导入明确返回42704，证明原
快照不可再导入。没有仅凭内存标志推断服务端释放。

首轮新增全迁移+旧 PG snapshot 三轮 **23.058s PASS**。静态检查发现三个测试直接
比较 error 触发 errorlint，改为 errors.Is 加精确固定 Error() 文本检查，不删除或
弱化包装文字不泄漏断言。最后同范围三轮 **20.976s PASS**，再扩大到全部
TestSnapshotMigration、TestPostgresSnapshot、TestSnapshotAudit、TestAuditSnapshot
真实 SQLite/PG 三轮 **67.211s PASS**。两个数据库没有 skip；没有运行 native Dump
tagged 用例，也不把已有远端 PG CI 当成本次修改证据。

root Windows 仓储 vet/lint 0；Linux amd64/CGO0 目标 vet/lint 0，仅静态，非原生。
本集成最终范围为原三个文件加 postgres_snapshot.go 与新集成测试。General DB
全部测试终态后交给下一报告 inventory 单元，没有修改实例配置或生命周期。

迁移 history 只是完整 inventory 的一个构件。全组织审计、报告/规则文件实际验证、历史密钥闭包/密码学验证、Jobs/Attempts、配置模板、同快照 DB 文件/dump、认证归档、授权发布/下载、隔离恢复/激活和干净双库 RTO/RPO 演练仍必须全部完成；不能用本单元取代或缩减原要求。
