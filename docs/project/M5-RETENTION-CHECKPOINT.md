# 响应正文保留策略：单调 cutoff checkpoint

日期：2026-09-08。状态：本批实现与独立双库回归已冻结，等待 root 集成；正式审核待统一执行。不是 0 天正文不落库功能已完整交付。

## 范围与恢复入口

按 PRD 11.2、TECH 18、`M5-EVIDENCE-DISPLAY-NOTES.md` §6 实现组织保留设置底座。本批只拥有 repository 新 `response_retention.go` 及对应新测试、`models.go` 的 cutoff 字段、`identity_management_organizations.go` 的真实设置路径、migration `000017_response_retention` 三文件及注册末尾追加，以及本说明。

不修改 000001～000016、Worker、analysis_source、raw/display 结算或清理，不动 root 的契约/台账，不执行 Git 操作。

## 已实现并独立验证

- 组织持久字段 `response_evidence_not_before_micros` 为 UTC Unix 微秒、非负、默认 0。0 表示尚未记录历史截止线，不表示允许留存 0 天。新表迁移不回填/解密/认证/删除既有正文。
- `ManageUpdateOrganization` 在实际权限与会话事务内锁定目标组织，锁后取得一次权威时间，以 `max(oldCutoff, now-oldDays, now-newDays)` 推進截止线。old/new 为 0 天时相应项就是 now。相同天数的显式保留设置也推进自然截止线；改名、时区或启用状态不推进。
- days/cutoff/version/updated_at 和既有组织变更审计同事务，CAS 检查完整原版本/旧天数/旧 cutoff 且必须 `RowsAffected == 1`。失败不得留下部分设置或假成功审计。
- SQLite 与 PostgreSQL 数据库触发器拒绝降低 cutoff 的直接 SQL 更新，错误为固定分类。它们不是抵御可修改数据库 schema 的超级管理员的防护；应用设置以外的直接 days SQL 不构成受支持的产品路径。
- 私有字段 `ResponseRetentionPolicy` 只能通过 repository 数据库装配，明确拒绝 JSON Marshal/Unmarshal，不能由 HTTP 手填组织 scope、版本或观察时钟。`Tenant.GetResponseRetentionPolicy` 为非写一致性快照，仅用于准备；`TenantTransaction.LockResponseRetentionPolicy` 为现有事务里的最终组织锁边界。二者不授予正文/历史/用户权限。
- `EligibleAtObservation` 必须同时满足活动组织、days>0、未删除、`captured > cutoff`、`captured > observedAt-days`、`sealedExpiry > observedAt`、`captured <= observedAt`。旧 sealed expiry 永远不被新长天数延长；严格等号均拒绝。

## 强制锁顺序

PostgreSQL 管理更新：既有 management advisory mutex → actor user → session → organization policy row → audit heads（既有组织升序）。

将来的 Worker 最终结算：既有 Job row → **organization policy row** → execution mutex → sample/run/target → audit heads。分析 `LoadRunAnalysis` 必须在 `lockRun` **之前**获取 policy/org；不能先沿现有路径锁 run、然后反向锁 org。任何路径都不允许持有 audit head 后回头取得 policy，跨组织场景需按组织 ID 升序一次性取得锁。

SQLite 保持 Store 既有短 `BEGIN IMMEDIATE` 写事务策略；准备读取使用既有非写一致性快照 helper。锁中不做网络、加解密、分析或缓慢文件操作。

## 尚未接入的工作

本批只让组织设置路径真实维护截止线。Worker 当前仍按 30 天保存 raw/display；migration16 的 display 固定 30 天 CHECK 也尚未改变。组织配置 0 天仍不能被宣布为“没有正文落库”。后续唯一可信 settlement、0/30 天派生 S1 等价、提交时重取策略、正文授权读取/清理，必须单独实现与验证。

## 测试记录

使用仓库固定 Go 工具链；PostgreSQL 为已运行的本地测试实例，DSN 从既有受忽略文件静默读取，不在日志或文档记录凭证。下列 repository 测试在设置 `MII_TEST_POSTGRES_DSN` 后均实际执行 SQLite/PostgreSQL 两种驱动。

- 最终 `go test ./internal/integrity/repository -run '^TestResponseRetention' -count=3`：通过，17.280s；包含最后新增的显式 JSON 拒绝行为及迁移测试。
- 扩大回归 `go test ./internal/integrity/repository -run '^(TestResponseRetention|TestManagement|TestMigrate|TestMigration|TestEmptyMigration)' -count=3`：通过，94.602s。此轮早于最后 JSON 方法小改动；该改动由上面的最终专有套件覆盖。
- `go test ./internal/identity ./internal/integrity/api -run '^TestManagement' -count=3`：SQLite identity 21.508s、API 14.736s；配置既有 PostgreSQL 驱动后 identity 36.935s、API 29.166s，全部通过。
- 最终 `golangci-lint run ./internal/integrity/repository/... ./internal/identity/... ./internal/integrity/api/...`：`0 issues.`。本批 Go 文件 gofmt 检查无输出；`git diff --check` 无错误（另有 root 所有 PowerShell 文件的既有 LF/CRLF 警告，不属于本批修改）。

实际回归覆盖：真实管理路径 30→0→30、缩短→延长不复活，精确 cutoff/day/expiry 边界，非保留更新不推进，组织停用/删除标记/未来采集时间拒绝；八个并发 CAS 仅一个成功；实际 SQL 的零行更新不得假成功；跨两个组织的后续审计追加失败使设置和先前审计头全部回滚；权限撤销/关闭事务/关闭库/跨 scope 读取失败关闭；持有真实 policy 锁时设置更新不能越过锁，另一连接仍可进行非写准备读取，提交后必须重新读取而不能信任旧快照。

迁移回归先建立真实 1～16 schema 与既有组织数据，再在第 17 步 DDL 后注入错误，核验列/触发器及 PostgreSQL 函数均回滚、前 16 条迁移记录不变，重试成功且旧组织设置/版本/时间不变、新 cutoff 为 0。双库还直接执行降低 cutoff 的拒绝 SQL 与相等/增加的允许 SQL。测试最初在 PostgreSQL 复用迁移前 `SELECT *` prepared statement 时触发结果列形变化；现用相同的显式旧列投影比较前后数据，未更改生产 prepared-statement 设置。本结果不宣称旧进程可在 schema 升级时无重启继续运行。

## 冻结文件清单

- `internal/integrity/repository/response_retention.go`
- `internal/integrity/repository/response_retention_test.go`
- `internal/integrity/repository/response_retention_migration_test.go`
- `internal/integrity/repository/models.go`（只增加组织 cutoff 字段）
- `internal/integrity/repository/identity_management_organizations.go`（真实保留设置原子更新）
- `migrations/common/000017_response_retention.up.sql`
- `migrations/sqlite/000017_response_retention.up.sql`
- `migrations/postgresql/000017_response_retention.up.sql`
- `migrations/migrations.go`（仅末尾追加第 17 项注册）
- `docs/project/M5-RETENTION-CHECKPOINT.md`

root 后续需同步迁移契约计数/最新名称，并单独完成所有消费路径的锁顺序与留存策略接线。本批没有 Git 提交，也没有正式批准任何里程碑。
