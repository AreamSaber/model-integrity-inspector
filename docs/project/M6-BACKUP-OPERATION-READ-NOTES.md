# M6-05：备份操作授权状态查询与历史列表

2026-09-10。状态：repository 独立读取接口及本单元专项回归已完成，文件冻结交 root 复核；后续 HTTP DTO、路由和 UI 由协调器接入。本单元不创建归档、不授予下载或恢复能力，不修改维护迁移、完成协议或全局计划。

## 来源与接口边界

完整核对 `system_maintenance.go`、`system_maintenance_gate.go`、`system_maintenance_records.go`、`system_maintenance_transaction.go`、`system_maintenance_lease.go` 以及 `backup_completion.go`。维护操作是系统范围而非当前组织范围；现有 m21 的 active/aborted/superseded 与 m22 的 completed 都属于真实历史，不可以只列成功结果或只信一条状态记录。

- `ReadBackupOperation(ctx, ManagementAuthority, backupID int64)` 返回一条 `BackupOperationView`。
- `ListBackupOperations(ctx, ManagementAuthority, BackupOperationListRequest{BeforeID, Limit})` 返回 `BackupOperationPage{Items, NextBeforeID}`。
- `BeforeID=0` 是首个页面，后续使用正 int64 的排他 ID 边界；`Limit` 为 1..100。没有自由字符串 cursor、SQL、where/order 或组织过滤参数。页边界直接进入参数化 `id < ?`，而不是事后在内存筛选。
- 列表按 **ID 降序**，不是时间降序：`repository.NewID` 使用 CSPRNG 生成正 int64，不能误称 ID 越大就越新。时间显示使用认证后的原 created/updated 字段。如果未来需要时间排序，必须单独设计有界 typed keyset，不悄悄改变现接口语义。
- 一次最多读取 101 项（100 条 + lookahead），lookahead 同样验证操作、事件、审计与必要完成回执。末项损坏不返回成功前缀或未验证的 next cursor。下一页 cursor 是最后返回项的 ID，不是 lookahead 的 ID。

## 授权与当前状态

每次调用在最长 2 秒的真实 `maintenanceTransaction` 中执行。FIRST lock 是 `lockMaintenance`，认证当前 singleton 及其最新历史绑定；随后复用 `authorizeMaintenance`，要求真实 active 系统管理员、该用户的活跃未撤销 session、密码时间关系、无需强制改密、上下文 actor 与授权 UserID 相同。组织成员或组织管理员身份本身不够；非成员的系统管理员可以读取完整系统操作历史。

PostgreSQL 保留原 state SHARE / user-session 锁协议，SQLite 保留原 BEGIN IMMEDIATE 和有界 busy handler；不会绕到缓存的 normal 标记。读取结束前复用 `finishMaintenanceAuthority` 的最终数据库时钟：会话即使在开始时有效，但在验证页面期间自然到期，也必须返回零值错误。调用者更短的 context 期限及取消仍然有效。

`restore_isolated` 在这个系统内备份状态入口明确返回 `ErrRestoreIsolated`；未验证的恢复副本不能在此被表述为 ready。未来隔离诊断应采用单独接口。

## 原事实验证与安全返回

每一项复用真实 `verifyMaintenanceOperation`，验证操作与原 begin/latest event 及 audit HMAC 绑定，而不是只读取 status。活动历史必须还对应当前 freeze 的 operation、generation、owner 和租约字段；不能拿旧 active 行代表一个已被后继操作替代的任务。所有原事件版本不得越过当前已认证 gate 的版本/代次。

completed 还显式读取 `loadBackupCompletion`，再次比较回执 digest 与已认证事件的 completion digest，防止晚读取把另一份自行重算哈希的回执当真。完成状态只说明数据库已有认证的完成事实；物理文件仍须在真正下载时重新授权、打开及认证。

只返回：安全操作 ID、原 active/aborted/superseded/completed 枚举、固定 reason code、created/updated/lease/deadline 微秒、原 event sequence 版本，以及 completed 的 manifest version。没有 owner、用户或 session 身份、object ID、路径、DSN、哈希、密钥或任意错误文本；类型的 fmt/slog 封闭，禁止直接 JSON/YAML 序列化或 JSON 反序列化，要求后续 HTTP 层显式映射 DTO。

active 即使租约已自然到期仍然是 active；过期不等于已停止、aborted、completed 或可下载。aborted/superseded 不含 manifest version，不被描述为 ready。失败始终返回完整零 View/Page，而不是部分已验证列表。

新历史操作读取对 scope/mode/owner/reason/status/event_digest 使用现有 SQL 字节界定投影；校验使用现有维护协议及 audit.Verify，没有复制 MAC 算法或引入新的签名协议。

## 实际发现与共享修复

编写创建时间回归时发现：旧 `verifyMaintenanceOperation` 仅要求 op.CreatedAt 正值且不晚于 UpdatedAt，没有将其绑定到 sequence 1 begin 的已签名观察时间。真实 SQLite 将一个旧 aborted 操作的 CreatedAt 改为原值减 1 后，旧读取返回成功；`TestBackupOperationReadCreatedTimeMustBeBeginAnchored` 得到真实 RED（0.225s）。

此缺口由 root 在共享维护验证器修复：验证原 begin 的哈希/HMAC、CreatedAt、initiator/session/reason/generation，然后验证最新事件；未改 v1 canonical。本单元保留真实损坏反例，直接依赖共享修复，不另复制 audit 查询或 MAC 规则。root 已报告 completion + 该反例真实双库三轮 49.039s PASS；这不是本单元全部测试的替代证据。

另一条真实 PG 损坏反例来自旧操作的 `generation=NULL`：PostgreSQL `generation DESC` 默认将 NULL 排在首位，原共享 gate 的 `[]int64` 投影因 `converting NULL to int64` 扫描失败，误归类为 `DATABASE_UNAVAILABLE`，虽然仍然返回零值。原三轮 session `7596`（201.012s，terminal exit 1）每轮均只报告这一精确错误分类失败，不计作成功全组。root 将共享投影改为显式 `sql.NullInt64`，让 NULL 明确返回 `ErrMaintenanceSource`；本单元保留真实 SQL NULL 顺序观察和精确错误断言，不放宽为任意错误。修复后 PG 窄测 `51a2c4`，0.636s，terminal exit 0。

## 本单元回归记录

- 纯层参数/零值/格式化封闭：3 轮 0.111s PASS。
- SQLite 生命周期、两个 Store 实例、权限/actor/session、101 原操作排他分页、坏 lookahead、自然会话过期和非成员系统管理员：1 轮 1.774s PASS。
- SQLite 真实旧操作损坏、旧 normal 重置、restore isolation、晚 SQL 故障和双实例锁等待：1 轮 0.916s PASS；原 driver 路径过滤没有覆盖 `test/mode/driver` 的 receipt 子树，receipt 证据以下述无 driver 过滤最终命令为准。
- SQLite 真实 m21 60 秒租约自然到期 → 仍 active → 另一实例实际 TakeOver → superseded → 实际迁移及新 completed：session `81337`，60.272s，terminal exit 0。没有修改生产租约时长或把合成过去时间冒充自然过期。
- SQLite driver 直接子树 3 轮：`go test ./internal/integrity/repository -run '^TestBackupOperationRead.*/sqlite$' -count=3 -timeout=5m`，session `62001`，**188.150s PASS，terminal exit 0**，包括三次真实 60 秒自然租约到期及 schema21 历史实际迁移，但不是 receipt 子树或纯层的证据，不能称完整全组。
- 最终除自然租约慢组外的 **全部纯层 + SQLite + PostgreSQL + 所有层级故障子树三轮**：配置 General DSN 后，`go test ./internal/integrity/repository -run '^TestBackupOperationRead' -skip '^TestBackupOperationReadMigration21NaturalExpirySupersededHistory$' -count=3 -timeout=5m`。session `99317`，**38.825s PASS，terminal exit 0**。没有 driver 子路径过滤，实际包括 receipt missing/duplicate/hash/rehash/late-rehash 五模式及每模式两库；保留原 2 秒操作期限。
- 最终真实自然租约与迁移慢组：`go test ./internal/integrity/repository -run '^TestBackupOperationReadMigration21NaturalExpirySupersededHistory$' -count=1 -timeout=5m -v`，session `18475`，**120.917s PASS，terminal exit 0**。该命令不作 driver 过滤，真实 SQLite 60.18s / PostgreSQL 60.63s 各一轮，不缩短 60 秒租约，也不扩展测试 5 分钟期限。结合上一条最终命令，所有新测试及所有嵌套路径均有最终实际双库通过证据；慢组最终是每库一轮，不冒称三轮。
- Windows/Linux repository `go vet` 最终 `69dda9` / `af6f40` 均 terminal exit 0；Windows 与 Linux/amd64 cross repository `golangci-lint` 最终 `f6d37c` / `c8156f` 均 `0 issues`、terminal exit 0。新文件均完成 gofmt。General 已在最终数据库命令终态后明确释放给 root/app，未操作 Backup。

初始测试夹具曾误把随机 NewID 当作单调时间 ID，以及用逗号 Select 恢复 User 字段；均只修正夹具为真实 ID 排序与明确字段 map。生产授权规则、2 秒期限和维护租约未降低。

## 尚未覆盖的交付

页面/HTTP 契约映射、备份创建协调、实际文件可用性与完整性检查、受权下载、外部调度或 UI 提示，不由本 repository 状态接口提供。完成 receipt 也不是可跨 session 使用的授权凭据。整个 M6-05/SYS-008 及开发 Goal 继续进行中。
