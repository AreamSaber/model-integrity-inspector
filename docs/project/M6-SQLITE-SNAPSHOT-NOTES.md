# M6-05 SQLite online snapshot 内部 helper

更新：2026-09-08。当前六个专属文件已冻结供主任务复核；Windows 真实专项三轮、纯故障三轮及静态检查通过，Linux 原生待 CI。实现范围仅新的仓储内部 helper 与独立测试；不是系统备份/恢复入口，不代表 M6-05、SYS-008 或正式审核完成。原 staging 八文件没有改动，使用其已提交 `54a9c31` 边界；不改迁移、Store、app、secret、manifest 或全局台账。

## 接口与信任边界

`sqliteOnlineSnapshot(ctx, source *sql.Conn, target *privatefile.SQLiteTarget, sqliteSnapshotOptions) (sqliteSnapshotStats, error)` 是未导出的基础设施函数。调用者必须是未来受维护门禁保护的可信协调器，持续独占新建的专用 source connection，不接受 HTTP 的 URI 或 SQL。当前没有公开 Store 备份/恢复方法，也没有自动调用维护、迁移或恢复。

- 必须有仍有效且不超过 24 小时的 context deadline；通常由 `WithSQLiteStaging` 传入。验证实际驱动 `IsReadOnly("main")==true`、`busy_timeout==0`，只容许 main/temp 两个 schema。普通 Store 的读写/busy_timeout=5000 池明确被拒绝；helper 不临时修改源配置、提交/回滚源事务，调用者的可选只读事务仍由调用者管理。
- schema 检查用 `main.pragma_database_list()` 的固定整数投影，将 seq 也映射为 0/1/invalid，只读 main/temp 分类，不把 file、任意 schema 名或伪造的 TEXT seq 载入 Go。最多读取三行，第三行必拒绝。目标 URI 只来自当前有效 staging capability，要求 file/mode=rw；固定设置 busy_timeout=0、1 MiB cache、DELETE journal、FULL synchronous。
- 在 `Conn.Raw` 内执行固定 modernc.org/sqlite v1.58.0 的真实 `NewBackup`，每次 Step 为 1..256 页、总 Step 1..2^24；只识别驱动原生错误码的 BUSY/LOCKED（含扩展码低八位）。全调用累计最多 0..128 次等待，每次最多 100 ms，失败或取消后不能无限重试。每次 Step 前后都检查 context 和 target.Check。
- 无论成功、忙锁、部分进度、取消、限额、检查失败，已创建的 Backup 恰一次 `Commit`（native sqlite3_backup_finish）。只有真实 Step 返回 DONE 才能成功；未完成时 Commit 可能回滚后仍返回 conn/nil，这不能冒充完成。返回的 destination driver.Conn 总会显式 Close，并检查其结果。没有使用会吞掉目的 Close 错误的 Finish，也没有裸 .db 文件复制或整库序列化。
- DONE 后同一目的写连接执行并核验 journal_mode=DELETE，随后执行固定有界完整性 SELECT，再关闭全部写连接。这一步不能省略：固定 SQLite 在只读加载 schema 时丢弃 CHECK AST，仅靠稍后的 RO 验证会漏验 CHECK。没有修改源连接或执行新的业务数据写。
- 全 Close 后另用 capability 的 `mode=ro&_pragma=query_only(1)` URI 打开，验证实际驱动只读、query_only=1、journal_mode=delete，复用同一完整性函数并进行外键检查。`sql.TxOptions.ReadOnly` 没有被当作 OS 只读开关；RO 结果也没有被单独称为 CHECK 约束证明。
- 完整性 SQL 在 SQLite 内把唯一合法 `ok` 投影为小整数，必须准确一行且为 1（最多两行）；外键 SQL 仅投影常量 1、最多一行且必须零行。不把可能超长的错误文字、子表/父表名字交给 Rows.Next/Scan。此投影避免无用结果物化，不宣称 SQLite 自身解析任意大 schema 的内存与数据库大小无关。
- 三条 table-valued PRAGMA 均明确限定 main、用函数调用，并在同一固定 SQL 内以 `main.sqlite_schema` 的 NOCASE 同名对象存在性守卫拒绝伪造；不是先查一次再发另一条存在 TOCTOU 的语句。普通同名表/视图的函数解析错误闭合失败；同名虚表即使可调用也不能冒充内置 PRAGMA。没有动态 schema/用户 SQL。
- rows、sql.Conn 与专用 sql.DB 的 Close 均检查。只读验证池保留唯一 idle connection，先归还 Conn 再由 checked DB.Close 关闭 native driver：固定 Go 1.26.7 的 MaxIdleConns(0) 会在 putConn 中吞 native Close 错误，不能用于此成功证明。
- helper 失败 stats 全零，公开错误仅闭集，不输出原始 SQL/driver/URI。完整 staging 成功才有 `Published=false` 文件 Receipt；consume 后的 native 检查、关闭、清理或最终取消仍可能失败，调用者必须等整个 WithSQLiteStaging 返回成功才发布加密输出。

## 真实驱动与无法隐藏的限制

固定 v1.58.0 的 Step 最终提交可能刷新脏页，所以页数上限不是内核 I/O 硬配额或任意阻塞操作的抢占承诺。staging 的容量/权限检查在有限 Step 间执行，不是可抵御同 UID/root/管理员的沙箱。目录、main 与 sidecar 的完整原生边界仍由原 staging 管理。

Commit 在 native finish 错误分支内部会尝试关闭目的连接但丢弃 Close 错误，同时不给调用者目的 conn。helper 对该分支返回失败，不再调用 Finish/Commit 二次释放；不能声称所有异常都证明全部句柄已释放。原 staging 可保留受限 orphan，但不会错误删除未知或被替换的文件。

源连接必须 fresh、专用并持续独占；此基础函数尚未证明全应用维护冻结，也没有同一副本上的 schema/inventory/审计锚点/报告引用生成。后续协调器可在 build 内通过目标只读 URI 进行这些有界读取，必须全部关闭后才返回，不应复制另一个全链算法或绕过维护授权。

Windows 测试新建 profile 下随机目录，出生时带 current user/SYSTEM 继承私有 DACL；先经原生无 reparse/规范路径/文件身份检查，再实际调用生产 staging 准入。默认 Temp 或 D: 根的宽权限不被修复/放行，不改现有 ACL。清理仅递归已核对身份和绝对范围的本次测试目录；失败准入只删除精确拥有的空目录或保留 orphan。

Linux 测试使用已列本地文件系统；默认 overlay 不被放宽，改用实际 Statfs 验证的 tmpfs /dev/shm 新建 0700 目录并再次经生产 staging 准入，无合适卷直接失败、不 Skip。最大测试有效 payload 为 25 MiB+17；源 WAL 在复制前先真实 checkpoint，随后保留小的已提交 WAL marker，源与副本合计约 50 MiB，单包不并行。**跨包 `go test ./...` 若 privatefile 与 repository 同时回退默认 64 MiB /dev/shm，仍可能争用空间**；尚无 Linux 原生复现，不把交叉编译当通过，不因此放宽安全或容量策略。需要上层 CI/测试资源协调后再称 Docker 全量可稳定执行。

## 已执行证据与待验证项

固定 Go 1.26.7，本机 Windows：

1. 首版 actual suite 单轮 **1.000s PASS**，修正专用验证池 idle 策略后三轮 **2.750s PASS**。这些是历史阶段，不覆盖后来发现的 CHECK 漏验。CHECK 修复后最终 `go test ./internal/integrity/repository -run '^TestSQLiteOnlineSnapshot' -count=3 -v` **5.012s PASS**（10 顶层），全部真实 NewBackup/WAL 路径，不是接口 mock。
2. 大库包含 25 MiB+17 的真实 zeroblob 与 checkpoint 后才提交的 WAL marker，复制结果经真实只读查询核对两行、marker 字节及 payload 长度，拒绝 SQL 写。最终三轮每轮 **101 Step、6408 页、26,247,168 字节**；完整流增量 hash 与 staging Receipt 一致；源 main/WAL hash 与源 WAL 策略不变。
3. 真实拒绝可写源、非零 busy_timeout（原值保持）、attached 用户数据库；真实 Step 上限/文件容量上限零 stats/零 Receipt/不消费；真实非法外键副本失败；完成真实复制后用测试拥有 SQL 损坏 sqlite_master rootpage，再由同生产只读校验拒绝，源仍可查询。
4. 独立连接真实 `BEGIN EXCLUSIVE` 造成原生 BUSY。schema 守卫加入后，主入口可在 preflight 就遇忙锁，此分支立即闭集失败，不冒称执行过 Step；独立定点测试在 source preflight 成功之后才取得实际竞争锁，调用真实 NewBackup，透明计数器证明 **三次实际 Step、一次实际 Commit**，没有伪造错误/页面/连接。两条路径单轮 **0.158s PASS**，随后包含在最终三轮中。
5. 取消测试观察到真实目的 DELETE journal 且非空之后才取消，再等待 watcher 同步结束，证明已进入 native Step，不是预先取消假象。全部 handled 失败测试检查没有残留 staging 目录。
6. 纯 options/finalize 早期三轮 **0.101s PASS**；含真实 `database/sql` 配合假 Connector 的 idle0/idle1 关闭错误传播对照，但不是实际数据库关闭故障注入。CHECK 修复后第二次验证查询有独立的 rows/Next/Close 计数与错误断言，最终三轮 **0.092s PASS**；不把假驱动当作真实在线复制证据。

### TVF 与 CHECK 的真实反例记录

- 第一次整数投影使用 `pragma_integrity_check(1)`，良库真实失败 **0.658s**。固定驱动的 hidden argument 是 TEXT，最终生成带引号的 PRAGMA 参数，被解释为名为 `1` 的表；专有合同测试真实确认 **0.144s PASS**。改为无参完整检查，SQL 限最多两条小整数结果，第一条非 1 即失败；没有把数值上限误写成真实可用参数。
- 原未限定/未守卫的 `pragma_database_list` 与 `pragma_foreign_key_check` 被普通同名表或同名 FTS5 虚表遮蔽。良库正例恢复之后，四个实际反例 **0.755s 真红**：真实 attached 数据库或真实外键违规被掩盖，helper 返回 nil 且进入完整 consume。更早四例 **0.356s 绿**只是所有数据库都被错误 TVF 参数拒绝的假安全表象，明确不作为有效防绕过证明。main+函数+同 statement 守卫后的四例均纳入最终三轮通过。
- 1 MiB 表名坏 CHECK 初测以为夹具错误，但真实复核证明：坏行存在、IgnoreChecks=0，同一源的 RW TVF 返回 0、RO TVF 返回 1，原裸 `PRAGMA integrity_check(1)` 在 RO 也为 `ok`，短表名对照相同。源码依据：固定 Windows `sqlite_windows.go:65402`，Linux amd64 `sqlite_g_000000000000c48b.go:1946` 的 `_sqlite3AddCheckConstraint` 在 Btree readonly 时不保存表达式，而完整性检查依赖该表达式。不是长名导致，也不是仅 TVF 漏验。
- 精确 CHECK 真红 **0.263s**：真实复制 helper 返回 nil、stats 非零；测试未完整消费导致外层 ErrIncomplete，不能将这次外层失败冒充 helper 已拒坏 CHECK。修复只在 DONE 后原目的 RW 连接上、DELETE 合并与 Close 之间增加同一固定有界完整性检查；再保留全 Close 后 RO 复验。1 MiB 真实 CHECK 与外键反例现均为闭集失败、零 stats/Receipt、不进入消费，已包含 **5.012s 最终三轮**。

### 最终静态/纯层收尾

- `go test ./internal/integrity/repository -run '^TestSQLiteSnapshot(Finalize|Options)' -count=3 -v`：**0.092s PASS**。38 个 finalize 状态机子例，加错误脱敏、标准库 idle0/idle1 对照与 options。包含第二验证 Query/Rows.Close/首末 Next/列数/空或多行/0或TEXT或NULL/取消/复合关闭失败；失败始终零 stats、原始 canary 不输出。
- Windows `go vet ./internal/integrity/repository` 通过；固定 golangci-lint 仓储检查 **0 issues**。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c` 通过（只生成系统临时目录内专有测试二进制，不执行）；相同 Linux 目标 `go vet` 通过，golangci-lint **0 issues**。
- Windows 的这些真实临时 SQLite 测试不使用共享 PostgreSQL fixture。数据库时段已明确交还主任务，后续仅静态/纯层收尾。Linux 尚未本机执行，不能将交叉编译或 Windows 三轮当作 Linux 原生证据。

冻结范围：`internal/integrity/repository/sqlite_snapshot.go`、`sqlite_snapshot_test.go`、`sqlite_snapshot_finalize_test.go`、`sqlite_snapshot_linux_test.go`、`sqlite_snapshot_windows_test.go`，以及本文档。没有修改任何已提交 staging 文件、迁移或公共 Store API。

未实现：全局备份协调、源维护票据绑定、同一快照完整 inventory/审计验证、PostgreSQL dump、manifest/报告/认证归档组合、隔离恢复校验、CLI/HTTP/UI 与真实双库灾备演练。未 Git 提交或推送，不作 TL/OPS/SEC/QA 批准。
