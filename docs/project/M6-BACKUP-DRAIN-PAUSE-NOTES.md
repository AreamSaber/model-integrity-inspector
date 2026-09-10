# M6：维护权限下候选来源与安全暂停基础

日期：2026-09-10。范围：`M6-BACKUP-DRAIN-DESIGN.md` 第 10 节第一阶段；不代表完整 drain、UNCERTAIN 结算、备份协调器或恢复已完成。

## 已实现的生产边界

新增五个文件：`internal/integrity/repository/backup_drain.go`、`backup_drain_source.go`、`backup_drain_source_sql.go`、`backup_drain_domain.go`、`backup_drain_pause.go`。

两个真实入口：

- `(*MaintenanceLease).LoadBackupDrainCandidate(ctx)`：返回至多一个 owned 私有元数据来源、闭集 Kind 和独立全局 blocker observation；不修改 Job/域事实，不领取任务。
- `(*MaintenanceLease).PauseBackupDrainCandidate(ctx, source)`：仅对 `pause_safe` 的真实过期 running Job 原地转 pending。其他 closed kind 一律 `MI_BACKUP_DRAIN_RECONCILIATION_REQUIRED` 和零结果，不先 terminal Job 留给普通 Worker 后补结算。

候选集合覆盖七类 Job，而非只选六类 safe：expired/null-lease running；pending 的 DISPATCHED、预检已 request、通知已领取、取消/耗尽/组织失效；failed/cancelled 的五类待域投影。所有 DISPATCHED 另做全局关联/唯一性及未映射 legacy 检查，避免 inner join 丢掉孤立或缺少历史 Job ID 的请求意图。

`CandidatePresent` 独立于 PG `SKIP LOCKED` 取到的行。`RunningJobPresent`、`UnsettledAttemptPresent`、`UnsupportedSourcePresent` 也独立存在；source=nil 绝非 drained/ready。Kind 仅表示当前阻塞类别，不构成后续结算输入或原终态错误码的选择权。

## 可暂停与不可暂停

当前六个真实生产 Handler 对应的安全无待结算出站工作均有真实 producer 正向回归：未启动 Run plan、未发出请求的 sample、未发布 analyze、未发布 report、零请求 precheck、现代 planned retention batch。

暂停要求：真实正 generation、nonnull 已过期 lease、非空原 owner、未完成 Job、仍可重试、未取消/组织失效，以及当前域状态和反向指针证明 safe。严格保留现代 retention 在 disabled organization 下的既有例外。

实际只修改 Job 的 status、lease_owner、lease_until、updated_at；不改 ID/object/idempotency/available_at/priority/generation/最大尝试次数/原错误码，不刷新 precheck lifetime，不生成新工作。追加真实当前系统管理员的 `system.backup.drain.pause_running` SYSTEM-anchor 审计，五项数字身份绑定 operation/generation/org/job/job-generation。原 maintenance v1/v2、队列协议和 schema 不变。

以下明确只观察并阻塞：DISPATCHED、预检已请求、已领取通知、需原终止规则/域投影、未知活动 legacy、不易证明安全的域状态。没有 S1/MAC 能力，也不读原正文、config_snapshot、request_plan、source_json、locator、凭据或 S2。不调用 Handler/Completion、Secret、HTTP、文件生成/删除、分析或保留删除。

当前没有生产 notification Handler；其测试明确是历史 outbox schema fixture，不是成功发送的 producer 证明。活动 legacy retention 组织 sentinel 不支持暂停；静态 terminal sentinel 原形保留，不伪造现代 batch 或删除 receipt。

## 权限、失效、并发与资源

- 每次 Load/Pause 进入现有 `maintenanceTransaction` 的不超过 2 秒事务：maintenance gate UPDATE → 真实 system-admin/session 授权 → 当前 DB clock/operation/owner/generation → 原 Job 锁及域关联重读 → Job 更新/系统审计 → `finishMaintenanceAuthority` 最终真实窗口检查。
- 正常 Renew 不使 source 失效：不绑定 maintenance row.Version；仍须为同一 operation/generation/owner。原 Job 任一已读取字段改变精确返回 stale，不报告 applied。域元数据改变也不能沿用旧 pause proof。
- 所有错误返回零结果；事务内审计、末端会话/原租约自然过期及取消均回滚。驱动 commit/连接 cleanup 的失败可能无法证明提交与否，零结果不是“肯定没有写入”的声明；应 fresh Load 观察，不盲目重放旧来源或补写 receipt。
- 复用的 persistence 层会清除 SQL 细节；新入口在失败且自己的 ctx 已取消/超时时返回已知 closed cancellation/deadline，不还原任何 SQL 文本。
- 不打开、篡改或续租 SQLite consumer；不授予 PG server-only 普通消费权。没有新后台 goroutine；上下文 timer 均作用域内取消。
- 所有关联 SQL 只选固定有限标量；selected Job 文本/时间及 selected 域元数据先由 SQL 侧 storage-class/字节上限检查，才跨 database/sql 物化。字符串最大 128 字节，hash 元数据最大 64；单次最多一份候选/最多两行重复探测，无正文读取或全表内存集合。
- 全局只做结构/关联/EXISTS/重复检查，不把 selected-source 的新文本分配上限施加到不会读取的静态历史 Job。全局 SQL 仍受真实事务期限约束；没有另加 Job/Attempt 人口限制，也不跳过 poison 声称完成。

## 兼容性

合法静态历史、nullable Job pointer、legacy `PLANNED`/terminal 记录及原 source version 不重写。活动 nullable sample pointer/旧零 generation/缺失原 Job ID 以 unsupported 和全局 blocker 保留，不生成现代身份或 MAC。选中活动来源无法验证时明确失败；不拿当前默认资源/参数补历史。

Job metadata 保留 SQLite 原时间文本与 NULL；PG 使用同连接 native timestamp 的确定文本投影。这里不解析旧 request JSON，也不声称是完整原行摘要；更不能用这份标量来源完成派生证据结算。

没有改既有 Claim/consumer/reconciler/维护协议/migration/app 或 Worker 合同。现有冻结前已领取 Job 的 admission 回归仍允许原记账/结算；此单元本身不产生任何出站，亦不声称能证明远端停止。

## 实际验证记录

新增八个专有测试文件：`backup_drain_pause_test.go`、`backup_drain_producers_test.go`、`backup_drain_blockers_test.go`、`backup_drain_authority_test.go`、`backup_drain_natural_expiry_test.go`、`backup_drain_pure_test.go`、`backup_drain_concurrency_test.go`、`backup_drain_legacy_test.go`。

- 首个语义红：真实 sample producer → 原 Claim → expiry → freeze → 原 Claim 无进展；新 Pause 尚未实现时在实际调用处失败，`safe expired sample was not paused / MI_BACKUP_DRAIN_RECONCILIATION_REQUIRED`，0.233 秒。
- 接通真实 UPDATE + 审计后，同一回归通过，0.339 秒；检查旧 Complete/Retry/Renew 全部失效，Job 其他字段逐项保留，无新增 Attempt。
- 31 个快速入口，精确枚举排除唯一 `TestBackupDrainNaturalLeaseExpiry`，SQLite/纯层 count=3：最终 terminal 40557，exit 0，14.582 秒。含六种实际 producer、七种 blocker、pending DISPATCHED/预检请求、终态投影、disabled retention、活动/静态 legacy、SQL 读取界限、私有格式/错误、原 Job/域变更 stale、审计/晚期取消 rollback、末端会话自然过期、真实 SQLite writer 锁与失效操作。
- 独立原 60 秒 lease：`TestBackupDrainNaturalLeaseExpiry/sqlite`，count=1，terminal 58810，exit 0，60.383 秒。实际 Pause 已更新 Job 并进入审计后自然跨原期限，验证 Job/审计一起回滚；同窗口验证 expired source 不可用、另一 Store 真实 takeover generation+1、旧 owner/source 拒绝，fresh source 才可暂停并通过真实 audit Verify。未缩短任何生产 lease/clock/timeout。随后仅补正 generation=0 不可 safe 及 lint 等价清理；全快组三轮覆盖。
- 复核修正并发测试 cleanup：失败退出先 cancel/release 再 join，避免 holder 尚未取得 SQL 锁时 cleanup 自己等不到取消；正常路径仍先 release/join 并验证事务成功，不用提前 cancel 掩盖错误。修后真实 SQLite 锁测试 count=3，1.017 秒通过；十三个专有 Go 文件 `gofmt -l` 无输出。
- 首轮完整 fast 双库 count=3 的真实 PG 红：terminal 27488，exit 1，69.882 秒。两处 1MiB+ indexed key 被 PG B-tree 物理行上限先拒绝（SQLSTATE 54000），不是 source 读边界被绕过；专有 fixture 修为 PG active key 210 字节、静态 legacy key 196 字节，均真实可存且严格高于新的 128 字节投影上限，SQLite 保留原 1.5MB/1.4MB 输入。修后两项真实双库均通过。
- 同一首轮的 sample 精确更新时间断言，安全诊断为 `pending=true / owner_null=true / lease_null=true / updated_delta=-7h59m59.960973s`：公共 `expireJob` 的 GORM `Update` 隐式将 `updated_at` 改成主机本地 +08 壁钟，PG 无时区 TIMESTAMP 原样存储，而实际队列/Pause 使用 UTC DB clock。只在此专有测试将租约故障注入改为 `UpdateColumn(lease_until)`，避免改动无关字段；没有修改公共 helper、生产时钟或放宽 `UpdatedAt.After`/逐字段精确比较。修后该项完整双库 count=1，0.723 秒通过。
- `go vet ./internal/integrity/repository` 已通过。新文件的 lint 诊断已经全部解决，没有禁规则；完整仓储 lint 曾被其他并行文件两条 G101 阻断，此处不冒称全仓 lint 通过。
- 最终 31 个 fast 入口无 driver 过滤，真实 SQLite/PostgreSQL 及纯层 count=3：terminal 8653，exit 0，67.170 秒。含实际 PG `SKIP LOCKED` 候选为空但全局 blocker 仍存在，以及上述 fixture/cleanup 修后版本；不是 SQLite 子路径或缺少 DSN 的 skip。
- 最终独立 `TestBackupDrainNaturalLeaseExpiry` 无 driver 过滤、两库各 count=1：terminal 79598，exit 0，120.951 秒，SQLite 60.18 秒、PostgreSQL 60.67 秒。两个实际原 60 秒窗口均验证晚期 Pause/审计全回滚、旧 owner/source 拒绝、真实另一 Store takeover 与 fresh source 成功。所有 DB session 均已终态，General 独占时段明确交还 root；没有重配或启停数据库。

精确测试选择方式（General DSN 仅在本地受控进程环境载入，不输出；无 driver 子路径，slow 仍 count=1）：

```powershell
$drainTests = @(& '.tools/go/bin/go.exe' test ./internal/integrity/repository -list '^TestBackupDrain' |
    Where-Object { $_ -match '^TestBackupDrain' -and $_ -ne 'TestBackupDrainNaturalLeaseExpiry' })
$drainPattern = '^(' + ($drainTests -join '|') + ')$'
& '.tools/go/bin/go.exe' test ./internal/integrity/repository -run $drainPattern -count=3
& '.tools/go/bin/go.exe' test ./internal/integrity/repository -run '^TestBackupDrainNaturalLeaseExpiry$' -count=1
```

慢组仍属于常规 CI，不 skip 或扩大原期限；其新增每库 60 秒成本由精确分片承担。

## 仍未完成

root 已全文复核五个生产文件、八个测试及本说明，并独立执行 SQLite 全部 `TestBackupDrain` 与现有 admission 组合单轮 **64.603s PASS**，包含原自然租约窗口。独立只读复核另对照原 queue/Reserve/StartRun/recovery/object SQL/维护授权，限定 stage 1 内没有发现可确认 P1/P2；该静态结论不代替上述实际双库测试。root 最后仓储 Windows vet/lint0、Linux amd64 交叉 vet0（61951 terminal0），不是 Linux 原生或 race。

DISPATCHED → 原 Job + 真实 unavailable S1/MAC + UNCERTAIN/预算/依赖/域审计同事务结算；其他 terminal 域投影；通知不确定状态政策的实际写入；app 备份协调器调用上述能力并继续实际同视图 snapshot/inventory/归档/readback/completion。本文仅证明候选/暂停基础及已明确记录的测试范围，不能据此将完整 drain 或 M6 备份/恢复标完成。
