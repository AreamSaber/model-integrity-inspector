# M1 / SEC：审计事件与链头写入原子性

日期：2026-09-10。服务于已批准 ADR-0006 及 TECH SPEC 13.6 的业务与审计同事务要求，也供 M6 维护协调复用。当前实现已获真实 SQLite/PostgreSQL 三轮、完整主树 lint 与 vet 证据，不是完整安全验收。

## 实际缺口与修复

`appendAuditWithClock` 原先仅检查事件 INSERT、链头 UPDATE 的 `Error`。真实数据库触发器可静默忽略写入而不返回 SQL error；普通追加、供应商创建、改密和首次初始化都可能返回成功，却缺少事件或未推进链头。后续读取能发现链损坏不等于当前业务事务已经安全回滚。

本次只在 `audit.go` 这两处检查实际 `RowsAffected == 1`，否则返回既有闭集 `audit.ErrIntegrity`，交给原调用者事务整体回滚。保留真实驱动错误的既有安全映射。链头初始 `INSERT ... ON CONFLICT DO NOTHING` 的合法零行不作错误；现有先创建/锁头、读原尾链、原 HMAC/canonical、历史 actor/时间与数据库时间分支、跨组织锁顺序都不改变。没有导出新权力或将尾链检查替代全链验真。

## 真实回归

新增 `audit_atomic_write_test.go`：

- 真实 SQLite `BEFORE INSERT/UPDATE ... RAISE(IGNORE)` 与 PostgreSQL `RETURN NULL`，不模拟 ORM 结果；只针对固定事件表 INSERT 或链头表 UPDATE。
- 普通 `AppendAudit`、真实 `CreateProvider` 和 `ChangePassword`，分别断言错误闭集、业务/用户/会话/事件/链头原行完全不变。移除唯一触发器后同类原操作成功，恰好一条事件、链头前进一步，并实际验证 HMAC 全链。
- 真正 `Initialize` 验证失败返回零结果，组织、用户、成员、角色、权限、关联、设置和审计行数与初始化前一致；只移除故障后真实初始化恢复，恰好一条可验证 genesis 事件。
- 测试只在专属数据库比较受控值，不打印密码、事件内容、hash、SQL 或 DSN。具名触发器/函数清理幂等，不删除其他状态。

## 实际执行记录

1. **341494 exit 1，0.858s**：生产修复前，八个 SQLite 反例全部实际返回 nil，证明事件 INSERT0 / 头 UPDATE0 被当成成功；不是编译失败或缺少 fixture 的假红。
2. **8b653f exit 0，2.415s**：最小修复后，新完整两父级与全部嵌套场景 SQLite 三轮通过。
3. **8a0ac4 exit 1，0.707s**：准备执行双库组合时，其他在建 execution drain 生产文件尚未完整落盘，缺少五个 helper，编译终止。没有执行到任何数据库，不能计为 PostgreSQL 失败或通过；保留并行 WIP，等完整可编译边界后继续验证。

4. 其他生产 helper 完整落盘且实际 compile-only 通过后，root 独占 General 并实际载入受控 DSN，执行 `go test ./internal/integrity/repository -run '^(TestAuditAtomicWrites|TestAuditInitializationFailsClosed|TestAuditFailureRollsBackSensitiveMutations|TestAuditConcurrentAppendAcrossConnections|TestAuditTamperingDeletionAndHeadLoss|TestOperationalAuditVerification)' -count=3 -timeout=4m`：**真实 SQLite/PostgreSQL 三轮32.652s PASS**（18160 首命令；d6bd47 输出）。包括新八场景、原20路跨连接并发、初始化/敏感变更/篡改/健康检查；完整父级及嵌套 driver 无过滤，不把纯夹具当生产验收。
5. 同一 session 后续完整 `^(TestJob|TestPrecheck)` 双库三轮 **39.835s PASS**，e3e485 终态 exit 0；覆盖实际普通队列终态修复及其原恢复路径。
6. **5f109e**：Windows repository `go vet` exit 0；随后完整 lint 唯一诊断为其他在建 `backupDrainExecutionMetadata` 尚未接入（unused），没有本单元诊断，但不得称本批全仓 lint0。
7. 该并行函数完成真实接入后，root 重新运行完整 repository lint，**0 issues**（a2fd83）；随后 Linux/amd64、CGO=0 交叉 `go vet ./internal/integrity/repository` 通过，34216终态7ed131 exit0。没有禁规则或删除并行文件。
8. root 继续在同一受控 General 独占时段验证原 `TestBackupDomain`、`TestBackupDrainPausePreservesRealSampleAndOriginalFence` 和 maintenance admission 文件的五个原顶层用例（freeze在途fence/依赖、cancel/precheck、expired blocker、历史报告下载、restore隔离重启），无 driver 过滤三轮 **40.337s PASS**（31706终态fbb575）。这覆盖共享审计改动的既有维护调用者，不纳入尚在开发的新 execution/terminal drain 的验收。
9. 独立只读全文复核无确认 P1/P2，核对初始化/目录/改密原事务、初始头合法冲突、PostgreSQL锁和闭集 API 503 映射，不见新增能力或敏感错误外泄；该复核未自行运行测试。
10. 为单独覆盖首个链头并发创建，root 另跑原 `TestConcurrentMigrationAndInitialization` 完整双库三轮 **2.242s PASS**（48ff3b exit0），不以仅并发追加代替首次初始化并发。

仍需本批远端及后续完整维护整合验证。本机 CGO=0，交叉 vet 不等同于 Linux 执行或 race；远端已推送 a4f7487 的 CI 也不包含本单元。
