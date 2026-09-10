# M6：非执行终态域投影共享事务核心

日期：2026-09-10。当前状态：共享核心已实现，真实 SQLite/PostgreSQL 三轮与静态验证通过；不代表完整 drain 已接通。

## 范围与调用边界

仅修改 `analysis_recovery.go`、`report_recovery.go`、`precheck_reconcile.go`，新增专有 `backup_domain_reconciliation*.go` 与测试。原 `backup_drain*`、execution、app、worker、migration 和 Git 均不在本单元修改范围。

新增 `backup_domain_reconciliation.go` 中的三个私有 Store 方法：`reconcileAnalysisDomain`、`reconcileReportDomain`、`reconcilePrecheckDomain`。它们使用调用者已经拥有的同一 `*gorm.DB` 事务、原 Job 和当前数据库时间，返回私有 applied/no_projection；错误返回零结果。它们不是新的 Store 管理接口、JobLease、consumer 或维护授权，不自行开启事务、Claim、续租、派生、生成/删除文件或发出 HTTP。调用者仍必须先取得原 gate/权限/Job fence，保留最终真实时钟与权限检查，以及跨组织审计链头锁序。私有方法不独立证明调用者的事务/Job 输入可信，也不把返回 applied 当成允许 commit 的凭据。

普通队列路径继续原 maintenanceRecovery admission、consumer guard、terminal 候选选择与错误投影，只复用单 Job 的事务内动作。未来维护调用者只能在同一事务中 terminal 原 Job 并投影；此单元不实现那个维护入口，也不以普通 Worker 后补作为原子性证明。

## 不变的域规则

- Analysis：精确 `analyze:<run>:1`，只投影仍 ANALYZING 且 execution_closed 的原 Run；存在 published result 时拒绝，不能覆盖评分或新增 revision。只写原 FAILED、MI_ANALYSIS_FAILED、finished_at 和 version+1，并使用原 persisted creator 的 worker 审计。
- Report：精确 `report:<id>` 与组织/Job pointer，只能处理 queued/generating；ready、原下载/发布事实不能降级。沿用原失败错误码及 completed_at 写入规则，历史 creator/审计原因不改。先判断无投影的幂等状态，与实际选中后 UPDATE 返回 0 必须区分。
- Precheck：保留原 caller 传入的 terminal status/error 决策；不把传入参数与尚未在内存回写的旧 Job.Status 混同。原顺序是 cancelled 优先，其次 request_count>0 的 uncertain，再 exhausted，最后 service unavailable。保留原请求数、started_at、frozen snapshot 和其他字段；只写原失败结果 `[]`、error、finished_at、version+1，并保持 `target.precheck.reconcile` 历史 creator 原因。
- Run/Precheck 原全文模型读取缩为实际所需固定标量；不解析或读取 config_snapshot、snapshot_json、result_json 等正文，也不引入新的 label/历史兼容限制或补默认值。
- 对实际选中并需投影的一行，UPDATE 必须精确影响 1 行；真实驱动触发器静默忽略更新不是成功，不得留下成功审计。原合法无活动记录/已经完成的幂等无动作不是存储失败。

## 实际实现与验证

新增三个专有测试文件：`backup_domain_reconciliation_database_test.go`、`backup_domain_reconciliation_test.go`、`backup_domain_reconciliation_compatibility_test.go`，共 10 个 `TestBackupDomain` 顶层入口。

- 真实红：最初 `TestBackupDomainAnalysisRequiresActualUpdate/sqlite` 使用真实 analysis producer 与数据库 BEFORE UPDATE `RAISE(IGNORE)`，旧 `ReconcileAnalyses` 返回 nil，0.235 秒失败；没有模拟 RowsAffected 或改生产数据源。新增核心精确 UPDATE 1 后，同一用例 0.231 秒通过，检查失败无 run 变更/无成功审计，移除唯一触发器后真实候选成功结算。
- 三域同事务反例：调用者先在同事务更新实际 Job，再调用核心；每类真实域忽略更新、实际 AFTER INSERT 审计 SQL 故障、真实审计已插入后的取消均返回零结果并回滚 Job、全部域行、审计事件与链头。失败不会提交 terminal 等另一个 Worker 后补。测试覆盖的是可信事务核心组合，不是尚未实现的维护 full Apply 权限链。
- 移除故障后以原 producer 结算一次，重复调用为明确 no_projection、所有行精确不变。原 creator 已真实 disabled，spoof actor/reason/IP 被丢弃；保留原历史 actor 和原因，通过真实 VerifyAllAudit。
- Run/Report/Precheck 除原允许投影列外逐字段 DeepEqual；finished/completed 精确等于调用者传入的真实 DB now。预检五种原优先级含 cancel+request、uncertain+exhausted、零请求 exhaustion/unavailable；原请求数/started/snapshot 不变。请求数变体明确为受控 fixture，正向请求通过真实 Begin/Reserve。
- 原真实发布分析与 ready report 不降级；“已发布却 ANALYZING”是明确合成关系反例，返回原 ErrAnalysisSource，不伪造合法新 producer 状态。报告 payload 仍是既有 repository 合成 opaque fixture，不宣称真实文件生成/恢复。
- 固定 Query 观测实际拒绝 Run/Precheck 的全文/正文投影，并将原 config/snapshot 置为不合法 opaque 文本，核心仍只读取所需有限标量而完成真实失败投影。不加历史 label 限制，也不解析或补默认 frozen JSON。
- 初轮测试观察器误将 `integrity_run_results` 按不存在的 id 排序，三项 fixture 在核心前失败；修正为原复合键 organization/run/revision 后 SQLite 通过。此为测试元数据错误，不归为核心语义缺陷。
- SQLite 专有新组与四项旧顶层恢复回归 count=3：session 53367 首命令 5.174 秒通过；旧预检 `requests-0/1/sqlite` 两条嵌套路径显式另跑 count=3，0.740 秒通过，整个 session exit 0。不是遗漏嵌套 driver 路径的假覆盖。随后只补测试 if→switch 等价 lint 整理和优先级测试同事务 Job 转换，最终复验另记。
- `go vet ./internal/integrity/repository` exit 0；完整 repository lint 在两处测试 QF1003 等价整理后 exit 0 / 0 issues，无禁规则。
- 上述所有测试整理后的最终 SQLite 三轮复验：session 86787 首命令 5.191 秒、预检两条嵌套路径 0.710 秒，均 exit 0；随后 vet 与完整 repository lint 再次 exit 0 / 0 issues。
- 上述阶段未运行 PostgreSQL。随后 root 独占 General 并实际载入受控 DSN（不输出），执行 `go test ./internal/integrity/repository -run '^(TestBackupDomain|TestAnalysisRecovery|TestReport|TestPrecheck)' -count=3 -timeout=5m`，完整匹配父级及所有嵌套 driver 子树，**真实 SQLite/PostgreSQL 三轮 95.544s PASS**（59941 第二条命令；a5936c 终态 exit 0）。包含本单元真实 PG trigger/审计失败路径及原报告、分析、预检组合，不把纯层用例另算 PG 验证。
- 独立只读全文复核未发现本次提取新增 P1/P2；另识别普通 `q.reconcile` 原有 terminal Job UPDATE 只检查 Error 的相邻缺口。该旧路径不具备本单元可信测试调用者的精确单行检查，另立正常 Claim 的实际回归与修复单元，不能用本次核心测试替代其证明。

## 尚未接通

没有修改已冻结候选来源/暂停入口，没有新增维护 full Apply 或另开事务包装器。当前维护权限、原 Job 精确重验/终止、三域核心、最终权限窗口和系统 drain 审计仍需后续协调器在一个真实事务中接线。此提取不能单独证明完整 drain、备份或恢复已完成。
