# 派生 S1 仓储接线 checkpoint

日期：2026-09-08。状态：仓储派生结算、migration18、两阶段维护恢复已实现且完成专有真实双库三轮回归；最后增补的维护分支也已双库通过，扩大回归进行中。尚未完成整应用验收；是否激活生产由 root 决定。本文件属于 evidence_capture，不替代 root 台账或最终批准。

## 已落盘

- migration18 `derived_attempt_source` 三方言及末尾注册。新增 Run SQL source mode、Attempt derived/body receipt、每 Attempt 唯一的 opaque S1 表。SQLite 重建 display16 表并搬运原列；PostgreSQL 精确替换原固定30天复合 CHECK，改为整数1～180天，未改迁移1～17。
- `execution_derived.go` 的 DTO、S1 单候选选择/插入、完成专用 Job cancellation 分类；`execution_derived_body.go` 私有 DB capture/expiry/scope、WithRecords 克隆封装材料、完成时 fresh policy 判定与条件 raw/display INSERT。
- `execution_models.go` 新字段；`execution.go` 新Run从plan导出SQL mode、lockRun/GetExecutionPlan交叉检查、明确legacy/derived启动入口；`execution_attempt.go` Reserve pending及共同final结算；`execution_recovery.go` 重新认领候选入口；`execution_display.go` 1～180通用结构检查及legacy旧入口仍固定30天。
- 候选正常状态由既有实际取消/stale/预算覆盖顺序选择，S1先INSERT后同一Attempt UPDATE写status/receipt，S1.CreatedAt等于Attempt.FinishedAt的同一DB观察值；原始正文采集时间不改成完成时间。
- `execution_derived_reconcile.go` 提供 terminal failed/cancelled Job 的私有两阶段 source：短事务冻结 DB 输入，锁外由可信 Worker 提取/认证，短事务重验 Job generation/status、Run mode、冻结 Manifest/wire/sample 和原 Attempt 后恢复。真实无响应只允许固定 UNCERTAIN 收据；legacy、未启动 Run、未发请求 Sample 不制造 S1。
- source 读取在加载/解码前执行真实 SQL 字节/行数 guard：Sample 请求计划最多1行2MiB、Run snapshot 最多1行8MiB、Attempt 请求快照最多1行2MiB；全批 source 总量累计不超过8MiB，batch只接受1～8。Use 深克隆全部可变指针/切片，临时 JSON S2 字节及 binding 编码在返回前 clear，不允许借用者篡改后续 Use 或原私有收据。
- migration18 同时保护 INSERT/UPDATE 的 Run mode↔Attempt receipt 关系，terminal receipt 不可退回 pending。SQL source 列只交叉校验冻结计划，不能替代 Manifest 签名；S1 MAC 验证由真实 features/analysis 执行。

## 稳定接口

- `StartRunWithDerivedSource(runID)`；旧 `StartRun` 只接受显式legacy，不升级旧计划。
- `FinishAttemptWithDerived(sampleID, attemptID, outcome, jitter, AttemptDerivedCandidates, *AttemptBodyCapture)`。
- `RecoverInterruptedSampleWithDerived(sampleID, attemptID, AttemptDerivedCandidates)`：共同scope、仅1个UNCERTAIN/INVALID_RETRYABLE/MI_UNCERTAIN_ATTEMPT候选。
- `BindAttemptResponseCapture(sampleID, attemptID, requestHash)` → 私有capture；`DisplayBinding()`只借出AAD绑定，`WithRecords(raw,display)`克隆材料，时间/scope不可手填；nil capture明确为not_captured，0天或cutoff拒绝为not_retained。
- `JobQueue.LoadExecutionReconciliations(ctx, limit)` → 私有 `ExecutionReconciliationSource` 列表；`source.Use(func(ExecutionReconciliationData) error)` 仅借出独立副本。
- `JobQueue.ReconcileExecutionWithDerived(ctx, source, *AttemptDerivedCandidates)` → `applied` / `already_completed` / `stale`。有 derived Attempt 时必须唯一 fixed UNCERTAIN 候选；无 Attempt 或 legacy 时必须 nil。重复提交逐字节核对原 Payload/MAC/版本/key version、完整 scope、实际终态与 CreatedAt==FinishedAt。未知 SQL/完整性错误不转换为成功。
- 无新增消费者。root 的既有 Runner 维护适配每轮加载一条，并继续调用既有 `ReconcileAnalyses`；仓储接口不做网络、Secret 读取、提取器或解密。

## 已实际验证

- `go test ./internal/integrity/repository -run '^$'`：编译通过。
- 固定工具链、静默载入既有PG测试DSN后，`go test ./internal/integrity/repository -run '^(TestMigrateRepeatableAndWorkerReadOnly|TestResponseEvidenceAtomicLeaseScopeAuditAndExpiry|TestDisplayEvidenceBindingValidationAndLegacyRemainSeparate)$' -count=1`：SQLite/PostgreSQL实际通过，1.971s。
- `go test ./internal/integrity/repository -run '^TestDerivedExecution' -count=3`：实际 SQLite/PostgreSQL 三轮通过，47.933s。覆盖正常实际取消/stale/预算组合候选、0/1/7/30/180天、旧三个完成入口拒派生绕过、精确旧 Attempt 重新认领、S1/raw/display/审计/依赖 Job SQL 故障与完成末尾失租全部事务回滚。
- 0天用 SQLite BEFORE INSERT 拒绝触发器 / PostgreSQL `CHECK(false) NOT VALID` 禁止 raw/display 任何 INSERT，真实 typed completion 仍成功保存唯一 S1；不是先写后删除的证明替代品。
- migration17→18 含真实旧 started/queued Run、原 raw ciphertext、30天 captured display 和 unavailable display：升级逐字段保留，失败DDL整体回滚，无临时表/新列/S1/触发器残留；新整数7天通过、额外1微秒失败；PostgreSQL 原CHECK缺失/重复均拒绝且回滚。
- `go test ./internal/integrity/repository -run '^TestDerivedExecutionMaintenance' -count=1`：最后增补双库通过，5.406s；覆盖 failed/cancelled、Use多次变异、两个并发提交恰有一个 applied/一个 already_completed、错误key收据重交拒绝、审计故障回滚、消费者关闭/外来 source、SQL超界预加载拒绝，以及两种来源模式的未启动/未发请求与 legacy UNCERTAIN 恢复。真实无actor Runner context由持久Job恢复审计主体，完整审计链通过。
- `golangci-lint run ./internal/integrity/repository/...`：0 issues（固定本地工具链）。

## 未完成／恢复入口

扩大三轮回归正在运行：`go test ./internal/integrity/repository -run '^(TestDerivedExecution|TestResponseRetention|TestResponseEvidence|TestDisplayEvidence|TestExecution|TestMigrate)' -count=3`。结束后补最终结果并冻结当前单元。

下一独立必需单元是 legacy 新正文写入的统一保留边界：现有 private capture 尚只接受 derived Attempt，旧 `FinishAttemptWithEvidence` / display wrapper 仍沿历史固定30天保存，不能宣称组织0天已覆盖所有旧已确认 Run。后续应在不升级旧 signed Manifest/SQL mode、不生成 fake S1 的前提下共享私有 DB capture、原 expiry 和事务内 fresh policy，并保证 legacy 0天从未 INSERT raw/display。旧历史 raw 缺失时 legacy 分析应明确不足，不可宣称无损。

专有回归 fixture 的 opaque S1 仅证明 repository scope/事务/关系，不是密码学或真实 TLS 证据；真实 Generator/Tokenizer、Purpose MAC、HTTP Credentials.Use、BuildDerived 等价及全应用激活由相应组件/集成测试独立证明。

analysis_source/worker-analysis由backup_scope负责，Worker/run由root负责；本agent不改那些文件、不改identity_management.go，也不做Git。source认证固定为domain.ExecutionPlan.AnalysisSourceVersion（空legacy或domain.AnalysisSourceDerivedV1），真实新Manifest由generator签入；SQL列不是独立密码学凭证，旧已确认Run不重签不升级。

此前retention锁P2三个文件已冻结供root提交，不能被本批覆盖。组织policy仍NO KEY UPDATE，Job→org→execution/sample/run→audit；锁中不做提取器/MAC/加解密或网络。
