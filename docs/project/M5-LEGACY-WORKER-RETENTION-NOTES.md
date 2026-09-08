# 已确认旧运行的正文保留策略接线

2026-09-08，兼容接线与专项/应用回归已通过；全Worker出现独立停机失租故障，未宣称全绿。未代表完整正文生命周期验收或正式批准。

新签名派生模式已提交52557c3，但旧已确认Manifest不能被隐式重签或升级。本单元把实际Worker在Credentials.Use内部的策略/时间捕获统一用于两种来源。旧模式完成时改用 `FinishLegacyAttemptWithCapture`，保留旧 raw 分析语义，不调用派生提取器、不制造 S1。

私有 capture 在实际响应后独立 WithLease 内生成，完成事务不补造过去的捕获证明。真实加密 raw 与经过凭证脱敏的 display 绑定原捕获时间/期限，再由完成事务按最新组织策略决定是否 INSERT。未捕获与不保留是明确不同状态。原旧无 capture 的带正文内部入口改为闭合拒绝，不能通过手填 created_at/expiry 绕过策略。

root 新增 `worker/run_legacy_retention_test.go` 并复用原真实签名/TLS fixture（生成前选择空 legacy mode），没有更改确认后的Manifest。现已实际通过的双库首轮6.308s覆盖：

- 0/7/30/180天正常结算，raw/display精确共享原DB捕获时间，期限不再固定30天。
- 完整18样本在0天和30天均可发布旧模式分析；0天从开始到结束由数据库约束禁止正文INSERT，全部无S1，结果明确为INSUFFICIENT、证据D、空风险分数；30天真正保留的响应仍有有效测量。
- Run SQL mode保持legacy，原ManifestHash及整个ConfigSnapshot逐字节不变，HTTP请求恰为实际计划样本数，完整审计链有效。

共享真实TLS捕获后禁用/0→30/截止线后延长反例保持禁写数据库约束。API结果fixture也已迁移为先WithLease捕获、后完成结算，原HTTP/权限断言未改变。

本轮root真实验证：

- 首次全Worker双库140.420s失败，只涉及取消/轮换/熔断三组旧测试要求无响应的中断请求仍有raw envelope。上游从未发送headers/body；真实取消后WithLease不可新mint capture，不能为了旧断言放宽生产权限。改为严格断言COMPLETED+legacy+not_captured、raw/display均无行、原stop错误码/NOT_APPLICABLE及审计；原5秒中断/计数/预算/不重复请求断言保持。
- `go test ./internal/integrity/worker -run '^(TestLegacyWorker|TestRunWorkerCircuitCancelsInflightWithoutUserCancellation|TestRunWorkerCancellationAndRotationAbortInflightWithinFiveSeconds)' -count=3`：真实SQLite/PostgreSQL通过31.893s，包含新增策略变更反例及上述兼容断言。
- `go test ./internal/integrity/api -run '^TestRunResultHTTP' -count=3`：SQLite4.683s、显式PostgreSQL8.354s通过。
- `go test ./internal/app ./tests/contracts -count=1`：app真实SQLite/PostgreSQL27.416s，contracts0.236s通过；包括实际0/30天初始化→TLS→分析→复核/基线/JSON/HTML报告→再次检测。
- Worker/API lint 0 issues。全Worker第二轮146.047s结束：旧raw兼容断言已通过，但`TestRunWorkerCircuitStopsFurtherActualRequests/model/postgres`一次正常清理返回JOB_LEASE_LOST。保持失败记录，正在核查SQL取消是否被误标为失租；未吞掉错误，也不将专项通过当全量通过。

前次已推送52557c3的CI34183736103：Windows job101927828281在`TestRunWorkerHTTPFailuresAndPartialStreamAreTruthful/limited/sqlite`失败，日志为renew→DATABASE_UNAVAILABLE、12秒未完成，package.ps1:46因Go测试失败退出。它发生在旧提交，不是上述新兼容断言失败；Windows job没有PostgreSQL，不能套用此前本机PG迁移竞争解释。具体driver/等待根因未证实，正在单独诊断。Linux包/镜像/六repo-race/依赖扫描成功，quality最近查询仍在运行，不称整体全绿。

原历史正文已不可用的运行不能获得无损S1回填。正文授权HTTP/UI、独立请求复现载荷和清理尚未接线，本单元不关闭REP-003、REP-005或完整M6-07。
