# Legacy 正文保留接线 checkpoint

日期：2026-09-08。状态：仓储单元完成、真实SQLite/PostgreSQL最终组合三轮通过，已冻结供root复核/提交；不替代整应用验收与批准。前批9405e03/52557c3不回改，不改历史迁移1～18，本批不需要migration19。

## 接口及边界

- `BindAttemptResponseCapture` 支持精确 legacy SQL mode+DerivedLegacy 或 derived mode+DerivedPending；私有sourceMode绑定在同一scope/generation/capture/expiry上，拒跨源使用。
- 新 `FinishLegacyAttemptWithCapture` 复用事务内实际最终取消/stale/预算分类、同一组织policy锁、原capture/expiry、最终fresh DB时间、条件raw/display写入和body receipt CAS；不制造S1、不重签/升级旧Manifest或SQL来源。未知usage预算保守计费修复保持。
- 旧 `FinishAttemptWithEvidence` / `FinishAttemptWithEvidenceAndDisplay` 无私有capture，一律明确ErrAnalysisSource（已关闭tx为ErrTransactionClosed）；不在完成时补mint、不静默丢正文而声称成功。仅保留这两个入口作为拒绝边界，真实Worker由root迁移。
- nil capture明确not_captured；0天/原expiry/单调cutoff拒绝为not_retained，raw/display从未INSERT。legacy没有原始正文时只能向旧分析提供明确缺失，不可fallback成派生S1。
- 锁顺序仍Job→org NO KEY UPDATE→execution/sample/run→audit；网络/secret/加解密不在事务内。原Reserve/WithLease取消与lease检查不放宽，完成专用路径仍由CompleteWith前后精确fence授权。

## 文件范围与验证

evidence_capture拥有repo生产最小接线、`execution_legacy_body_test.go`、本说明，以及repo旧fixture迁移（包括analysis_source_test.go的一处fixture，**不改analysis_source.go**）。root拥有Worker/app，derived_s1已迁移api旧fixture。

已执行（固定本地Go工具链，既有PG DSN静默读取，无新启动/停止PG）：

- `go test ./internal/integrity/repository -run '^$'`：可编译。
- `go test ./internal/integrity/repository -run '^(TestLegacyBodyCapture|TestDisplayEvidence|TestResponseEvidence|TestExecutionBreakerAuditRollback|TestAnalysisSource)' -count=1`：实际双库首轮通过18.678s。
- `go test ./internal/integrity/repository -run '^(TestLegacyBodyCapture|TestDerivedExecution|TestDisplayEvidence|TestResponseEvidence|TestExecutionBreakerAuditRollback|TestAnalysisSource)' -count=3`：最终实际双库三轮全部通过145.782s，exit0。独占本轮数据库验证，无遗留测试进程。
- `golangci-lint run ./internal/integrity/repository/...`：0 issues；专有diff --check通过。

验证范围：0/7/30/180、0→180、先捕获再0→180、短期再延长、已封expiry不延长、scope/mode/gen错误、旧入口拒绝与真实Job取消。0天及被cutoff拒绝的场景都安装SQL禁止raw/display任何INSERT的断言，正常结算依然成功；不是写入后删除。0天额外强制SQL审计INSERT失败，Attempt/Job/Run/receipt完整回滚；解除精确测试故障后同一capture可正确完成，仍从未写body。原display raw/display/审计/依赖Job SQL故障及末尾失租全部事务回滚也已迁移并通过。

最终组合同时回归新derived的S1/正常/重新认领/维护/迁移18路径，未改变其来源义务。legacy ConfigSnapshot/ManifestHash/SQL来源保持逐字节不变、S1表始终为空；0天分析仓储source保留真实Attempt且明确缺少raw，整应用 `INSUFFICIENT/D/nil risk` 判定以root真实Worker/app测试为准。

为覆盖8天等待，专有短期场景会在**仅内部测试fixture**中同步前移已有私有capture和matching Attempt开始时间，再用真实管理设置与真实DB完成校验；这是边界回归，不冒充真实等待8天或HTTP可创建capture。真正0天及0→180场景无时间模拟，使用DB禁止INSERT断言。

精确生产文件：`execution_attempt.go`、`execution_derived.go`、`execution_derived_body.go`、`execution_evidence.go`、`execution_display.go`。旧fixture仅改`analysis_source_test.go`、`execution_breaker_test.go`、`execution_evidence_test.go`、`execution_display_test.go`；新增专有`execution_legacy_body_test.go`及本文。未改Worker/app/API/analysis_source.go/secret/历史迁移，不做Git。
