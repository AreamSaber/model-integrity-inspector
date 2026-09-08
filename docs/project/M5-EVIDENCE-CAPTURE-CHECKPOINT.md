# REP-003 / REP-005 Phase 2a：实际 Worker 展示副本采集 checkpoint

日期：2026-09-08。状态：Phase 2a 实现与本地双库验证已冻结，待 root 集成自查；正式审核仍待统一执行。只覆盖采集与原子持久化，不代表正文读取、复现导出或 0 天留存已完成。

## 恢复入口与所有权

- 已完整阅读 `M5-EVIDENCE-DISPLAY-NOTES.md`、PRD 9.8/10.3/11、TECH 10.10/12.2/13/18、ADR-0002/0004/0006。
- 当前专有文件：`internal/integrity/worker/run.go`、`execution_http.go`，新增 `internal/integrity/repository/execution_display.go`，新 migration `000016_evidence_display` 的 common/sqlite/postgresql 三文件；`migrations/migrations.go` 仅追加名称注册。后续测试限相应新 `execution_display*_test.go` / Worker display 测试。
- 不改写既有 000001～000015，不覆盖其他 agent 的系统状态、会话、离线回放、S1 派生、OpenAPI、需求矩阵和持续开发台账；由 root 集成提交。

## 已落盘实现

1. `NewRunHandlers` 在现有必填 EvidenceKeys 基础上一次派生独立 DisplaySealer；也允许可信启动注入窄 sealer，无新增 HTTP 能力。
2. 在实际 `Credentials.Use` 内、实际响应和 tokenizer 已完成后，严格解码该持久 Attempt 的 pre-auth RequestSnapshot，以实际 Key 与全部自定义 Header 值构造 `Prepared` 并立即 Seal/Close。不修改原 NormalizedResponse、Outcome、请求 hash 或分析 ContentHash。
3. 独立最长 2 秒子上下文的短 `Queue.WithLease` 事务验证 Attempt/job/generation 并获取数据库 UTC 微秒。网络和 Prepare/Seal 不在事务内；密文 AAD 固定该时间和采集起算 30 天 expiry。
4. 新 display 表只有闭集状态、S1 绑定、密文，无明文列。结算包装原 `FinishAttemptWithEvidence`；Attempt、依赖 Job、审计、分析密文与展示行同事务。旧结算路径不回填历史展示证明。
5. 脱敏、超限、取消、来源不合法、采集失败、Seal/时钟失配仅生成闭集 display unavailable；不把 raw 密文解密后补做展示。

## 当前验证与下一步

恢复时上述代码及 SQL 已落盘；恢复后的实测如下。不得把之前 Phase 1 纯组件测试冒称本阶段的 Worker 验证。

- `go test ./internal/integrity/worker ./internal/integrity/repository -run '^$' -count=1`：编译通过，0.112 / 0.103 秒，仅编译检查。
- 新 `execution_display_test.go`（repository）：14 类绑定错误、7 种 captured/unavailable 持久化状态，实际 SQLite trigger / PostgreSQL CHECK 故障注入方案覆盖 display insert、raw insert、finish audit、dependent analysis Job；另覆盖事务尾部 lease expiry 围栏、旧路径不回填、失去 owner、逃逸的已关闭 tx、必须使用 CompleteWith、错误持久 scope、fmt/JSON/slog 禁止泄露。
- 新 `execution_display_test.go`（Worker）：实际 TLS bearer 和 custom-header 两种认证；全部自定义 Header 使用不含 key/token/auth 的普通字段名，实际值与固定编码出现在响应和冻结请求；实际 Key 跨 SSE content_delta。精确 AAD 解密展示后检查无这些 canary，并核对 raw analysis Content、ModelReported、全部白名单 metadata、tokenizer 结果、Usage、时间与事件完全未被展示改写。短 Header/本机时钟落后或超过 sealed expiry/坏 sealer 均只出现闭集 unavailable，成功 Attempt 和真实分析保留。
- `go test ./internal/integrity/repository ./internal/integrity/worker -run '^(TestDisplayEvidence|TestRunWorkerDisplay|TestRunDisplay)' -count=3`：4.867 / 3.516 秒通过。**此轮未配置 DSN，仅证明 SQLite；PostgreSQL 被标准 fixture 跳过。**
- 新增真实 TLS 采集完成后、提交前替换 owner / display SQL 故障 / finish audit SQL 故障；以及在全部 typed 写入后真正取消提交 context，保证无 display/raw/依赖 Job/finish audit 残留、Attempt 仍 DISPATCHED 且仅有一次上游请求。该测试 SQLite 三轮 1.707 秒通过。
- 相关 worker/repository `golangci-lint run` 第二轮 0 issues；完整 Worker 包 `go test ./internal/integrity/worker -count=1` 30.711 秒通过（仅 SQLite，未设置 PostgreSQL DSN）。
- 新 `execution_display_migration_test.go` 真实迁移到既有 15 版本前缀，执行完 16 的 DDL 后注入不存在表写入以验证表、索引及迁移行均回滚；再重试实际迁移，校对旧 15 行的名称/校验和/状态/应用时间完全不变，展示表为空且两类索引存在。SQLite 三轮 0.300 秒通过；不冒称已验证填充历史正文的数据升级场景。
- 第一次显式设置现有测试 DSN 的执行在所有 PostgreSQL fixture 创建 schema 前失败；只读核实 15432 无监听且无 postgres 进程，由 root 接手恢复现有 cluster。**此失败没有被当作双库通过或归因到业务断言。** 恢复后的实际重跑见下项。

2026-09-08 最终双库增量验证：root 恢复既有 cluster 后实际 `pg_isready` 确认 127.0.0.1:15432 接受连接；从既有 `dsn.txt` 静默载入 `MII_TEST_POSTGRES_DSN`，没有更换数据库或用 Skip 代替 PostgreSQL。执行 `go test ./internal/integrity/repository ./internal/integrity/worker -run '^(TestDisplayEvidence|TestRunWorkerDisplay|TestRunDisplay)' -count=3`，**全部 SQLite + PostgreSQL 三轮通过：40.708 / 34.803 秒**。此轮已包含全部上述最终反例及实际 TLS 用例。随后 **完整 Worker 包双库 `go test ./internal/integrity/worker -count=1` 通过，114.548 秒**；包含原分析、取消、失租、费用预算、预检、报告与错误证据等既有 Worker 回归。最终相关 worker/repository lint 0 issues，所改 tracked 文件 `git diff --check` 通过。生产、SQL 与测试文件已冻结供 root 集成自查。

## 冻结文件清单

1. `internal/integrity/worker/run.go`
2. `internal/integrity/worker/execution_http.go`
3. `internal/integrity/worker/execution_display_test.go`
4. `internal/integrity/repository/execution_display.go`
5. `internal/integrity/repository/execution_display_test.go`
6. `internal/integrity/repository/execution_display_migration_test.go`
7. `migrations/common/000016_evidence_display.up.sql`
8. `migrations/sqlite/000016_evidence_display.up.sql`
9. `migrations/postgresql/000016_evidence_display.up.sql`
10. `migrations/migrations.go`（仅追加16注册）
11. 本 checkpoint 文档。

未修改 `execution_evidence.go`：旧分析结算被新方法复用，不更改其既有语义。未进行 Git add/commit/push，未编写或虚构正式审批记录。

初次自查修复了捕获短事务的模式检查：`WithLease` 必须为 completing=false，不能误用 `CompleteWith` 的 true。旧 Worker 测试仅检查分析结果，无法证明 display captured；新增正例显式断言 captured 与认证后正文，从而避免以 unavailable 偷换展示实现。

## 明确保留的边界

- 当前仍固定 30 天；组织 0～180 天配置、单调 cutoff、清理和 0 天可信派生 S1 路径未接入。
- display source hash 是既有纯组件对原 NormalizedResponse 和核对 wire hash 的域分隔摘要，不是分析 ContentHash 或 HTTP 全字节哈希。
- DB 和本机时钟不假设一致。默认 crypto 时钟若拒绝 DB 时间，则保存 `unavailable_seal`；不得放宽 AAD/time 验证或移改时间冒充可用。
- 仍未提供正文读取 API、解密旁路、网页正文、模板下载或正式批准。
