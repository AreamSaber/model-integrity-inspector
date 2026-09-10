# M5 派生 S1 读取、分析与发布接线说明

状态：本单元六文件已冻结，交 root 复核；仓储定向三轮与双包分析回归通过，另一个混合 Worker 三轮命令保留一次实际 TLS 失败，由 root 统一串行复核。不是 M5、0 天保留或 V1.0 的正式验收批准。本文只记录本单元，不替代原 PRD/开发计划。日期：2026-09-08。

## 文件和稳定接口

- `internal/integrity/repository/analysis_source.go`：`AnalysisData.Derived`、显式源模式读取、SQL 读取前预算、S1 行锁、私有源摘要。
- `internal/integrity/repository/analysis_result.go`：`PublishRunAnalysis` 在所有结果写入前复验源模式与源摘要。
- `internal/integrity/repository/analysis_source_derived_test.go`：真实 SQLite/PostgreSQL 的来源、预算、锁、恢复、策略和事务反例。
- `internal/integrity/worker/analysis.go`：`AnalysisConfig.DerivedVerifier *features.DerivedVerifier`、逐行绑定和完整 `Builder.BuildDerived`。
- `internal/integrity/worker/analysis_derived_test.go`：复用实际 TLS 执行，验证损坏源绝不回退 raw，认证后修改不得发布。
- 本说明。没有修改 app、执行器、迁移或纯 S1 格式；没有执行 Git。

复用现有 `AttemptDerivedRecord`、`DerivedRecord`、目的隔离的 `DerivedVerifier`、`Builder.VerifyDerivedRecord` 和 `Builder.BuildDerived`，没有另造记录格式或重新封存结果。实际 app 的 Builder/Verifier 注入、执行器生成、迁移和恢复写入由相邻实现单元负责。

## 模式与认证边界

1. Run SQL 模式必须是 `legacy_response_v1` 或 `mii.derived-s1.v1`，并与冻结 Plan 的对应字段一致。Worker 再通过原有签名 Manifest 重放校验整个 Plan。不能通过记录数量猜模式。
2. Derived Run 的所有 Attempt（包括非最终重试）各需要一条 S1；逐一核对组织、Run、Sample、Attempt、RequestHash、结算状态、Validity、ErrorCode、CreatedAt/FinishedAt、封存版本和持久 receipt。
3. `derived_recorded` 对应实际 COMPLETED；`derived_recovered_unavailable` 只对应 UNCERTAIN/INVALID_RETRYABLE/MI_UNCERTAIN_ATTEMPT。恢复缺少响应仍必须有明确的签名无响应观察；删掉它是损坏，不是正常缺失。
4. 真正未 Reserve 的 NOT_APPLICABLE Sample 可以没有 Attempt/S1；不伪造请求或响应。Pending/legacy receipt 不能冒充已有的派生记录，现迁移还会直接拒绝非法 receipt 降级。
5. 派生分支完全不查询 raw/display 表，也不解密响应。仅 Builder+DerivedVerifier 就可以运行，不要求一般性 EvidenceKeys。存在 raw、缺 verifier、错误 MAC/密钥或丢记录都不会切换旧路径。
6. 每个物理 SQL 行先经 `VerifyDerivedRecord` 绑定到该行声明的真实 Attempt，随后仍必须调用完整 `BuildDerived` 验证图、全部记录集合、签名 Manifest、提取器和预算。薄单行验证不能替代整批验证。交换两条完整 Payload/MAC 的 SQL 行，不能利用 flat record set 恰好相同绕过行归属。

## 读取前资源预算

读取仍只可通过真实 analyze Job 的组织/owner/generation lease。不得提供任意调用者可自行构造的源能力。

派生分支在获取所有 S2/S1 正文列之前：

- 固定 Run ID 行锁；PostgreSQL 再只读取、锁住同 Run 最多 451 个固定 Attempt ID，超过 450 立即失败。
- SQL COUNT/SUM/MAX 检查 150 个 Sample、450 个 Attempt、450 条 S1；单条 S1 Payload 最大 32 KiB，MAC/版本/错误码等分别有闭合大小上限。
- ConfigSnapshot 保留原有 8 MiB 表示上限；每条 RequestPlan 和 RequestSnapshot 使用 1 MiB 适配器 wire 上限加 2 KiB 外壳余量。固定字段、128 字节标签/模型/hash 的合法外壳低于该余量，不把整个外壳当作 wire。
- 统一逻辑预算与当前 `features.MaxBatchBytes` 的口径相同：`len(Manifest) + Σ len(RequestSnapshot.Payload) + Σ len(S1.Payload) <= 8 MiB`。不是各给 8 MiB 后装入再拒绝。Manifest 单条 2 MiB；wire Payload 单条 1 MiB。
- SQL 提取实际 JSON 对象字节，不信任 `payload_bytes` 声明。SQLite 的提取会压缩空白，因此要求本来就由现有持久化生成的紧凑 JSON；逐层路径键必须唯一，消除 SQLite 首键与 Go 末键解析差异。PostgreSQL 使用保留对象原文的 `json`，不使用会重新排版的 `jsonb`。畸形/歧义对象闭合失败。
- 存储的 Snapshot、SamplePlan 和实际 wire 是重复表示。它们有额外的表示/单行上限，但不能把同一内容的重复外壳错误加入分析器的 8 MiB 逻辑预算。纯层还会复核预算与签名，SQL 预算不代替认证。

测试把 SQL 常量与实际 `features.MaxBatchBytes`、`features.MaxDerivedBytes` 和 `openaichat.MaxRequestBytes` 对齐，防止未来独立漂移。资源检查限制的是本单元的源读取，不是大型数据库或备份容量验收。

## 发布与并发

- 初次读取完成后不在数据库锁内跑 tokenizer、密码认证或分析。Worker 在锁外生成完成能力。
- 私有 SHA-256 源摘要覆盖完整 Run/Sample/Attempt 图、所有 RequestPlan/RequestSnapshot、全部 DerivedReceipt 以及每条 S1 的全部存储字节（包括 Payload/MAC/版本/CreatedAt）。保护字段只直接编码进入哈希，不返回/记录 JSON。
- ResponseMeta 和 ResponseBodyReceipt 不进入派生摘要，避免独立正文清理改变同一个 S1 分析源；raw/display 本来也不是其输入。
- `PublishRunAnalysis` 在现有 CompleteWith lease/Run/version 检查后、任何结果/发现/成功审计写入之前，重新进行同模式的有界源读取并比较摘要；变化则整个事务回滚。
- PostgreSQL 的 S1 `FOR SHARE` 持至事务提交或取消，封闭最终摘要检查至提交之间的直接 S1 UPDATE/DELETE 窗口。SQLite 延续原有 IMMEDIATE 事务。重复 Completion 仍被原有 lease fence 拒绝。
- 锁顺序为 Job →（仅 legacy 读取策略时：organization）→ Run → S1。派生读取不获取 organization 策略锁，发布复验也不会因为 SQL 模式突变而在 Run 锁后倒取 organization。没有添加 Run→Sample/Attempt 锁，以免与现执行器顺序相反。
- 图一致性依赖应用现有 Run 锁协议。私有摘要只是当前进程的读后变化检测，不是外部签名、持久反回滚锚或抗任意管理员完整数据库重写的证明。S1 密码学认证仍由独立 verifier 完成。

## Legacy 兼容

旧 Run 仍走原始响应路径，Attempt 必须保持 legacy receipt，注入 S1 不能升级模式。加载时先取得 organization 策略锁再锁 Run，使用数据库时钟与当前窗口/单向截止线筛选最终响应；0 天和 0→180 天不会恢复已失效的旧正文。原始证据缺失仍是旧模式的部分观察，不暗中补造派生记录。

本单元不迁移历史正文为 S1，也不新增 legacy 发布前的策略重锁。旧模式维持原发布语义；禁止为了补旧模式复验而在已持 Run 锁后逆序获取 organization 锁。

## 验证证据与范围

当前已实际通过的有界检查：

- 仓储派生/旧策略双库首轮 13.296 秒，含实际 `pg_blocking_pids`：独立 UPDATE/DELETE 在最终摘要后等待发布事务；提交后继续；取消时无结果行并释放锁。不是只 sleep 推断阻塞。
- 真实双库统一预算边界 7.131 秒：实际创建/开始/Reserve/重试/结算 4 个 Sample、8 个 Attempt；逻辑源恰好 8 MiB 可加载，即使重复表示累计超过 8 MiB；多 1 字节在任何源正文列 fetch 前拒绝。GORM Query 禁读门禁证明前置拒绝。该仓储 fixture 的 Manifest/S1 是明确的非密码学测试值，不冒充真实签名业务执行。
- SQL 实际引擎验证 UTF-8、保留的转义、字符串内空格、空白压缩、重复路径键、缺键、非对象和损坏 JSON。独立大小表验证单条/总量/行数边界，不将其称作完整 Run 验收。
- Worker 实际 TLS 负例双库首轮 18.106 秒：已有真实 raw 仍拒绝缺失、坏 Payload/MAC、未知/错误密钥、完整签名行交换、缺 verifier 和取消；0 天无 raw/display INSERT 的真实执行在认证后修改 S1 时拒绝发布，恢复原 S1 后原有效 lease 能正确发布，重复不能发布。
- root 的 `TestDerivedWorkerActualTLSZeroAndThirtyDaysPublishRealAnalysis` 复用同一真实签名/TLS执行：0 天仅 S1 完整分析，30 天 actual raw 以精确 AAD 解密后经显式 `BuildResponseReference` 得到完整 analyzer JSON，与实际 published 文档逐字一致。该端到端证据由 root 所有测试提供，不以仓储 opaque fixture 替代。
- `golangci-lint run ./internal/integrity/repository/... ./internal/integrity/worker/...`：0 issues。

冻结前最终结果：

- `go test ./internal/integrity/repository -run '^TestAnalysis(Derived|LegacyPolicy)' -count=3`：真实双库 PASS，309.998 秒，覆盖新统一预算和 PG 行锁。
- `go test ./internal/integrity/repository ./internal/integrity/worker -run '^TestAnalysis' -count=1`：真实双库 PASS，repository 219.545 秒、worker 187.123 秒，含旧分析兼容与新负例/读后修改。
- 混合 Worker 三轮（本单元两个 `TestAnalysisDerivedWorker*` 加 root 的 `TestDerivedWorkerActualTLSZeroAndThirtyDaysPublishRealAnalysis`）：整命令 FAIL，299.510 秒。报告的失败是后者 `days_0/postgres` 在剩余实际 TLS 执行中返回 `DATABASE_UNAVAILABLE`（root 文件当时第 129 行）；不能把该命令称作全绿。自有两个测试未报告失败，但不以此消去整命令失败。
- 只读 PG 活动核对确实观察到并行测试的迁移 advisory-lock 争用和持续前进的 schema-create/WAL 活动；尚未证明它是上述 TLS 失败的唯一根因。保留失败、未放宽测试/生产界限；root 接手统一串行复核，避免再次堆叠测试批次。
- 最后一次 repository/worker `golangci-lint`：0 issues。冻结后不再改本单元文件或自行重跑。

本机双库验证不是尚未运行的新 CI 结果，也不是正式 TL/OPS/SEC 审批。
