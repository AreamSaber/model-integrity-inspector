# M5 派生 S1：Worker / 结算 / 恢复装配说明

日期：2026-09-08。性质：对当前代码的只读核对与下一代码单元的接口建议；本次只新增本说明，没有实现 Worker、仓储、迁移或应用装配。

本说明不表示“0 天原始响应保留”已经交付，不替代真实 SQLite / PostgreSQL Worker 验证，也不修改既有算法版本或验收结论。

## 1. 结论

最小正确方案是：**真实 Worker 在事务外，用同一份实际响应和原 `DeriveAttempt` 生成最多 4 个闭合终态候选；完成事务按实际最终 Attempt 状态选择唯一候选，原子持久化该 S1、结算、最终样本、依赖 Job、审计以及策略允许的原始证据。** 不重写已封存的 outcome hash，不在数据库锁内重新跑 tokenizer / 行为提取或 HMAC。

恢复路径同样需要真实、显式的无响应可用观测；它不需要 `Credentials.Use`。正常重新认领和维护恢复都必须装配，不能让后者绕过 S1。模式由持久 Run source version 决定，不由 `len(records)>0` 或当前组织保留天数猜测。

## 2. 当前代码证明的装配约束

| 边界 | 当前代码 | 对装配的影响 |
| --- | --- | --- |
| 最终结果可能改变 | `internal/integrity/repository/execution_attempt.go:331`，尤其 357–370 | `FinishAttempt` 在事务内把结果改为取消、目标过期或预算过期；预算过期可以覆盖目标过期，取消优先。Worker 事先预测的唯一结果不可靠。 |
| 真正落库状态 | `internal/integrity/repository/execution_attempt.go:377`、436 | `settleAttempt` 决定 `COMPLETED` / `UNCERTAIN`，持久化实际 outcome，释放预留，选择最终 Attempt 或重试，写审计。 |
| 改外层 hash 不够 | `internal/integrity/analysis/features/mapping.go:48`、53、59、146、191 | UNCERTAIN、无 Evidence、无效终态会提前返回；Validity、Included、Limitations、NetworkFailure、tokenrisk 与行为绑定都可能不同。只改 `OutcomeHash` 会留下不一致的有效样本特征。 |
| 可以事务外准备 | `internal/integrity/analysis/features/derived.go:80` | `DeriveAttempt` 校验实际 Manifest / SamplePlan / wire / scope，但不要求伪造 FinishedAt、Run 关闭时间或最终样本指针。 |
| 签名最终核验 | `internal/integrity/analysis/features/derived.go:156`、170、212 | `BuildDerived` 要求每个实际 Attempt 恰有一条记录，并与真实已提交状态逐一匹配；重试的非最终 Attempt 也不能缺。 |
| 重新认领直接恢复 | `internal/integrity/worker/run.go:120`、`internal/integrity/repository/execution_recovery.go:16` | 发现旧 DISPATCHED 后在加载完整 Plan / Credentials 之前返回恢复 Completion；必须专门装配 S1，不能依赖正常响应回调。 |
| 维护路径直接结算 | `internal/integrity/repository/execution_recovery.go:150`、199 | `ReconcileExecution` 对 failed/cancelled 终态 Job 直接 `settleAttempt(..., uncertain=true)`，目前没有 Worker 提取器。 |
| 已有维护注入点 | `internal/integrity/worker/run.go:87`、`internal/app/app.go:165` | 可以扩展现有 `worker.ReconcileRunJobs` 的可信配置，让 app 注入 Builder / purpose-only sealer，不给 repository 增加 features / secret 依赖。 |
| 原始分析目前允许过期缺失 | `internal/integrity/worker/analysis.go:68`、114；`internal/integrity/repository/analysis_source.go:159` | 当前仅加载未过期的最终响应密文，缺失 Evidence 留 nil。这只能留在显式 legacy 路径，不能成为派生模式的回退。 |

## 3. 正常 Worker：4 个闭合候选

建议新建 Worker 内部帮助文件，例如 `internal/integrity/worker/run_derived.go`，持有实际 app 注入的同一 `*features.Builder` 与 `*features.DerivedSealer`。独立用途 MAC 可使用现有 `secret.KeyRing.NewDerivedSourceMAC` → `features.NewDerivedCapabilitiesWithMAC`；不要把一般 KeyRing 传进 features。

准备顺序：

1. 读取并验证真实 Run / SamplePlan / Attempt wire 快照。实际 Attempt ID、Job ID、AttemptNo、Probe ID 和 ordinal 取既有仓储记录，不能自行生成。
2. 得到 `callRunSample` 的真实结果；先落实 `run.go:196` 的 watcher 分类，包括 circuit。
3. 先落实既有响应大小限制分支，再确定本次共同的分析输入。`run.go:216–224` 目前可能把 outcome 改为 `INVALID_SAFETY_LIMIT / MI_EVIDENCE_LIMIT` 并只封存 minimal response；如果派生仍用完整原响应而 raw oracle 使用 minimal，0 / 30 天将产生分歧。最小装配应把这里实际选用的同一响应显式传给两条路径，保留 Attempt 真实 usage / cost 字段。不能因 0 天跳过加密而漏掉同一大小限制分类；可暂时维持纯内存加密 / 大小检查，但 0 天不得执行原始证据的数据库写入。
4. 用同一份响应、Manifest 和 wire，生成以下去重后的候选，最多 4 个：

   - `COMPLETED / <实际 outcome.Validity> / <实际 outcome.ErrorCode>`。
   - `COMPLETED / NOT_APPLICABLE / MI_EXECUTION_CANCELLED`。
   - `COMPLETED / NOT_APPLICABLE / MI_EXECUTION_TARGET_STALE`。
   - `COMPLETED / NOT_APPLICABLE / MI_EXECUTION_BUDGET_EXCEEDED`。

5. 每个候选都重新调用原 `DeriveAttempt` 和 `Seal`。取消 / stale / budget 的候选在原提取器的非有效状态分支提前返回，不重复完整 tokenizer / behavior 工作。禁止只复制原候选后替换 Validity、OutcomeHash、Included 或 MAC。
6. 原始候选已经是这三种覆盖状态之一时去重；重复终态键、越界候选数、未知 source version、错租户 / Attempt / wire、空记录一律拒绝。候选集合仅驻留可信 Worker 内存，不能把 4 条都落库。

事务接口可采用新的仓储 DTO（名称可调整）：

```go
type AttemptDerivedCandidate struct {
    // 仅固定身份、最终状态键、版本、最大 32 KiB 的 opaque S1 与 MAC。
    // 不含 NormalizedResponse、request body、KeyRing 或任意回调。
}
// 通过既有 CompleteWith 使用；候选数 1..4。
FinishAttemptWithDerivedEvidenceAndDisplay(sampleID, attemptID, outcome, jitter, candidates, evidence, display)
```

事务先遵守 `response_retention.go:95` 的锁顺序，取得组织保留策略，再进入既有 execution mutex / sample / run / target 锁。完成最终 outcome 判定后，按 **实际 `Status / Validity / ErrorCode`** 选择唯一候选。repo 只做固定元数据 / 长度 / 唯一性校验与选择；完整 S1 MAC、提取器、Manifest、wire、时间图校验仍在分析 Worker 执行。

可以重构私有 `finishAttempt` 返回实际最终事实，或在同一事务中精确重读刚结算的 Attempt。不得再用调用者原 outcome 选择，也不得把 `closeExecutionIfFinished` 提前提交。选择失败必须使整个事务回滚，不能单独成功结算后留下“应该有 S1 但没有”的完成行。

原始证据和展示证据的期限不能作为 S1 的期限。0 天时只允许持久固定的禁用 / 未捕获状态与 S1，不允许插入正文密文再删除；事务提交、WAL、触发器、失败回滚路径均不能经过一次正文写入。

## 4. 取消上下文不能复用错误

`callCtx` 是网络执行上下文，watcher 会主动取消它；`DeriveAttempt` 和 `Seal` 都检查传入 context。真实响应已经收到后继续用已取消的 `callCtx` 提取，会把本来应正常完成的取消变成派生失败。

S1 提取不需要密钥明文或 header，因此可在 `Credentials.Use` 结束后、实际响应仍在可信 Worker 内存时执行。需要区分：

- handler / 完成上下文仍有效，仅 `callCtx` 因业务取消、目标过期、截止或 circuit 取消：使用有界的 handler 派生上下文，不重新打开任何网络工作。
- Runner `CheckLease` 收到 `ErrJobCancelled` 时也会取消 jobCtx（`runner.go:278` 起）；此时要通过明确的、短期有界的纯计算完成上下文准备取消候选，例如在允许的业务终止分类下使用 `WithoutCancel` 派生出截止时间。它不授予提交权限；真正提交仍必须使用 Runner 的既有 `CompleteWith` 和事务前后租约校验。
- consumer / lease 丢失、父 Runner 关闭不应借派生上下文绕过 fence 或延长网络请求。现有 Runner 父上下文关闭时不会提交 Completion；允许走真正的后续恢复。

不要把“任意取消后无限脱离父上下文计算”作为通用策略。候选数、输入字节、总耗时都必须有界，且保留现有 5 秒 handler 收口与 10 秒完成事务约束。纯层目前只在阶段边界检查 ctx，不能声称可以强行中断任意内部 CPU 工作。

已收到的正常完整响应不能为了避免候选生成失败而主动改成 nil / UNCERTAIN。MAC / 配置 / 格式失败属于真实完整性或操作失败，应保持失败可见，不能发布一份“正常缺失”的成功分析。真正进程中断导致未持久化响应不可得时，恢复的 UNCERTAIN 表示“无法证明结果”，不表示 HTTP 一定没有收到响应。

## 5. 两条恢复路径必须同时闭合

### 5.1 旧 DISPATCHED 被重新认领

在 `executeRunSample` 当前恢复分支中，以新一代真实 lease 有界读取冻结的 Run Plan、SamplePlan、旧 Attempt wire。读取不应依赖 `CheckExecution` 成功，因为取消 / stale / 已过期恰是需要释放预留的场景。

使用 **旧 Attempt 的 JobID / AttemptNo / 请求快照**，准备唯一：

```text
UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT
Evidence = nil
```

再调用扩展的 `RecoverInterruptedSampleWithDerived`。完成事务继续检查旧 `LeaseGeneration < 当前 lease.Generation`、DISPATCHED、sample/job 归属，并原子写入显式恢复 S1 和既有保守计费 / 释放预留 / 完成状态。

这里无需当前 target 仍有效，也无需解密 / 使用当前 Secret；Secret 已轮换或删除不应阻止处理旧账。不得把旧 generation 改写进派生 scope 的 JobID，亦不得创建一个新的 HTTP Attempt 或自动重试未知请求。

### 5.2 failed / cancelled Job 的维护恢复

优先扩展已有 `worker.ReconcileRunJobs` 注入 `Builder + DerivedSealer`。建议把 repository 维护操作拆成“有界读取恢复 source → 事务外准备 → 重新验证并结算”，而不是在 repo 事务里调用 feature / crypto callback。

可新增 private-receipt 风格的 `ExecutionReconciliationSource` 和对应 `LoadExecutionReconciliations` / `ReconcileExecutionWithDerived`：

- source 由既有 Queue consumer 权限读取并绑定 store、org、Job ID、Job generation、终态、Sample / Attempt ID、原 wire / Manifest 身份；只含有界冻结输入，不含响应正文。
- source.Use 在事务外借出冻结输入，Worker 生成同一个 UNCERTAIN / nil-Evidence 候选。
- 最终事务重新锁定 Job 并复核 consumer、Job 仍 failed/cancelled、sample 未完成、Attempt 仍原 DISPATCHED、wire / Manifest 未变。不要把一次读锁或 source 当作永久租约。
- 其他合法恢复已经先完成时，按明确的 stale-source / 已完成结果重扫，不重做结算、不重写 S1、不整批回滚已完成的独立小事务。
- 必须维持 Job → org policy → execution mutex → sample / run / target → audit 的顺序，沿用 `workerAuditContext`。不要创建第二个 SQLite consumer。
- 当前 maintenance 总预算只有 2 秒（`runner.go:184`）；不能把 100 个 Manifest 验证塞入一个持锁回调。每轮按条目数和总字节有界（可先每轮少量），预算耗尽是留下下一轮继续处理的进度状态；真实 I/O / scope / MAC 失败才是失败。不要靠无限加长维护超时绕过心跳保护。

repo-only 旧恢复入口对 **要求派生的 Run** 必须拒绝“没有候选还直接 settle”，否则 app 的正确装配依然可被另一入口绕过。显式 legacy Run 可继续旧入口。

若选择“先 settle 并记录 pending-recovery receipt，下一轮补派生”的替代方案，需要额外的、不可混同 ready / missing 的状态机、受 fence 的补齐能力与分析等待规则；不能只写 UNCERTAIN 后让 analysis 为任意缺记录自动生成 nil Evidence。相比之下，两阶段准备后原子恢复更小、更接近当前纯层的每 Attempt 必有记录约束。

## 6. 持久模式、完成 receipt 与 legacy

建议新增 Run 级 `analysis_source_version`（闭合值 `legacy_response_v1`、`mii.derived-s1.v1`，具体存储拼写统一即可）。模式在实际开始 Run 时冻结。

- 实际 app 向 `NewRunHandlers` 注入已经建立的 Builder 与独立 sealer。Plan handler 使用 `StartRunWithDerivedSource`，不能因配置缺失悄悄回退旧 `StartRun`；缺能力应在启动阶段失败。
- `StartRunWithDerivedSource` 只允许未开始、没有 Attempt 的 Run 从兼容默认模式进入派生模式，并与 StartRun / 首次 Job 分派原子提交。已经开始的 legacy Run 继续 legacy；已经开始的派生 Run 幂等保持派生，不能降级。
- 迁移把真实历史数据明确置为 legacy；不要从“现在有没有派生表行”反推模式。已有未开始 Run 可以在其首次真实 StartRun 时启用新模式，已有开始记录不可追认。
- `ReserveAttempt` 依据冻结 Run 模式声明该 Attempt 的派生义务。可以在 Attempt 上镜像 source version / receipt state，便于检查恢复和完整性；不能只依赖另表是否存在。

最小完成状态建议：

| 持久状态 | 合法行集与含义 |
| --- | --- |
| `legacy_not_recorded` | 只允许显式 legacy Run；不宣称有 S1。 |
| `derived_pending` | 只允许仍 DISPATCHED 的实际 Attempt；表明完成时必须交付 S1。 |
| `derived_recorded` | 已完成实际观测；必须恰有一条相同 org / run / sample / attempt 的 S1，且 MAC、scope、版本能通过。 |
| `derived_recovered_unavailable` | 只允许受恢复 fence 生成的 `UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT`；同样必须有完整的认证 nil-Evidence S1。 |

以上状态名称只是建议，不要求额外引入正常的“派生失败即成功缺失”状态。需要持久派生失败时，必须作为显式失败处理，不能使分析变成成功的低证据报告。

不要将 `Content==""`、HTTPStatus 0、usage 缺失、refusal、部分流等都变成 nil Evidence。真实 transport 已返回的 NormalizedResponse 即使没有正文仍有真实协议 / 时序观测。恢复的 nil 表示该执行结果在可信边界不可用，不能用于覆盖已完成记录的丢失。

legacy 兼容只允许通过明确模式进入旧 raw 路径；不是为派生模式兜底。历史已发布结果可按既有不可变结果读取。legacy 未完成 Run 如果原始响应已经过期，不能宣称靠新 S1 实现了 0 天无损重分析；应保留显式 legacy / 证据不可用的边界。若未来要升级历史 Run，需要独立、可审计的从真实可解密证据生成 S1 的回填工作，不能随读随造或根据 metadata 猜测正文特征。

安全注意：source version / receipt 不是单独的密码学证明。如果威胁模型包含攻击者同时修改 Run 模式和整套数据库行，应进一步将 source version 绑定到签名 Manifest 或独立的认证启用 receipt，防止把派生 Run 改标 legacy 来规避缺失拒绝。至少当前应用代码不得提供任何回退 / 更新模式的普通入口，也不能把空值当自动识别。

## 7. 分析读取装配

建议在 `AnalysisData` 增加冻结 source version 与所有 Attempt 的有界派生记录；`LoadRunAnalysis` 必须读取 **所有实际 Attempt 的 S1**，不能沿用 raw evidence 的“仅最终 Attempt”查询。

- SQL 读取前限制记录数、每条 payload 32 KiB、MAC 32 字节、闭合版本、总字节；和 `BuildDerived` 的最多 450 Attempt、8 MiB（包含 Manifest / wire / payload）限制一致，避免先装入巨量损坏数据再验证。
- 对派生模式，检查 Attempt 义务 / receipt 与 S1 行集恰好匹配；跨 scope、重复、缺行、未知版本、错误终态、孤立记录都拒绝。无 Attempt 的 NOT_APPLICABLE 样本不凭空造 S1。
- `analysisInput` 分出明确的 legacy / derived 构造路径。derived 构造完整持久状态图，但不解密 raw response、不赋 `AttemptBinding.Evidence`，调用 `BuildDerived`；不能 `BuildDerived` 失败后再调用原 `Build`。
- raw / display 的过期与保留策略不删除 S1，也不改变派生模式。0 天与 30 天的新 Run 都走同一派生分析路径；30 天 raw 解密路径保留作独立测试 oracle，不是生产自动回退。
- MAC / source version / wire / final pointer / retry 记录失败必须保持明确失败，不当成 `MI_FEATURE_EVIDENCE_MISSING` 的正常输入。

## 8. 下一单元必须具备的真实验证

1. SQLite 和 PostgreSQL 各跑真实 Worker → Queue.CompleteWith → repository → Analysis：同样真实响应，0 / 30 天最终 analyzer JSON 对照，同时用 30 天独立原始响应 oracle 证明不是“派生与派生互相比”。
2. 在返回真实响应后、完成事务前分别触发取消、target stale、deadline 到期，以及 stale + deadline 同时发生；断言只落最终那条候选且所有 scope 匹配、费用 / 预留正确。
3. callCtx 已取消与 Runner JobCancelled 两种上下文路径分别验证；断言不会多发请求、不会跳过租约、不因普通业务取消留下必须靠恢复才能结算的悬挂 Attempt。
4. 重新认领旧 DISPATCHED 和 failed/cancelled maintenance 两条路径都验证 Secret 不可用 / 已轮换仍能生成认证 UNCERTAIN，不重发 HTTP，释放全部预留；重复执行幂等。
5. 删除已完成派生记录（包括非最终重试）、改 receipt、复制跨 org / Run / sample / attempt、改 outcome、改版本 / MAC 后，分析全部硬失败；即使 30 天 raw 密文仍存在也不能回退成功。
6. 源模式迁移：已开始 legacy 不升级；未开始 Run 首次 StartRun 启用；派生模式不按表内行数或当前 retention 改变；无能力的实际 app 启动失败。
7. 0 天数据库断言 response / display 正文密文行从未插入（不能只查最终数量为零）；验证 policy 在捕获后改成 0、0 → 30、过期 / cutoff 后上调都不复活历史正文。S1 与审计 / 计费不受影响。
8. 真实空正文、网络失败、refusal、部分流、usage 缺失、ErrEvidenceLimit、非最终重试分别覆盖；断言没有为了通过派生验证把真实响应改 nil 或丢弃有效测量。
9. 任一 S1 写入 / 审计失败使整个完成事务回滚；数据库 commit、Job fence、并发维护竞争不会造成“Attempt 完成而 S1 缺失”。不能把损坏资料的拒绝误报为取消 / 恢复正常路径的交付。

## 9. 状态

本说明已完成只读链路核对，可作为下一代码单元的装配边界。尚未新增 Run source version / Attempt receipt、派生表、4 候选 Worker、两阶段维护恢复或双库 0 / 30 天证据；当前只能称“派生 S1 纯层与底层能力已具备，生产装配待实现”，不能称 0 天已验收。
