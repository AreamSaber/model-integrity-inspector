# M5 派生候选准备与单行认证核验

日期：2026-09-08。两个独立的小型实现单元，由主任务负责实际 Worker、仓储、恢复、app 和 replay 的装配及双库验证。本记录不宣称 0 天留存或全 Worker 已验收。

## 1. Worker 纯准备接口

新文件 `internal/integrity/worker/run_derived.go`：

```go
prepareRunDerived(ctx context.Context, config RunConfig,
    plan domain.ExecutionPlan, sample repository.LogicalSampleRecord,
    attempt repository.AttemptRecord, response *domain.NormalizedResponse,
    outcome domain.AttemptOutcome, recovered bool,
) (repository.AttemptDerivedCandidates, error)
```

只使用 `RunConfig.DerivedBuilder` 与 `DerivedSealer`，不读 Store / Secrets / EvidenceKeys、不访问网络、不读时钟、不执行数据库事务、不自行使用 WithoutCancel。传入 ctx 的取消/截止必须保留；主任务负责区分业务取消和失租并提供有界完成上下文。

来源要求：已经签入 `mii.derived-s1.v1` 的冻结 Plan；同组织/Run/Sample/Job 的真实 DISPATCHED / PENDING Attempt、DerivedPending receipt、真实非零 StartedAt、未完成 Sample 和 Attempt。`Candidate.Scope.Ordinal` 和 feature row.Ordinal 使用 `sample.ExecutionOrdinal`，同时检查持久 sample.Ordinal 与冻结 RequestPlan.Ordinal 一致。正常 Sample 通常在 ReserveAttempt 前读取，AttemptCount 可暂时落后一轮，因此不编造或强制覆盖该计数。Attempt 的原 ID / JobID / AttemptNo 保留，不写 FinishedAt、Run 关闭时间或最终指针。

Manifest、SamplePlan JSON 和 wire snapshot 各在解码前限制到 2 MiB，Plan probes 至多 150；SamplePlan / wire 使用拒绝未知字段、尾随数据及非 canonical 编码的解码器，重复字段也不能通过。完整签名、冻结计划、请求 hash / wire 和 scope 最终仍由原 DeriveAttempt 验证。响应交给原 NewEvidence 做独立副本及原有 1 MiB / typed 字段限制，不建立另一份特征提取器。

正常路径必须传非 nil 响应。空正文、HTTP 0、网络零值、usage 缺失、minimal evidence-limit 响应均仍是实际观测；不得为了完成派生而改成 nil。helper 使用传入的同一响应，生成实际终态和取消 / stale / budget 三个覆盖终态，按 Status / Validity / ErrorCode 去重后最多四个。每个候选单独调用 DeriveAttempt 与 Seal，不能只改 OutcomeHash 或复制 features。候选准备一旦失败，只返回空集合，不能提交已准备的部分候选。

恢复路径必须传 nil 响应及固定 `INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT` 的空响应 outcome，仅生成 `UNCERTAIN` 一个候选。它不依赖目标 Secret、凭据作用域或 target 仍有效；需要的 Manifest / 派生用途认证能力仍由可信启动提供。正常路径不会接受 MI_UNCERTAIN_ATTEMPT 来掩盖真实响应。

helper 只校验候选的闭合状态键，不另写计费算法。正常 outcome 的 usage / cost 来源可以与实际选择保存的 minimal response 不同；这些原始计费值不被修改，完整计费校验和最终覆盖选择仍在原 repository 事务执行。四条候选只留内存，由事务按最终状态唯一选择一条原子落库。

旧集成说明中“已确认但未开始 legacy Run 可以启用派生”的建议已经过时。任何已确认 signed legacy 保持原模式；本 helper 拒绝 legacy，不重新签署、升级或猜测来源。

## 2. 薄的物理行认证接口

另经主任务授权新增 `internal/integrity/analysis/features/derived_binding.go`：

```go
Builder.VerifyDerivedRecord(ctx context.Context, run RunBinding,
    row SampleBinding, attempt AttemptBinding,
    record DerivedRecord, verifier *DerivedVerifier) error
```

内部仅复用现有 `verifier.open`、`scopeFor`、提取器版本/摘要与 SourceHash 规范检查，不新增 payload 格式，也不让 Worker / repository 解析私有派生 JSON。

目的：两条 SQL 行如果交换完整 payload + MAC，flat BuildDerived 收到的完整认证集合仍可能相同，因而不能单独证明每条 SQL 镜像与它承载的 payload 对应。读取者先用真实物理行及其关联 Attempt 调用本接口，再运行完整 BuildDerived。单条检查不验证完整 Run 图、最终指针、全部重试集合、签名来源模式或数据库身份，不能替代 BuildDerived，也不授予发布权限。

## 3. 实际验证与边界

- Worker 纯测试使用真实模板生成器、真实签名 Manifest、实际 adapter wire builder、真实 tokenizer 和 synthetic master 派生的实际 secret purpose MAC。传入 helper 的 config 没有 Store / Secrets / EvidenceKeys。
- 正常四候选、实际取消/stale/budget 去重、空正文、transport 零值、minimal 响应、无响应恢复逐条通过完整 BuildDerived 和显式 BuildResponseReference，并独立核对完整 NormalizedResponse 的 sourceHash。实际正常响应有 Included=1，覆盖候选 Included=0，证明是分别提取而非只换外层键。额外实测非零 global execution ordinal 的认证 scope。
- 反例覆盖 legacy / 未知/篡改模式、错 org/run/sample/job/ordinal/probe/AttemptNo、已完成状态/错误 receipt、请求或 wire 不匹配、未知/重复/尾随 JSON、正常 nil、恢复带响应或错误终态、未知 outcome、输入大小上限、ctx 预取消/预截止及第二个 MAC 时取消/失败。全部错误只返回空集合和闭合错误，不输出测试 S2 canary。
- 薄认证测试用两条真实记录交换完整 payload+MAC：flat BuildDerived 仍能还原完整集合，但逐物理行 VerifyDerivedRecord 拒绝。另测 outcome、认证提取器、取消和缺能力拒绝。
- Helper 独立三轮 `go test ./internal/integrity/worker -run '^TestPrepareRunDerived' -count=3` 通过（0.388s）。薄接口独立三轮 `go test ./internal/integrity/analysis/features -run '^TestVerifyDerivedRecord' -count=3` 通过（0.386s）。最终 features / worker lint 为 0 issues。完整 features 三轮通过（24.452s）；全仓 `go test ./... -run '^$' -count=1` 编译检查通过。

未改 run.go、execution_http.go、analysis.go、app、repository、迁移或原已冻结的 features 文件；无 Git 操作。实际 TLS、事务覆盖、恢复 fence、双库 0/30 天无正文写入和最终报告发布由主任务独立验证，不能由本纯计算测试推断完成。
