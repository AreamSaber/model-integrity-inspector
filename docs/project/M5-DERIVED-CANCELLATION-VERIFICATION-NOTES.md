# M5 派生来源实际在途取消验证

本工作单元仅新增 `internal/integrity/worker/run_derived_cancellation_test.go` 和本说明；不修改生产 Worker、Runner、features、repository、迁移或其他既有测试。无 Git 操作。

## 真实入口与因果隔离

`TestDerivedWorkerRunnerInFlightTLSCancellationRecordsAuthenticatedOutcome` 的两个子场景均启动实际 `Runner.Run`、实际 `NewRunHandlers`、实际 credential use / TLS adapter / ReserveAttempt 和 completing 事务。不是直接调用 helper，也没有人为给 jobCtx 注入取消 cause。

- `run_cancel`：在真实 TLS 请求开始且 token / 金额预留均非零后调用有权限的 `Tenant.CancelRun`。Job 的 `CheckLease` 仍通过，production handler 返回时实际 jobCtx cause 仍为 nil；业务 Run watcher 只取消调用用的 callCtx。
- `runner_job_cancel`：只设置当前真实 Job 的 `cancel_requested_at`。由实际 Runner 的 `CheckLease` 检测并向 jobCtx 传播 `ErrJobCancelled`。观察 production handler 返回时此 typed cause 已存在、TLS 服务已观测断开、业务 Run 仍 RUNNING 且无取消标记，才调用 `CancelRun` 收口其余十七个未尝试样本。

测试 wrapper 只记录真实 Execution、实际 jobCtx cause 和返回的 completion，并在第二场景取消剩余 Run 前暂停返回该 completion。它不替代 handler、不调用任何 context cancellation、不改变准备或结算结果。Runner 的 5 秒取消 grace 仍然生效。测试 shutdown 的普通父 context 取消只发生在最终清理或失败退出时。

TLS handler 排空请求后仅等待 `r.Context().Done()`，没有自动返回的定时器或 4 秒假响应。测试在触发取消前检查网络尚未停止，取消后要求独立 TLS 断开信号在 5 秒内出现；实际请求 timeout 为 30 秒，签名 target timeout 至少 10 秒。

## 签名与金额预留

独立 fixture 使用真实 quick 生成器生成十八个样本，真实 Manifest 认证、模板与 tokenizer；`AnalysisSourceDerivedV1`、合成非零 input/output 单价及金额 ceiling 都在生成前签入。使用真实 `KeyRing.NewDerivedSourceMAC` 装配 features capabilities。只使用测试密钥和本地一次性测试数据库，无真实用户密钥或上游。

首轮 fixture 漏签已知价格的金额 ceiling，导致 CreateRun 的 Policy 正常添加 ceiling 后与签名 Plan 不一致，真实派生层返回 `MI_FEATURE_BINDING_INVALID`。这属于测试创建路径未模拟生产 service 的签名前 policy 投影；修正为在 Generate 前明确签入 ceiling 后通过。没有放松生产 binding、改 Manifest 或改阈值，不把该首轮 fixture 错误称为生产取消缺陷。

## 断言与实际结果

两条路径均断言：

- 在途真实请求计数为 1，token 和金额预留均大于 0。
- 终态为 `COMPLETED / NOT_APPLICABLE / MI_EXECUTION_CANCELLED`，receipt 为 `DerivedRecorded`、AttemptNo 为 1，保留原 lease generation；不经过 UNCERTAIN 恢复。
- 用实际持久化 payload + MAC 和最终物理行调用 `VerifyDerivedRecord`，验证选定记录认证真实终态；该薄检查不被描述为完整 Run 分析验证。
- 整个 Run CANCELLED，十八样本全部 NOT_APPLICABLE，其他十七样本没有 Attempt 或 final pointer，十八个执行 Job 全 completed，Runner 仍 Ready 且未退出。
- 实际请求只发一次；token 和金额预留归零；已发请求的保守 token / 金额收费和单个 Attempt 一致且非零。释放预留不被描述为免收已发请求费用。
- 0 天策略下用真实 INSERT 禁止约束验证未写两类正文，只存在一条派生记录。
- 旧 completion 再执行被 `ErrJobLeaseLost` 拒绝，无重复派生记录或成功 audit。

最终指定测试 `go test ./internal/integrity/worker -run '^TestDerivedWorkerRunnerInFlightTLSCancellationRecordsAuthenticatedOutcome$' -count=3` 在实际 SQLite + PostgreSQL 均通过（6.486s，未跳过 PostgreSQL）。Worker lint 为 0 issues。此次仅验证新增取消专项，不声称重跑完整 Worker 或 Linux/race；完整集成由主任务统一执行。

本工作单元已冻结，没有发现需要修改生产代码的取消缺陷。
