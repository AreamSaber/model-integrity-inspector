# M5 派生来源真实在途失租与预算中断

本工作单元只新增 `internal/integrity/worker/run_derived_inflight_test.go` 和本说明。沿用实际 quick Manifest / 十八样本 / 合成已签单价 fixture 及真实 KeyRing 派生用途 MAC。没有修改既有测试、生产 Worker / Runner / repository，没有 Git 操作。

## 1. 网络与状态屏障

两个场景均启动实际 `Runner.Run` 和实际生产 handler。TLS 服务排空请求后只等待 `request.Context().Done()`，不返回正文、不设置自动成功或自动结束的计时器。测试确认在触发故障前网络尚未停止；然后由独立服务端断开信号证实实际取消，要求信号在五秒内出现。

HTTP 配置使用生产默认 180 秒，而不是普通测试 fixture 的两秒 timeout。没有修改生产上限、签名 Manifest、签名预算、目标参数或父任务预算。唯一观察 wrapper 记录真实 Execution、生产 handler 返回的 completion / error 和实际 jobCtx cause，暂缓返回 completion，让测试能够检查“内存准备已完成但业务事务尚未提交”。它不提供人为取消 cause，也不伪造响应、认证特征或终态。

## 2. 实际在途失租与合法重新认领

`TestDerivedRunnerActualInflightLeaseLossAndLegitimateRecovery`：

1. 请求真正到达 TLS 服务，真实 Attempt 为 DISPATCHED，并持有非零 token / 金额预留。
2. 在测试数据库中模拟另一个 owner 持有下一 generation。原 Runner 自己通过实际租约检查/续约发现失租，取消 I/O；原 handler 返回 `ErrJobLeaseLost`，实际 jobCtx cause 也是该错误，completion 必须为 nil。
3. 仍在返回屏障内验证：无 S1 / raw / display、无成功结算 audit、原 Attempt 仍 DISPATCHED，预留未释放、未计费。用旧租约调用 `CompleteWith`，必须在进入业务 callback 前返回 `ErrJobLeaseLost`。
4. 放行后旧 Runner 必须以 `ErrJobLeaseLost` 退出且 Ready=false，不将它重新分类为普通停止。之后通过真实 `CancelRun` 收口其余样本，令模拟 replacement lease 过期；新的实际 Runner 用真实 `Claim` 获取同一 Job 的下一代，不手工捏造一个有效租约。
5. 新 handler 在原 Attempt 上准备恢复。提交前仍未写入业务结果；新 owner 搭配旧 generation 的 completion 同样被拒绝。实际提交后只出现一次认证 `UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT` 和 `DerivedRecovered`，原 Attempt ID / AttemptNo / lease generation 不被重写。
6. 实际网络请求计数始终为 1，非零 token / 金额预留归零；按真实请求的输入估计和完整输出上限分别加 25% 的保守收费只记一次。恢复 completion 重放被终态 fence 拒绝，S1 和 finish audit 各一条，新 Runner 仍 Ready。

此测试模拟的是已发生的 owner/generation 替换，不声称真实等了六十秒 lease 自然过期；合法恢复的认领和所有 fencing 检查由真实 Runner/JobQueue 执行。

## 3. 实际 deadline 截止与已确认 P2

`TestDerivedRunnerActualInflightDeadlineAuthenticatesBudgetOutcome` 在实际 HTTP 等待中，仅把测试数据库内该 Run 的 `deadline_at` 设为已过期。没有改签名 Plan 的预算，也没有取消 jobCtx / 父 context。实际 `CheckExecution` watcher 因 deadline 中断 callCtx，服务端观察到断开，jobCtx cause 仍 nil，原 Job 的 `CheckLease` 仍通过。提交屏障放行后，真实事务选择并认证 `COMPLETED / NOT_APPLICABLE / MI_EXECUTION_BUDGET_EXCEEDED`，receipt 为 `DerivedRecorded`，不会误判用户取消或 UNCERTAIN 恢复。其他十七样本不发请求，全部收口；终态重放仍被拒绝。

首轮真实双库红测确认了一项生产计费缺口：最终预算错误覆盖原网络分类后，`repository/execution_attempt.go` 的 `settleAttempt` 在 usage 未知时没有为 `MI_EXECUTION_BUDGET_EXCEEDED` 使用完整输出上限。

- SQLite 实际 tokens/cost 为 268，按该真实请求应为 348，少计 80。
- PostgreSQL 实际 tokens/cost 为 403，按该真实请求应为 563，少计 160。
- 差额分别正好是该次签名样本输出上限 64 / 128 加 25%；此 fixture 单价为每 token 一微单位。具体样本由真实随机生成器选择，测试期望从真实冻结请求计算，不固定 nonce 或样本。
- 原首轮命令退出失败（26.263s）；同轮在途失租/合法恢复测试双库通过。预算场景的实际网络取消、最终错误码、MAC 和 receipt 已通过，失败定位在计费断言，不能把它归因于取消失败。

主任务收到证据后仅在 `settleAttempt` 的现有无 usage 保守输出分支加入 `MI_EXECUTION_BUDGET_EXCEEDED`；没有改其他计费公式、重试、阈值或 golden。该生产修复由主任务实施，本工作单元保留严格原红测，不以修改期望隐藏少计费。

## 4. 验证与边界

修复后指定 `go test ./internal/integrity/worker -run '^TestDerivedRunnerActualInflight' -count=3` 实际 SQLite + PostgreSQL 三轮通过（79.410s，未跳过 PostgreSQL）。Worker 局部 lint 为 0 issues。主任务独立预算专项双库三轮也通过（43.890s）。未运行全 Worker / Linux / race，不以 Windows 测试替代这些覆盖。清理阶段的正常父 context 取消只用于终止测试 Runner；原失租场景在清理前已严格断言其真实非成功错误及退出状态。
