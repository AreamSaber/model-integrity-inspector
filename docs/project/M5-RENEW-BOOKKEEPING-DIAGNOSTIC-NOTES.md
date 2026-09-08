# Renew 与本进程事务：受控诊断记录

## 范围与当前事实

- 本记录针对提交 `52557c3` 的 CI `34183736103`，Windows job `101927828281` 的 `TestRunWorkerHTTPFailuresAndPartialStreamAreTruthful/limited/sqlite`。
- 已有日志只证明 `operation=renew` 后 Worker 以 `DATABASE_UNAVAILABLE` 退出、Run 未收口。日志没有保留 SQLite driver code、操作耗时或连接池等待分类，因此**原 CI 的唯一根因尚不明确**。
- Windows 打包 job 没有 PostgreSQL 服务或 DSN。其他 matrix job 使用独立 hosted runner；不能用本地 PG migration advisory 竞争解释这次 SQLite 失败。
- 原 fixture 是一个 legacy 样本、真实 HTTP 429、最多三次 Attempt，没有人工持锁。凭当前源码不能证明这条路径里某个具体事务在原 CI 占用了两秒。
- `scripts/package.ps1` 执行普通 `go test ./...`；包级并行可能增加机器资源压力，但这不是已经证实的根因。
- 同一 CI 的 quality job `101927828363` 也已 failure：非仓储 race 组的 Worker 包触发默认十分钟整体超时（600.072s）；当时 `TestRunWorkerLimitsTimeoutAndFixedParameterNoFallback` 运行 36s、其 `long-retry-after/sqlite` 子测试仅运行 1s。该子测试不是已经证实的“卡十分钟”根因；`scripts/race-shards.ps1:102` 因非零退出码失败。静态检查、测试构建和离线回放隔离步骤此前成功，不能称整个 CI 全绿。

## 可证调用链与独立合同

SQLite Store 的唯一连接执行所有读写；`WithLease` 先锁定当前 Job，回调结束后再次验证 owner、generation、expiry。PostgreSQL 即使有多个连接，也会对同 Job 的 Renew 产生行锁等待。实际网络、Tokenizer、密钥解密后的回调、展示证据 Prepare/Seal 均不在这些事务内。

Runner 的 Renew 在进入数据库池前启动固定两秒 deadline。执行期的 WithLease 与 Renew 不共用 `queueGate`；该 gate 目前只协调 consumer pulse/maintenance 与完成事务。Renew 的未知存储错误被安全归类为 unavailable，并取消 handler、退出消费者。这一 fail-closed 行为本身没有证明丢失了 fencing。

待确认的可用性合同是：当一个已授权、仍持有有效租约、总时长有界的本进程 pre-call 事务与本进程 Renew 相遇，能否在不扩大原 SQL deadline、不暂停取消、不削弱最终 fencing 的前提下避免把自己的等待当成数据库失效。不能仅以人为延时证明应无条件容忍真正的 DB 故障。

## 新增受控红测

文件：`internal/integrity/worker/run_renew_bookkeeping_diagnostic_test.go`，显式构建标签 `renew_bookkeeping_diagnostic`。该尚未批准的可用性合同不进入常规测试；源代码及真实红测证据保留，不代表已修复，也不是跳过已有回归。

- 实际 Runner/SQLite Job claim 与 `WithLease`，使用真实数据库 lease，而不是手造 owner/generation。
- 不发送 HTTP，不改 Run budget，不创建 Attempt 或收费；去掉这些与队列等待无关的混杂因素。
- 在合法 WithLease 回调中设置 release 屏障，操作原本有三秒期限；由测试在 2.2 秒释放，或在实际错误提前返回时释放。没有改 Renew 的两秒期限或租约的六十秒期限。
- 使用正常一秒 CheckLease 间隔及原 fixture 已支持的 40ms heartbeat，使 Renew 先进入等待。不会把检查间隔放宽到生产上限之外；这是独立隔离实验，**不是原 limited fixture 的精确运行参数复现**。
- 沿用现有 lease-replacement fixture 的 gate，只隔离无关 consumer pulse。实际执行 goroutine 的 CheckLease/Renew 不被 gate 排除。
- 失败时仅输出闭集 operation 布尔值、毫秒耗时、context/error sentinel 状态，以及提交后 fence 是否未变和 lease 是否未过期。没有输出 driver Error、SQL、DSN、owner、请求或响应。
- 该测试也能在 PG fixture 运行，但当前先限定 `/sqlite`；PG 未运行时不能声称跨库结论已经验证。

独占数据库时段真实 SQLite 单轮红测（2.410s）：`renew_failure=true`、`check_failure=false`、`consumer_failure=false`、`elapsed_ms=2041`、`parent_active=true`、`job_cause_unavailable=true`、`runner_unavailable=true`、`ready=false`、`fence_unchanged=true`、`lease_unexpired=true`。这证明受控阻塞可触发该时序，但**不是原 CI limited 场景的唯一归因**。恢复此诊断应显式使用 `go test -tags renew_bookkeeping_diagnostic ./internal/integrity/worker -run '^TestRunWorkerOwnLeaseBookkeepingDoesNotStarveRenew$/sqlite$' -count=1`。

## 独立确证缺陷：查询取消误标失租

root 随后在正常全 Worker 回归中遇到 `TestRunWorkerCircuitStopsFurtherActualRequests/model/postgres` 清理返回 `JOB_LEASE_LOST`。原未改 fixture 独占运行 30 轮通过（21.968s），不能由此声称原偶发时序已复现或解决。

新增普通回归 `worker/run_shutdown_lookup_test.go` 使用实际 TLS 的两次 404，使 Run 正常打开 model circuit 并提交 execution_closed_at；第三个已跳过样本 Job 的真实 CompleteWith 获得事务及 fence 后，屏障触发实际 Runner 上下文取消，再调用原完成回调。原码在 SQLite/PG 都失败（合计 1.055s）：`lease_lost=true`、`parent_cancelled=true`，而 DB owner/generation 未改变、lease 未过期。仓储层 before-query 的真实事务取消屏障也在原码失败（SQLite 0.197s）：取消被误归为 lost。

根因：七个 lease-bound `First` 查询将所有 SQL 错误无条件改成 ErrJobLeaseLost。最小修复新增私有 `executionLeaseLookupError`，只将（含 wrapped）gorm.ErrRecordNotFound 归为 lost，其余错误保留在仓储内部交由现有 Queue 脱敏边界转为 unavailable。涉及 executionJob、lockedExecutionSample、finishAttempt 的 Attempt 查询、derivedCompletionJob、recovery Attempt 查询及两种 capture Attempt 查询。所有 WHERE/fence/零行检查保持原样；没有改 Runner、没有无条件吞掉真实 lost。

测试覆盖七入口的真实 canceled query、opaque driver error 和真实 missing record；纯 helper 覆盖 wrapped not-found、cancel/deadline、opaque driver。额外负控制使用错误 generation 和实际数据库 owner 替换，仍须拒绝且不能进入完成回调。

本轮最终验证（全部独占数据库、顺序执行）：

- 仓储七入口及纯 helper 首轮双库通过 1.282s；增加实际 owner 负控制后，双库三轮通过 4.098s。
- 实际 Worker 事务内正常停机屏障及原 circuit 四种场景，双库三轮通过 19.528s。
- 实际 TLS 在途失租与合法新 owner 恢复，双库三轮通过 3.366s；旧 owner 没有结算，真实 lost 未被吞掉。
- 原 `limited/sqlite` 参数十轮通过 44.284s，未复现远端 renew。**这个通过结果不是旧 CI 根因定位或修复证据。**
- Repository + Worker lint：0 issues；六个既有文件的七个返回值 hunk 未改 WHERE/fence，精确 diff whitespace 检查通过。
- 显式诊断 tag 编译通过 0.094s（no tests to run）；其先前真实红测与未批准合同仍保留。

这些结果不等于 Linux 实际 race 或完整远端 CI 全绿。本轮没有修改 Runner、队列 deadline、轮询、租约时长、收费规则，也没有读取真实密钥。数据库测试时段已释放给 root 后续实际 app 验证。

## 进一步闭集诊断建议（尚未实施）

原失败若再出现，最小有用诊断应区分 `pool_wait`、`begin`、`consumer_guard`、`fenced_update`、`commit` 等固定阶段，并记录操作 elapsed_ms、deadline/cancel 布尔值、SQLite 有界数字 code（或五字符 SQLSTATE）。若记录池等待，只保留 WaitCount/WaitDuration 的数值增量，并明确它是共享池累计量，不能假装是单次操作的精确归因。

driver 原始错误应继续禁止离开仓储；不要为诊断开启 GORM SQL logger、输出 DSN/SQL/请求正文或直接把 driver Error 传给 Worker。日志不足前，不应通过抬高超时、降低轮询、忽略 unavailable 或重跑到绿来宣称修复完成。
