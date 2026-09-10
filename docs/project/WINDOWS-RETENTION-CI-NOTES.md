# Windows zero-day retention CI 故障夹具复核

## 原始失败与能确认的事实

2026-09-10 复核 [CI 34427119645](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34427119645)，HEAD 为 `8fe207a82f5f57d183eb3aa64915acd9cde40005`。[Windows package job 102714613259](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34427119645/job/102714613259) 在第二次带 `webassets` 的 `./web ./internal/app` 测试失败；不是第一次 `go test -p 1 ./...`，不是构建工具链、镜像或 PostgreSQL 备份 job 失败。quality、Linux package、image 和各 race job 已成功；Windows package 与依赖它的总门禁失败。

完整上下文的第一错误为：

- `TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts/sqlite/display_service_writer_short`，4.28s，`evidence_service_pipeline_test.go:270`：writer 未观察到已提交且认证的 grant。
- 随后 `pipeline_test.go:413` 的请求得到 `network_dial / request_context=none`，不是调用方超时。
- `pipeline_test.go:280` 清理得到 `MI_STARTUP_FAILED`。
- 固定诊断：02:09:13.332 listener 启动；02:09:35.958 queue `claim` 失败；02:09:37.899 `worker_exit / database_unavailable / caller_done=false`。

原诊断没有区分 writer 根本未调用、receipt count、绑定还是 full-audit 检查失败，也未保存原 SQLite 错误码。因此不得宣称仅凭这段 CI 日志已经知道唯一根因。

## 已证明的结构性问题

原 `assertCommitted` 在真实 Writer 的首块回调中调用 `app.store.VerifyAllAudit(full=true)`。生产 SQLite Store 只有一个连接，full audit 在这个连接的 `BEGIN IMMEDIATE` 事务内读取并逐条验证完整历史 MAC；Worker 的正常 claim 使用原两秒预算，该预算包含等待这个共享池的时间。

新回归使用真实签名初始化、真实 SQLite Store／JobQueue 和只在审计 MAC 中启用的 channel barrier，确定性持有验证阶段；没有修改 claim deadline、轮询、并发或错误策略。

- 同一回归暂时接回旧 live full verifier：**2.214s / terminal 1**，`claim=database_unavailable`，而释放 barrier 后 `verify_success=true`。健康数据库仅因测试观察器持有连接就消耗了整个 claim 预算。
- 独立物理只读观察器首轮：**0.229s / terminal 0**。在同一个 MAC barrier 尚未释放时，原两秒预算内的实际 queue claim 已成功。

这证明该夹具足以制造所见的失败链条，不等同于重放了 GitHub 那次调度或取得其原始 driver 错误。

## 修复范围与保留的断言

仅修改 app 测试及本说明，不修改 repository/worker/app 生产逻辑，不操作 PostgreSQL／服务，不提交 Git。

增加 test-only 独立 audit reader：SQLite 使用 `mode=ro`，BeginTx 前从同一原生连接检查 `IsReadOnly("main")`，并使用 deferred 只读事务；PostgreSQL 使用真实 READ ONLY REPEATABLE READ 事务。查询和 MAC 验证均固定在同一快照，只有这个只读观察器的连接被占用。未停止 Worker 或降低真实并发。

保持首字节之前的三项检查：独立连接观察 receipt／grant count 的精确增量、receipt ID/hash 到 audit object 的精确绑定、完整历史审计验证。最终整条流水线仍再次验证完整审计。没有把 full 验证换成 tail，也没有只验最新 grant。

测试 reader 不另造密码算法：逐条调用生产 `audit.Verify`，独立比较冻结 head 的总数、每条组织 ID／连续 sequence／previous hash、末 hash 与 key version。100 条分页，测试夹具有显式组织／事件上限；这不是生产审计／备份接口。补充错误 head、错误 MAC、跨三页和验证期间另一连接正常追加审计的反例。

Writer 失败诊断新增调用次数、闭集 grant 检查阶段和既有固定错误类别；不会格式化任意 driver／consumer error、SQL、URL、密钥或正文。专门用 Error() 会 panic 的 opaque error 测试这条边界。

## 不掩盖的生产容量边界

完整检查所有非测试调用：`app.go` 的 full verification 在启动 Worker 前执行；运行期 readiness 使用 tail，没有发现运行期 HTTP 或后台 full-audit 入口。原夹具是在任意故障 Writer 内注入了生产运行期并不执行的完整维护扫描。

正常运行期事务、系统调度停顿或长时间 I/O 仍可能占用 SQLite 唯一连接。Worker claim 的两秒失败封闭会停止所需组件，当前修复**没有**改成重试、忽略错误或不健康 server-only 降级。这个行为及实际容量边界应由后续 M7 长事务／慢磁盘／CPU 压力验证覆盖；不能用本夹具改动宣称该生产风险已消失。

## 验证记录

使用固定 Go 1.26.7；每个测试 shell 只清除自身 `MII_TEST_POSTGRES_DSN`，不读取 General/Backup DSN、不操作服务。所有实测数据库都是新临时 SQLite 文件。

1. 未改代码的真实 TLS zero-day SQLite 定向三轮：22.529s / terminal 0。说明故障不是本机稳定必现；不将这次视为修复后的通过。
2. 新物理只读 barrier 首次正向 0.229s / terminal 0；临时旧 live verifier 对照 2.214s / terminal 1，随后恢复新实现。
3. 一次集成编译暴露测试删除旧 fmt 调用后残留 import，已删除；不是运行时失败。
4. 后续运行暂被其它 agent 正在编辑的 `snapshot_key_inventory.go` 未完成类型／import 阻断，未擅自修改该文件，也不将受阻调用计为通过。
5. 编译稳定后，新 barrier、三页完整历史、head count/hash/key 篡改、错误 MAC、同快照并发追加以及闭集诊断三轮通过：`go test ./internal/app -run '^TestPipeline(FullAuditObserver|DisplayGrantDiagnostic)' -count=3 -v`，2.034s / terminal 0。
6. 原 Windows 失败的真实 TLS zero-day SQLite 流程，带相同 `webassets` tag 连续五轮通过：`go test -tags webassets ./internal/app -run '^TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts$/sqlite$' -count=5`，36.367s，session 46179 / terminal 0。
7. 按 CI 原第二阶段命令形式、无降低 package 并发参数，再运行 `go test -count=1 -tags webassets ./web ./internal/app`：web 0.384s，app 27.637s，session 46092 / terminal 0。包含正常 30 天与零天流程及所有 app 测试；本任务按授权清除了当前 shell 的 PostgreSQL 环境变量，因此新 PostgreSQL observer 分支未由本任务实测，仍须主任务后续双库集成验证。
8. `go vet ./internal/app` 通过；lint 首次发现测试把闭集 column 拼接到 SQL，已改成完整 SQL 字面量而非豁免；最终 `golangci-lint run --allow-parallel-runners ./internal/app/...` 返回 `0 issues.` / terminal 0；`git diff --check` terminal 0。
9. root 复核发现两个新 barrier 的提前失败路径只有 release，没有等待 verifier 退出。补充共享的 test-only 生命周期 helper：先 cancel 子 context，再 release barrier，最后等独立 done 通道；正常路径已经读取 finished 也不会二次消费结果／死锁。两个原测试的 5 秒 barrier 和 2 秒 claim／append 期限、完整审计断言均不变。
10. 最后补丁只跑不访问数据库的生命周期／闭集诊断三轮：`go test ./internal/app -run '^TestPipeline(AuditVerifierLifetime|DisplayGrantDiagnostic)' -count=3 -v`，0.101s / terminal 0；覆盖进入前提前返回、验证中提前返回、结果已经消费以及重复 cleanup，验证取消先于释放、cleanup 返回前 verifier 已退出。随后 vet、lint `0 issues.` 和 diff-check 均 terminal 0。未重复数据库或 TLS 测试；最终真实双库 webassets 集成由 root 执行。

主任务在最终 cancel/release/join 修正后，独占既有 General PostgreSQL 测试实例，
实际重新运行 `go test -count=1 -tags webassets ./web ./internal/app`，没有测试过滤、
没有降低包并发或放宽期限。**web 0.407s、完整 app 59.660s PASS**，会话 20673
终态退出 0，覆盖真实 SQLite／PostgreSQL 30日／0日应用流程及新的 PG RO/RR 审计观察器。
之后明确释放数据库时段；未操作 Backup 实例或业务数据。

没有声称原 CI 已变绿；GitHub 新提交结果仍由主任务跟踪。未在本机运行 race detector，不能用既有 `8fe207a` 的绿色 race jobs 追认这次新夹具代码。
