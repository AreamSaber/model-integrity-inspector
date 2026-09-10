# M6：窄恢复派生准备能力

日期：2026-09-10。范围：新增 Worker 的窄准备入口，并让普通 `NewRunReconciler` 复用；不是完整备份 drain 或备份/恢复完成。

## 1. 生产接口与所有权

- `RunRecoverySource` 只有 `Use(func(repository.ExecutionReconciliationData) error) error`。真实普通来源仍是仓储的 `ExecutionReconciliationSource`，保留原实现的深拷贝；后续维护来源可实现同一内部借用合同。
- `NewRunRecoveryPreparer(*features.Builder, *features.DerivedSealer)` 返回准备函数。闭包只捕获这两个实际能力，不接收/保留 `RunConfig`、Store、JobQueue、Secret Service、EvidenceKeys、HTTP client 或普通消费权。复用原 `prepareRunDerived` 时，局部 `RunConfig` 仅填这两字段，其余为 nil/零值。
- 本入口不 Claim、不 SQL、不查当前 Target、不取凭据、不读取/解密 S2 响应或展示正文、不出站。它仍必须暂时消费来源中的原冻结 manifest、sample plan 和 request snapshot；不能把“无响应正文”误写成“不读取任何冻结请求数据”。
- 返回的是待仓储选择、验证并原子提交的 `AttemptDerivedCandidates`，不是已持久化 S1、来源授权、drained、ready 或备份收据。实现来源接口的普通结构体不能因此取得数据库授权。
- 不限制 Job 必须已经 terminal：真实备份 Apply 将在同一事务内终止 expired running/pending 意图并结算。准备保持原 Job/Attempt 身份；维护权限、lease、原私有来源绑定和最终 fence 仍由后续仓储 Load/Apply 负责。

## 2. 来源分类及原内核不变

- 原持久化 `legacy_response_v1` 只与原冻结 plan 的空 source mode 对应，与现 `planAnalysisSource` 相同。legacy 无论有无 Attempt 都不造 S1、不读取旧正文、不重签原 manifest。
- `mii.derived-s1.v1` 必须与冻结 plan 的 mode 相同。没有实际 Attempt 时不制造 unavailable S1；有 Attempt 时只通过原 `prepareRunDerived(..., response=nil, recovered=true)` 生成唯一 `UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT`。
- 未知 source version、legacy/derived mode 冲突明确失败，不降级到 legacy 的空成功。
- 有 Attempt 时附加核对原 Run/Sample/Job/Attempt 组织、反向标识、原 manifest hash、Job 类型/object、原 lease generation 范围。原 prepare 内核继续核对 signed manifest、完整冻结 plan、实际 wire request/hash、ordinal、attempt 状态和原 receipt，生成真正的 no-response source hash 与 purpose MAC。
- 没有默认资源替换或旧 MAC 伪造：当前 Builder 无法验证原 manifest/资源时失败；新 unavailable S1 使用传入真实 sealer 的活动 purpose key version。原 request snapshot/hash/Attempt generation 保留。此单元没有扩展历史算法/资源兼容能力。
- 保留原准备内核限制：manifest/sample plan/request snapshot 各自原有 2 MiB 限制、至多 150 probes、实际 S1 至多 32 KiB。没有为了备份放宽内核，也不声称所有合法历史活动来源已得到兼容处理；仓储 SQL 侧来源预界仍是其独立责任。

## 3. 同步借用生命周期

每次调用建立独立作用域。可信 `Use` 必须恰好调用一次回调，并在回调结束后返回；借用期间不得并发改写其提供的 owned 数据。

- 不调用回调却返回 nil、重复调用、MAC 内重入、吞掉回调错误、未知来源、外层迟错/取消及 panic 均返回零候选。
- nil/typed-nil source、nil context、缺失两项能力拒绝。外层错误使用闭集映射，不格式化/转发未知错误字符串；标准取消/期限错误保留。普通 panic 和 `GODEBUG=panicnil=1` 下的 panic(nil) 都失败封闭。
- 来源违反合同、在已进入的回调还活动时返回：先关闭能力并取消派生 context，再等待该回调退出；返回前不把它遗留给下一阶段。所有已接管的候选 payload/MAC 在失败时清零，来源可保留的旧回调不再保留本作用域的 Builder/sealer/context。
- 成功返回之后再调用旧回调直接失败，不再签名；不能声称未来的违规调用可以追溯撤销已经合法交付的结果。
- 错误的 `Is` 方法也在锁外处理，避免它重入旧回调时死锁；其 panic/敏感 Error 文本不逃逸。
- 调用者提供统一的有界 context。本组件不启动后台 goroutine，不另设超时，也不假装能强制中断任意不返回的恶意 Go `Use` 或不响应的自定义 MAC 方法；可信同步/有界实现是该内部能力的合同。实际生产 MAC 为现有 purpose-key 实现，异步/阻塞源仅用于反例。
- 清零证据限于本作用域实际拥有的已准备候选，不声称擦除了旧内核、Go GC 或来源自身保留的全部内存。

## 4. 真实测试与诊断记录

以下为本单元实际执行，不借用旧 CI 追认：

1. `e72bd4`，exit 1，Worker 0.233s：先直接提取原真实准备行为，真实 producer+MAC 正例通过；空 Use、重复调用、吞错、回调后取消、未知来源及外层敏感错误反例失败。**原旧 reconciler 在 Use 返回 error 时已不会 Apply；迟错红例证明的是敏感错误原样外抛，不是虚称原代码在该处已经泄漏候选。**
2. `cc4f00`，exit 0，0.579s：生命周期初修后，新纯层与旧实际 TLS terminal reconciler（SQLite）通过。
3. `84f155`，exit 0，0.380s：扩展纯层三轮，包括真正的 purpose MAC/独立 Verify、legacy/无 Attempt 零签名、typed-nil、重入、迟到回调、MAC panic/取消、活动回调 cancel-and-join。
4. `c2daea`，exit 0，1.820s：新全组及普通 TLS terminal reconciler 三轮。新实际来源用真实 signed Run → TLS 请求 → 未提交 completion → 真 Fail/Load 来源 → 窄准备 → 实际仓储 Applied/AlreadyCompleted → 独立 MAC Verify。借用副本被篡改后原源仍可复读；目标禁用/版本变化、禁止 S2 INSERT、准备前后 Run/Attempt 无变化、只有一次 HTTP、原请求/hash/generation 保留、旧 completion 受 fence 拒绝均有断言。
5. `4c3624`，exit 1，0.222s：补查实际 repository mode 映射，legacy row 配 derived/unknown frozen plan 被错误接受为空成功；补精确 mode 关系后通过。此红例没有候选泄漏，但错误地接受了冲突来源。
6. `712e10`，exit 0：新完整组、原 `prepareRunDerived` 及普通 TLS reconciler 三轮 1.950s；Windows `go vet`、golangci-lint 均通过（0 issues）。
7. `7b7319`，exit 0：`GODEBUG=panicnil=1` 下 source/MAC/error-Is panic 三轮 0.231s；Linux/amd64、CGO=0 交叉 `go vet` 通过。交叉检查不是 Linux 实际执行。
8. 完整 Worker 包单轮：启动 `b98b8e` / session `57599`，终态 `0f483b` exit 0，48.796s；当前进程无 PostgreSQL DSN，因此包含真实 SQLite/文件/TLS 与纯层，不包含实际 PostgreSQL。

以上 agent 命令在当前进程移除 `MII_TEST_POSTGRES_DSN`，没有读取 DSN、使用 General/Backup PostgreSQL、修改服务或写 Git。数据库 fixture 中 PostgreSQL 未配置分支不能计为 PostgreSQL 通过。

9. root 后续独占 General、在进程环境实际载入受控 DSN（不输出），执行 `go test ./internal/integrity/worker -run '^(TestRunRecoveryPrepare|TestPrepareRunDerived|TestDerivedRunReconciler)' -count=3 -timeout=3m`：**真实 SQLite/PostgreSQL 与纯层三轮 7.774s PASS**（59941 第一条命令；a5936c 终态 exit 0）。不作 driver 子路径过滤；包括新真实 TLS/SQL/MAC 来源和原普通 reconciler，但不等于尚未接通的备份来源。
10. 独立只读全文复核生产、三测试、原派生内核与密钥边界，未发现可证实阻断缺陷。确认不返回的恶意 Go 代码不在可强制中断保证内，成功返回后也不追溯撤销事实；不把这些明确合同误写成新增权限。

测试来源说明：纯层用现有真正 generator/template/tokenizer/adapter/MAC fixture，但它的域 ID/完成时间是纯测试投影；只有 `*_actual_test.go` 和原普通 reconciler 用例具备实际 SQL/TLS/持久化证据。活动 MAC barrier 是在实际 purpose MAC 外加的测试阻塞包装，不是生产 hook。它的所有早退 cleanup 都 cancel、释放 barrier 并 join 已启动的 goroutine。

## 5. 未完成的接线与验收

- 新维护 `BackupDrainSource` 的真实来源 Load/Apply、expired/pending 终止与 S1/预算同事务提交、全部 Job 类型的 drain、维护 lease/final authorization 与取消编排仍由后续独立单元负责。
- 尚不能将普通 terminal source 的 TLS 成功等同于冻结下的完整 drain，或等同于真实全视图 capture/AEAD/恢复验收。
- 本单元已取得上述真实 PostgreSQL 专项，但尚无本批 Linux execution 或 race 运行证据。当前 Windows 本机没有可用 gcc/clang 且 CGO=0，未安装编译器或把非 race 运行冒称 race 通过。
