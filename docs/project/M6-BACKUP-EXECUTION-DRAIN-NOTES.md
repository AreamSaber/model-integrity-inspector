# M6：维护能力下的执行任务原子排空

## 范围与状态

本单元只为 `integrity.run.plan`、`integrity.sample.execute` 接通真实备份维护租约下的原子结算；不是完整备份协调器、下载就绪回执或恢复准入。其他五类任务由独立 terminal 单元处理。它不 Claim/Reserve 新任务，不发 HTTP、不读 Secret 或响应 S2，不启动普通 Worker 补偿。

新增生产文件只有 `backup_drain_execution.go`、`backup_drain_execution_data.go`、`backup_drain_execution_audit.go`。复用已提交的 stage-one candidate、维护授权/时钟、原 reconciliation reader、私有结算 core、audit canonical。未修改旧 source、普通消费者、worker、app、迁移。

## 窄接口与私有绑定

- `MaintenanceLease.LoadBackupExecutionSource(ctx, *BackupDrainSource)`：只允许原 Store、operation、generation、owner 和真实活跃管理员维护能力，且必须是 execution/terminal-required 的两种执行 Job。
- `BackupExecutionSource.Use(func(ExecutionReconciliationData) error)`：借出深拷贝。嵌套计划、请求与指针不与原来源共享；格式化关闭、JSON/YAML 序列化拒绝。没有任意 SQL、consumer、JobLease 或提交权限。
- `MaintenanceLease.ApplyBackupExecutionSource(ctx, source, candidates)`：重读原来源后在一个短事务原子结束原 Job 并调用共享结算 core。成功只返回 `applied`；同来源重放必须是 stale/零结果，不伪报第二次 applied。

原 Job/domain metadata 与原 reconciliationBinding 独立比较。后者绑定真实组织/Run/sample/probe/Job/代次、原冻结配置/请求字节、原 Attempt ID/开始时间/预留账目。不是对历史数据库的密码学证明。原 Job 先被核对，随后才将本事务实际产生的终态 Job 交给 core；没有重签、替换来源版本或把终态伪装成加载时原态。

正常 Renew 只更新同 operation 的维护时钟，不使来源失效。新 operation、接管代次、Store 或 owner 不得复用旧来源。原 Run 进度字段沿用 reader 的绑定约定；真实 stage-one domain 已变化仍会使旧 candidate stale，需要重新观察。

## 锁序、权限和原子边界

顺序是维护 gate →真实管理员/原活跃 session 行锁→数据库时钟/原租约→原 Job 行锁与 domain 关系→组织 retention 锁→全局 reservation 锁→原 Run/sample/Attempt 重读与绑定→升序预锁域与 SYSTEM 两个审计头（相同组织去重，首次 INSERT 也按序）→原 Job 终态→共享 core→原域审计+真实系统审计→两链真实 tail 复核→原 session/lease 自然时限终检。

非维护审计写入不一定持 gate，因此不能用 gate 替代审计头锁。独立第二连接实际保持域审计头写锁的测试会让本接口按调用者短 deadline 全回滚，释放后原来源仍可成功；实际查询回调确认两个头按组织 ID 升序预锁，PostgreSQL 使用 `FOR UPDATE`。

来源 Load 后的实际 session 撤销、管理员资格移除、用户停用都会使 Apply 重新授权失败。事务中既有授权行锁阻止外部改写；最终检查保留原自然 session/lease 窗口，不以事务内延期冒充原授权。原 60 秒租约慢测试不缩短生产期限，也不改写数据库时钟。

所有返回错误均为零结果并使整个 SQL 事务回滚；原 Job、Attempt、sample、Run 预算、probe 进度、审计不能部分提交。真实 trigger `RAISE(IGNORE)` / PostgreSQL `RETURN NULL` 覆盖六类 UPDATE 吞写；共享 core 与 audit append 的实际影响行数检查不由本单元另造。

## 原终止规则与兼容性

已有 failed/cancelled Job 保留原终态及原 reason。新的 pending/expired running 依原取消→无有效租约→尝试耗尽→组织失效优先级决定终态；无上述条件但存在真实 DISPATCHED 意图时为 `failed / JOB_BACKUP_UNCERTAIN`。实际请求由原 core 记为 `UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT`，预留账目结算一次，不新建 sample/执行重试 Job；原 core 可按原协议创建内部分析 Job。

真正未发出请求的 RunPlan/Sample 可以沿原终态投影为 NOT_APPLICABLE，但不会补造 Attempt 或 S1。RunPlan 仅看计数为 0 不够：还查询该 Run 下 sample 的真实 Attempt，存在实际意图时明确不支持。Sample 额外观察其所有 DISPATCHED 行，不能让共享窄 reader 的 org/run/job 过滤隐藏旧未绑定意图后误走 no-attempt 路径。

合法旧空 source discriminator 对应 `legacy_response_v1`，保留不生成 S1。原 `CreateRun` 用 `json.Marshal(sample)` 保存 request_plan；本单元以同一原 producer 编码核对原 sample，不标准化数据库原字节。真实 Unicode 内容与多 probe 的旧局部 Ordinal 均有正向回归，ExecutionOrdinal 用来定位原全局成员。当前 derived 模式仍按真实 generator/worker 的全局 Ordinal 约束。

未知来源版本、旧 NULL Run/G0 活动意图以及无法安全对应的 RunPlan 活动图不能自动恢复。NULL Job 的 DISPATCHED 无法路由至合法 candidate，stage-one 全局观察已经返回 source-invalid；测试保留该零结果，不杜撰新 Job 绑定。静态合法旧历史的归档/隔离恢复兼容性不由这个活动排空接口决定。

## SQL 预界与敏感数据

在 `reconciliationData` materialize 前以 SQL count/字节长度检查原 Run config ≤8 MiB、sample request_plan ≤2 MiB、DISPATCHED request_snapshot ≤2 MiB，三者原载荷总和 ≤8 MiB。所有将被完整读取的 Run/Sample/Attempt 文本 metadata 另逐列 ≤4096 字节，Job 文本沿 stage-one 上限；`response_meta` 从原 Attempt 查询明确 Omit。超出这些活动来源支持预算为 unsupported，不是所有历史数据不得归档的政策。

strict JSON 复用既有私有 scanner 的 UTF-8、深度/键长/对象键数预算与 Unicode SimpleFold 重复/大小写别名拒绝，不复制 crypto。随后执行原计划、样本、请求 hash、真实物理对象关系和代次检查。错误不含 source 内容、SQL、DSN、owner、密钥或路径。三类 1 MiB metadata、各原载荷超限和合计超限测试通过实际 GORM Query 回调证明在完整 typed reader 前停止；原 body 仅增加合法空白仍破坏原绑定并使 Apply stale。

## S1 信任边界与真实密码学证据

`AttemptDerivedCandidates` 是应用内部可信窄 preparer 产物。仓储复用原 `insertSelectedDerived` 只检查 scope/outcome/版本/字节结构，不拥有 MAC verifier，因此**不声称仓储验证 MAC**，也不把 32 字节形状当作真实性。未知 root key/历史 extractor 完整认证与完整备份 root-key/artifact 闭包仍属后续协调范围。

新增外部 `repository_test` 桥接使用真实内置模板与 tokenizer、真实 generator 签名、真实目的限定 MAC sealer、真实 `worker.NewRunRecoveryPreparer`，不向生产 repository 引入上层循环。通过实际 CreateRun/StartRunWithDerivedSource/ReserveAttempt，在受信任测试证书、固定 resolver 和受控 dial 的 safehttp HTTPS 链路发送一次原请求；其完成不提交。随后 pending 和 expired 各加载实际来源，在当前 Target 被停用后仅靠原来源完成 UNCERTAIN S1，不读 Secret、S2 或再次发请求。

持久化 S1 独立以真实 `Builder.VerifyDerivedRecord` 对实际最终物理行验真，并证明同长度 MAC 单字节改变验失败。缺失 candidate、错误 scope、错误 outcome、坏记录结构均使仓储零结果、完整回滚。真实 S1 验真只是单记录/真实来源证据，不替代完整 BuildDerived 图验证、历史密钥闭包或整包恢复演练。

## 验证记录

以下记录按实际执行结果更新；没有执行的组合不计通过。

- 初始完整生产编译 `832a5b`：退出 0，0.101s（无测试）。此前 helper 未同时落盘的编译失败只记失败，未到 DB。
- 新执行组初轮 SQLite/pure `344ab0`：退出 0，2.915s。
- 真实 TLS 桥接 `f4c654`：退出 0，0.586s；此前夹具未显式签入原 AuthType/Timeout 的失败已修夹具，未绕开真实 verifier。
- 第一版新快组 SQLite 三轮 `59495`：退出 0，13.944s；当时尚不含后来新增的第二组织/并发/撤权组。
- 新第二组织/并发/撤权及迟发失败 SQLite `f09772`：退出 0，1.720s。
- 曾误在 `68391` 尚未结束时启动 `39286`，后立即取消后者（退出 1）；虽然 `68391` 最终退出 0/84.006s，该次重叠整轮明确作废，不作为最终双库证据。
- 最终**严格串行**双库快组三轮 `40504`：退出 0，90.746s，包含当前全部 15 个快测试父级及完整嵌套模式/双库子树。命令为 `.tools/go/bin/go.exe test ./internal/integrity/repository -run '^TestBackupDrainExecution(Actual|Unattempted|Pure|Bounded|Late|Source|Old|PlanCounter|LegacyUnicode|Payload)' -count=3 -timeout=5m`，没有 driver 层过滤。
- root 委托的当前 `TestBackupDrainRouting`（含合法 legacy retention sentinel 新分类）及六个库存表示/日志守卫完整父级组合双库三轮 `99593`：退出 0，20.266s。选择为 `^(TestBackupDrainRouting|TestSnapshotReportInventoryRepresentation|TestSnapshotInventoryLogExtractionPreservesActualLeaks|TestSnapshotAuditInventoryTransactionAndRepresentationGuards|TestSnapshotMigrationInventoryRequestAndRepresentationGuards|TestSnapshotArtifactInventoryRepresentationAndManifestIdentity|TestSnapshotJobInventoryCountAndRepresentationGuards)`，`-count=3 -timeout=5m`。
- 当前 repository `go vet` + `golangci-lint run --allow-parallel-runners ./internal/integrity/repository`，`52246` 退出 0、0 issues。
- 原 60 秒/库慢组 `TestBackupDrainExecutionNaturalLeaseExpiry -count=1 -timeout=5m`：双库 session `13007` 实际退出 0，122.304s。两库均在真实系统 audit 后越过原租约，全部 Job/domain/audit 回滚；第二 Store 真实接管后旧来源/旧 lease 被拒，新来源重新加载并实际结算成功、完整审计通过。Go 使用本项目 `.tools/go/bin/go.exe`；General DSN 仅受控读取到该子进程环境，未输出或操作 Backup。
- `13007` 终态后已向 root 明确释放 General，无残留运行中的测试；由 root 安排下一位 agent，不存在直接跨 agent 抢占。

### 冻结文件

生产：`backup_drain_execution.go`、`backup_drain_execution_data.go`、`backup_drain_execution_audit.go`。

测试：`backup_drain_execution_test.go`、`backup_drain_execution_fault_test.go`、`backup_drain_execution_actual_bridge_test.go`、`backup_drain_execution_actual_test.go`、`backup_drain_execution_legacy_test.go`、`backup_drain_execution_audit_test.go`、`backup_drain_execution_natural_expiry_test.go`。

上述 Go 文件均在 `internal/integrity/repository/`；文档为本文件。没有 Git 写入，集成/提交由 root 独立复核负责。

范围外：未接入完整备份协调器、独立五类 terminal、归档写入/回执/下载状态；不代表 M6-05 或用户完整开发 Goal 已完成。

root 已全文复核最终三份生产、七份测试及本说明，并回读共享借用/绑定、维护事务终检与原子行对比助手。未发现阻断提交的新P1/P2；该自查不是正式人工审核，也不替代未完成的完整备份产品集成。

root 另对实际提交 **3ca5acb** 建立独立 detached 检出，排除主树未提交terminal/app/routing文件，按上方完整快组正则执行SQLite三轮：**16.677s PASS**（71261实际终态0），repository/worker vet均退出0。该检出未提供General DSN，不计PG证据。检出确认精确HEAD及零改动后已移除，仅清理临时副本，主树与全部提交保留。
