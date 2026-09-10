# M6：备份冻结下的保守 drain / reconciliation 设计

日期：2026-09-10。状态：待实现的生产接线设计；本文件不代表 drain 已实现或已通过数据库测试。

本次只读核对了队列、执行/预检/分析/报告/保留清理、Runner、维护租约、快照 Job inventory 及相关现有测试，并完整阅读 ADR 0001–0006 和 `M6-BACKUP-IMPLEMENTATION-NOTES.md`。唯一交付是本文件；没有生产、测试、Git 或数据库变更。

## 1. 要解决的真实进展缺口

- `repository/job_queue.go:135` 的 `Claim` 先检查 `maintenanceScheduled`；冻结时直接返回，`q.reconcile` 尚未执行。不能通过把 reconcile 简单移到门禁前、临时解冻或手工调用 Claim 来完成备份。
- `job_queue.go:211` 的普通 reconcile 只终止取消、耗尽、组织失效或缺失 lease 的候选；可重试的普通 expired running Job 仍需下一次 Claim 才能推进。冻结期间不能发生这次 Claim。
- `execution_derived_reconcile.go:159` 和 `execution_recovery.go:186` 只选已经 failed/cancelled、尚未完成域投影的 Job。`worker.NewRunReconciler` 可以准备真实签名候选，但不会自行把上述 expired running Job 变为 terminal。
- 不能只处理 running：`job_queue.go:350` 的 Retry 可以在 `DISPATCHED` 已入库、最终结算未提交时把 Job 变成 pending。冻结后这个 pending Job 也不能靠重新领取来回收原请求。
- `MaintenanceLease.Observe` 有意只观察 running / expired / DISPATCHED，不修改它们。快照 Job inventory 明确拒绝任何 running 或 DISPATCHED；观察到租约过期不等于 drain 成功。

最小修复是给真实备份协调器一项受当前维护租约约束的、只做数据库保守协调的能力，而不是给它一个特殊 Worker 或另一个任务队列。

## 2. “禁止新出站”的精确边界

遵守现有备份设计及已存在的 admission 回归契约（`M6-BACKUP-IMPLEMENTATION-NOTES.md` 第 3 节）：停止新业务提交、新 Claim 和调度；允许冻结前已经领取的工作继续真实续租、必要记账、结算和内部 pending 依赖入库。M6 设计尚无新的正式人工批准，不能与已批准 ADR 混同。

这里存在必须保留的具体契约：`system_maintenance_admission_test.go:47` 明确允许冻结前已领取 Job 在冻结后完成原 pre-call bookkeeping，测试实际在 freeze 后调用 ReserveAttempt。`precheck_lease.go:66` 的 WithLease 使用 `maintenanceSettlement`。这不是本设计擅自修复的漏洞。

本单元保证：

1. drain 自身不 Claim、不调用 Handler/Completion、不 ReserveAttempt、不 ReservePrecheckRequest、不读取凭据、不建 HTTP client，也不触发通知、报告生成、保留删除或分析计算。
2. 其他 Worker 不得到新的 JobLease；已经入场的 live Job 仍属在途，协调器等待其实际结算，不把它的后续 Reserve 当成“没有在途工作”。
3. 只有原 Job 的数据库 fence 已失效，才允许保守转换；旧 Worker 的迟到结算仍被 status/owner/generation/deadline 拒绝。
4. `execution_http.go:60–69` 是 Reserve 事务提交后再调用实际 client.Do。进程可能在两者之间停顿；远端也可能在本地取消后继续执行。数据库 drain 只能证明本地意图已经结算且不会按该身份重试，不能证明远端停止计费或物理网络静默。

如果产品另外要求“freeze 提交以后，连已领取 Job 的任何新 Reserve 都必须禁止”，必须作为独立的契约收紧实施：在两个 typed Reserve 入口增加 dispatch admission，并给 Worker 增加不会误当普通失败重试的 paused 结果映射，保持结算和续租门禁不变，另加实际双库/HTTP barrier 回归。不得修改整个 WithLease 为 business，也不得删除上述既有断言掩盖变更。即使这样仍不能消除已经提交 Reserve 到 Do 的窗口；严格物理静默需要另行设计所有出站方的分布式暂停确认/进程隔离，不能用一次 DB check 或长事务包住 HTTP 冒充。

## 3. 最小生产接口与依赖

以下名字是建议的新接口，不表示仓库已有实现。

```go
// repository；方法只能由真实且仍有效的 MaintenanceLease 调用。
func (lease *MaintenanceLease) LoadBackupDrainCandidate(ctx context.Context) (
    *BackupDrainSource, BackupDrainObservation, error)
func (lease *MaintenanceLease) ApplyBackupDrainCandidate(
    ctx context.Context, source *BackupDrainSource,
    derived *AttemptDerivedCandidates,
) (BackupDrainStepResult, error)
```

接口约束：

- 每次最多持有一个候选；没有导出的任意 SQL、TenantTransaction callback、组织列表覆盖、JobLease 或 consumer owner。所有错误返回零结果，不返回半成功字段。
- `BackupDrainSource` 是私有 owned capability，绑定 Store 指针、operation ID、维护 generation/owner、原 Job 的组织/类型/object/id/status/attempt_count/owner/lease_until/cancel 标记及候选决策。调用者不能选择终态、改组织或把普通业务 Job 当作维护 Job。
- 对 sample，额外绑定现有恢复路径的原 Run、Sample、Attempt、冻结 plan/request、原 source version 和 request hash；三个实体的组织与反向指针必须精确相符。申请后仍要在 Apply 内重新读取、重新验证。
- Source 的 String/Format/LogValue 使用固定私有投影，JSON/YAML 拒绝序列化。不返回 locator、正文、凭据、SQL 或原数据库错误。需要派生时，提供现有 `ExecutionReconciliationSource.Use` 风格的深拷贝限时访问；私有绑定不由可变副本反向生成。
- 复用现有恢复源的读取上限：Run config 8 MiB、sample plan 2 MiB、attempt request snapshot 2 MiB，以及现有恢复候选总载荷 8 MiB 上限；必须 SQL 侧预检后分配，不把全表或完整 S2 读进内存。超界是明确的 source unsupported/invalid，不用当前默认 plan 替换历史值。库内不增加 Job/Attempt 总人口硬上限。
- `BackupDrainObservation` 只含闭集 blocker 布尔/计数上界及观测时间，例如 live running、expired running、unsettled attempt、需域投影、source unsupported；不是快照许可，也不是 ready。
- `BackupDrainStepResult` 只区分 applied / stale-or-already-changed / no-candidate；重复调用后“已变化”不能伪造本次 applied。若需要证明某次已成功，应验证那次真实状态和审计记录，而不是仅比较 caller digest。

依赖方向：repository 只拥有 SQL、fence、事实验证和原子提交；不得 import worker/features/secret。app 编排 lease → load → 窄派生准备 → apply。worker 可从现有 `prepareRunDerived` 抽出仅接受 `features.Builder`、`features.DerivedSealer` 和受保护恢复输入的共享纯准备核心；普通 NewRunReconciler 也复用它。不能为了复用构造要求 Secrets、Tokenizer、Resolver 等完整能力的 NewRunHandlers，也不能把“备份”登记成被自己冻结的业务 Job。

SQLite 不打开第二个 JobQueue、不替换或续租现有 consumer 记录。PG 的 server-only 角色不需要取得任何普通消费权；其协调器只有上述派生 MAC 能力，而不是可检索凭据的 Secret Service。实际启动接线缺少所需历史 MAC 能力时明确失败，不退回 legacy/raw 或伪造签名。

## 4. 候选集合与状态转换

### 4.1 选择集合

每个短事务按正 ID 有界选取一个候选，SQL 参数化；不要 OFFSET，不在内存收集所有组织。集合为以下并集：

1. `running AND (lease_until IS NULL OR lease_until <= database_now)`；live running 从不被接管。
2. pending 且命中现有取消/耗尽/组织失效终止规则，或者绑定尚未结算 DISPATCHED，或者预检已有 request_count，或者通知已被领取过。
3. failed/cancelled 且仍有现有 Run/Sample/Analyze/Report/Precheck 终态投影待完成。
4. 独立检查所有 DISPATCHED 是否精确属于可等待的 live Job 或可处理候选；孤立、跨组织、多份当前 DISPATCHED、伪造 lease generation 或未知原来源不能因 join 丢行而被忽略。

pending 的 `available_at` 在未来也不能让既有 DISPATCHED 隐身：出站意图已经持久记录，即使某次进程恰好停在真正 Do 之前，事后也不能据此证明没有出站。普通纯 pending、terminal 且已投影的行不需要为备份改写。

PG 可以使用 `FOR UPDATE SKIP LOCKED` 限制候选争锁，但返回空集合不代表全局 drained。独立 EXISTS 必须仍看到被跳过的 running/DISPATCHED/待投影候选。遇到合法竞争返回 stale/no-progress；遇到确定坏来源立即失败并保留原数据，不用“跳过 poison”声称全量完成。

### 4.2 通用规则

- 不主动取消 live Job；不改它的 deadline、attempt_count、lease_until、业务超时或执行预算。让真实 Worker 完成，或等真实 fence 失效。超出备份总期限是备份失败，不是强制 drain 成功。
- 无已发出副作用、仍可继续的 expired running Job 可以原地转 pending：只清 owner/until、更新 status/updated_at；保持 id/object/idempotency/priority/available_at/attempt_count/max_attempts/原错误码和已冻结业务来源。暂停事实另有审计，不覆盖原错误诊断。下一次正常 Claim 才增加 generation。
- 现有取消/耗尽/组织失效/缺失租约的优先级与固定 Job 错误码保持原样，retention 的 disabled organization 例外也保持。缺失 lease 的 running 按既有异常终止规则，而不是解释为可重试暂停。
- terminal Job 与业务投影必须在同一 Apply 事务内完成；签名派生准备失败时不能先单独 terminal Job 再留下 DISPATCHED。仅已有 terminal Job 的历史待投影可以从原状态继续。
- 新的真实不确定请求终止使用有限 Job 错误码，例如 `JOB_BACKUP_UNCERTAIN`；已有取消/耗尽等终态及其原码不重写。Attempt 结果仍是原有 `UNCERTAIN / INVALID_RETRYABLE / MI_UNCERTAIN_ATTEMPT`，不可用 Job.cancelled 盖掉请求已发出的事实。
- 无实际副作用证据的“业务已完成而原 Job running”等状态，不凭备份需求写 Job.completed；先证明是支持的真实 producer 状态，否则闭集 source invalid/unsupported。不能用通用 repair 把损坏修成通过 inventory 的行。

### 4.3 七种 Job 的处理矩阵

| Job 类型 | 可安全保留的未完成工作 | 已发出/终止后的保守协调 | 严禁的替代动作 |
| --- | --- | --- | --- |
| `integrity.run.plan` | 原冻结来源完整、尚未启动且可重试的 expired Job 回 pending。 | cancel/exhausted 等按 `reconcileUnstartedRun` 同事务关闭尚未启动的 Run/Samples/Probes；验证 plan_job_id 与零请求/零 reservation，不能猜测未启动。 | 不调用 StartRun，不建新的执行 Job 来“排空”。 |
| `integrity.sample.execute` | 未完成、没有当前 DISPATCHED、精确当前 job pointer 且仍可重试的 expired Job 回 pending；已有历史 COMPLETED/UNCERTAIN attempt 原样保留。 | pending 或 expired 的原 DISPATCHED：同事务 terminal 原 Job + 真实 unavailable S1（derived source 必需）+ UNCERTAIN/预算结算 + 样本封口 + 必要 Run 收尾。原 failed/cancelled 用同一核心补投影。无 Attempt 的已终止 Job 按原 N/A 规则收尾，不造 Attempt/S1。 | 不重发请求、不增 request_count/attempt_no、不把不确定结果算 valid、不读 S2 当替代证据。 |
| `integrity.run.analyze` | 未提交分析结果的可重试 expired Job 回 pending，Run 保持 ANALYZING。 | 已终止时复用 ReconcileAnalyses 的精确 run/idempotency/未发布条件，投影 MI_ANALYSIS_FAILED。 | 不计算评分、不发布新 revision、不删旧结果。 |
| `integrity.report.generate` | 保留原 frozen source 的可重试 expired Job 回 pending；已有私有文件 orphan 不构成 ready。 | 原 terminal Job 按 ReconcileReports 使 queued/generating 报告失败，必须核对 job pointer/idempotency；现有 ready 及下载事实不降级。 | 不生成/删除/搬迁报告文件，不根据文件存在伪造发布成功。 |
| `integrity.retention.delete` | 现代 planned batch 对应的可重试 expired Job 回 pending，不修改策略、observed time、cursor 或 batch 身份；原组织 sentinel 的历史 Job 按其原形保留。 | 原终止 Job 只做所需队列终态；planned batch 保持原事实，正常解冻后的既有调度器负责继续。completed batch/删除 receipts 与 completed Job 的原子事实不改写。 | 不调用 DeleteResponseEvidenceBatch，不补历史删除 receipt，不用现代 batch 覆盖 sentinel。 |
| `integrity.target.precheck` | request_count=0 且可重试的 expired Job 回 pending，保留原 started_at/总 lifetime，不重置时钟。 | pending 或 expired 且 request_count>0：原 Job 保守终止并使用现有 precheck 投影；除已有取消优先级外为 MI_UNCERTAIN_ATTEMPT，保留请求数和原 target snapshot。其他 terminal 用既有 exhaustion/cancel 规则。 | 不调用探测、fallback 或 stream 请求，不把不确定预检设 passed，不清请求计数重跑。 |
| `integrity.notification.send` | 尚未领取过的 pending 原样保留；当前 app 没有此类型的生产 Handler，不能推断历史也未发送。 | 已领取后 pending/expired 且无可信 delivery ledger 的原 Job，保守 failed（拟 `JOB_DELIVERY_UNCERTAIN`；已有终止原因不覆盖）；outbox 原 status/delivered_at/事件身份逐字保留。 | 不重发、不宣称 delivered/undelivered、不给 outbox 造回执。将来启用 handler 前必须另行实现幂等发送及不确定状态协议。 |

通知边界是保留未知事实，而非扩展当前通知功能。现 schema 只有 outbox 状态/时间，没有可靠发送尝试 ledger；现 app 注册的六种 Handler 不含 notification。不能用当前实现“没有 Handler”证明所有保留历史均未出站。解冻不自动恢复上述保守终止的通知 Job；任何独立 outbox dispatcher 接线必须明确审查这个状态，不能无视它扫描 pending 后发送。

## 5. DISPATCHED → UNCERTAIN 的真实接线

1. Load 在当前维护租约下读取并绑定原 Job、Run、Sample、Attempt。对 expired running/pending，不先写临时 terminal，也不构造伪造的新 JobLease。
2. 事务外使用原 request/plan/identity，通过现有 DeriveAttempt → MAC Seal 生成唯一 recovered unavailable candidate。参数为真实 `MI_UNCERTAIN_ATTEMPT`、nil response、无 usage/本地 tokenizer 结果；不需要目标仍启用、Secret 仍存在或任何 S2 body。
3. Apply 重新授权和锁定原状态、检查源绑定；仅此时按照闭集决策更改 Job 并调用与现有 ReconcileExecutionWithDerived 共用的私有事务核心。原消费者公共 API 继续 guardConsumer，不扩成任意 Store 调用。
4. 核心保持原 derived scope/request hash/key version/选定 outcome 的精确校验和一份 S1；legacy source 继续合法 legacy 路径，不加伪 MAC，不升级信任。
5. 复用 `settleAttempt(..., uncertain=true)`：基于原冻结估算/最大输出和原 `UncertainTokens`/价格计算，reservation 精确释放一次，预算计入一次。该路径的 retry 条件含 `!uncertain`，因此不创建第二个请求；不可另算一套“备份预算”。
6. `closeExecutionIfFinished` 可按现契约创建内部 pending analyze 依赖，但仍不能 Claim。所有剩余未完成样本未消失前不可强行关闭 Run；取消 Run 的既有规则不变。
7. Job、Attempt、S1、sample、run/probe 计数、依赖队列和相应审计一起提交。任何晚期 SQL、MAC 验证、审计、权限、lease 或 context 失败均回滚，返回零结果。

## 6. 锁顺序、权限、生命周期与审计

每次 Load/Apply 都通过现有 `maintenanceTransaction`，使用不超过现有 2 秒短事务窗口；不能持 SQL 锁进行派生、文件 I/O、等待 Worker 或 HTTP。

Apply 的顺序固定为：

1. 维护 gate 行 UPDATE 锁，读取经过历史事件/审计验证的冻结状态。
2. 按现 `authorizeMaintenance` 顺序检查真实 active system-admin user/session、密码变化、must-change、revoke 和会话期限；并验证 actor context，非成员系统管理员的系统权限不被误变成单租户权限。
3. 当前 DB clock 验证 operation/owner/generation/lease/deadline，锁原 Job 并重新判断是否仍 expired/pending/terminal。lease 已续回 live 或业务已提交则不接管。
4. 有执行投影时按现路径取受影响组织 retention 锁 → 全局 execution reservation 锁 → 原 sample/run/attempt 所需锁。一次只处理一个组织/候选；禁止拿全局 reservation 锁后再逐个追加组织锁。
5. 所需审计链头按 organization ID 升序预锁，再追加域审计和系统 drain 审计，避免跨组织链头逆序。初始化首条链头也必须遵循相同顺序。gate 排除正常业务共享 gate 的同时，不能假设所有纯审计写入也取得该 gate。
6. 写全部事实后，以同连接真实 DB clock 调用与 `finishMaintenanceAuthority` 同等的最终检查，验证原 lease 窗口及实际会话仍有效。Renew 不得在 Apply 里复活过期 lease；新 owner takeover 后旧 Source 一律失效。

Load 也不能把带锁候选跨事务返回；Source 是已释放锁的数据承诺，不是锁本身。新 Source 的 lease binding 不绑定会因正常 Renew 改变的 state.Version，否则每次续租会无故使候选过期；但必须绑定维护 operation/generation/owner，并在 Apply 验证最新窗口。Job 绑定则保留读取到的 lease_until/owner/status/generation 等精确 CAS 输入。

审计最小方案不需要改 maintenance v1/v2 事件协议，也不需要新 drain Job/新状态枚举：

- 同事务追加一条新的闭集 `system.backup.drain.<decision>` audit action，写入现有持久 SYSTEM anchor，不伪装成 begin/renew/complete。ObjectType 固定为 `system_backup_drain`。
- ObjectID 为固定顺序十进制 `operation:generation:organization:job:job_generation`：前四项为正数，job_generation 允许尚未领取 Job 的 0；五个 int64 上界共不超过 99 字节。decision action 精确区分 pause、从 pending/running 保守 uncertain、已有 terminal 的投影及 terminal 规则。系统 actor 是本次真实管理员，ReasonCode 保留本次维护原因。
- 原执行/报告/预检域审计继续使用历史 creator 的 `workerAuditContext`；停用/离职不改写历史请求归属。历史 creator 只用于事实归属，不能代替当前管理员授权。notification/legacy retention 原本没有相应 worker actor 时仍有系统 drain 审计，不能造匿名业务 actor。
- 不扩展通用 AuditCommand 为任意 JSON，不改变旧事件 canonical bytes，不把 caller 自算 digest 当作已锚定审计。上述系统事件本身不是全量 drain 或备份 ready receipt，最终仍要真实快照/归档/完成事务。

正常 Job heartbeat/consumer heartbeat 仍遵循原 60 秒 lease / 15 秒 heartbeat。协调器单独按维护租约节奏续租；同一协调器的 Load/Apply/Renew 串行化短数据库步骤，不能让本地锁被一个等待 Worker 的循环长期占有。

## 7. 真实协调器时间线和失败处理

```text
真实系统管理员授权 → BeginBackupMaintenance（开始审计 + freeze）
  → 有界循环：Load → [事务外纯派生] → Apply → 新的全局 blocker 观察
     ├─ live/锁竞争：等待实际变化，并续有效维护租约
     ├─ 坏来源/审计/权限/失租/取消/总期限：失败路径
     └─ 无 running、无 DISPATCHED、无待处理投影：进入真实快照阶段
  → SQLite 实际 staging snapshot / PG 实际 RO snapshot + dump
  → 同一视图各 inventory（再次拒绝 running/DISPATCHED/坏绑定）
  → 文件/资源/配置载体 → manifest/AEAD → 私有原子发布 → 全文件读回
  → 既有 CompleteBackup（再授权/fence/审计/receipt 后才 ready 和 reopen）
```

最后一次“没有候选”不能替代所有组织的 blocker 检查，也不能成为可复用 snapshot permit。现有 Observe 可保留兼容字段；新 drain 的全局观察还必须覆盖上述待处理集合。快照内 Job inventory 是独立第二道验证，不拿活库之前的计数填它。

冻结消除了新的普通 Claim，但还有已入场 settlement；因此必须等所有 running 真正消失后才拍快照。允许存在 pending 待恢复工作，也允许保守 UNCERTAIN；备份不是把所有业务计算完成。仅有 ready=false、Queue.Close、Runner.Run 返回或取消请求发出均不构成 barrier：Runner 对不响应 Handler 的 5 秒 grace 到期后可能返回 ErrHandlerUnresponsive，旧 Handler/远端仍可能存活。

失败规则：

- 所有协调器拥有的 timer/派生任务/续租 goroutine 均 cancel-and-join；cleanup 不在仍被 worker/callback 持有的锁下等待，不遗留下一阶段后台工作。不得降低现有业务期限或把失败循环自动重试当成功。
- 发生真实状态竞争可以 fresh Load；确定 SQL/来源/审计错误应终止本次，不无穷 retry，也不跳过坏行以获取空列表。等待正常在途结束不是故障重试。
- 已提交的逐项 drain 事实是正确的持久事实，后续备份失败不能回滚为 DISPATCHED 或伪造原 live lease。普通 paused pending 只有以后正式 reopen 才可领取；不确定请求不能自动重放。
- 在短 cleanup context 中，仅当前 live owner + fresh authority 可以调用原 Abort 记录失败并正常解冻。失租、session revoke、takeover 后不调用无授权强制解锁；冻结保持，交给管理员真实 takeover/abort 流程。总期限失效不能用 Renew 延长到审批以外。
- 不删除其他操作的 workspace、已发布文件或历史 receipt；既有私有文件清理 capability 只处理自己拥有的对象。drain 不拥有报告文件清理权。
- restore_isolated 不允许这些变更，也不自动复用 drain Source；恢复后 pending/UNCERTAIN 历史不因导入被重放。恢复隔离 gate/显式激活和全部历史验证仍是后续真实恢复协调器职责。

## 8. 兼容性与迁移边界

最小版本只使用现有 Job 状态、域列和 audit schema；不需要新增业务队列类型、pause 状态或维护事件 action，因此无需为状态转换重建旧表。若实际查询计划需要新索引，可单独增加双库 additive migration，并以 populated 升级/回滚和真实 EXPLAIN 证明；不能借此重写历史行或扩大现有 migration 版本的语义。

明确保留：最初 foundation 数据、合法 nullable execution 字段、旧 `PLANNED` attempt、terminal legacy Job、原 source version、原 estimate/manifest/签名版本、retention 组织 sentinel，以及已删除但仍保留的证据/密钥引用。它们只因是历史行不成为 drain 候选。现有 inventory 的合法 legacy 分类不能被缩成“必须当前 producer 完整字段”。

相反，仍在 DISPATCHED 且无法无损还原组织/请求/原 MAC 来源的历史活动行，不能伪造当前字段来实现 UNCERTAIN。应明确区分 known legacy unsupported 与 actual corruption，失败保持原数据库和已保留文件；不得通过跳过、改信任级别、套默认配置或修改恢复格式把它“修好”。这不是删除历史恢复能力：合法静态历史继续原样归档，未知活动历史需单独的有证据兼容适配后再自动协调。

## 9. 必须先红后绿的回归和反例

实现时沿用真实双库 fixture、实际密码学及严格期限，不 skip/retry 扩 timeout；本设计没有运行这些测试。

| 用例/反例 | 必须证明的结果 |
| --- | --- |
| 首个红例：冻结前领取普通可重试 Job，真实受控过期，反复普通 Claim 和现有 reconciler。 | 现实现保持 running；新 drain 将安全本地 Job 原地 pending，attempt_count 不增、无 Claim，旧 JobLease 的 Complete/Retry/Renew 均不能提交。 |
| 七种 Job × live/expired/pending/failed/cancelled；取消、耗尽、缺失 lease、disabled org 与 retention 例外。 | 覆盖矩阵中的准确终态和保存字段；不把所有类型一刀切 failed 或 completed。 |
| 真 TLS 收到 sample 请求后、正常结算前断开所有者；分别 running 过期及 Retry→pending。 | 只有一次请求、原 identity、不增计数；实际 DeriveAttempt/MAC Verify 成功的 unavailable S1，UNCERTAIN 和预算/释放各一次，无原请求重试、无新增 sample execution。 |
| 上述 sample 的 target 后续变更/禁用、secret 删除、所有 S2 evidence 删除。 | 原恢复仍只依赖冻结 source + MAC 能力；不取凭据、不 fallback raw、不拿新资源覆盖旧参数。 |
| 在 source Load 后另连接续租、真实正常 Complete、Run cancellation、管理员 takeover。 | fresh Apply 不能覆盖新事实；尤其 lease 已变 live 时不 terminal，旧维护 generation 无 mutation/ready。 |
| SQL/审计/S1 插入故障，以及事务末才会话自然过期或原维护 lease 到期。 | 全部业务与 Job 一起回滚、零结果；故障移除后用 fresh Source 只结算一次，不能保留“已 terminal 但仍 DISPATCHED”的半步。 |
| 篡改 Source 副本、跨 Store/组织/job、错误 request hash/key/MAC、旧 Source 重放。 | 正确拒绝或报告精确 stale；不允许任何 caller digest/错误码选择把 candidate 升权。 |
| live Job 在 freeze 后仍按既有契约 Reserve 并完成；内部依赖 analyze 入库。 | 保留原 admission 回归；协调器看到真实 blocker，之后 pending analyze 保留但未 Claim，无假网络静默结论。 |
| 预检已 Reserve 一次后失租；0 次失租；取消与请求数同时存在。 | 不发 fallback/stream，已有请求保留不确定/取消事实；0 次暂停不重置 started_at 或扩大 lifetime，不伪 passed。 |
| 报告已存在 orphan、retention 有 planned/completed batch、notification 有未知历史状态。 | 无文件操作、无保留删除、无通知；不造发布/删除/发送 receipt，历史结果/outbox 原值保留。 |
| PG 锁住最低 ID 候选，第二连接观察；多个组织/大量 terminal 历史；poison 候选。 | SKIP LOCKED 空不报告 drained；有限内存有实际进展；坏来源显式失败，不饥饿循环、不静默遗漏、不以人口上限排除合法历史。 |
| SQLite 既有 live consumer 与协调器并存；随后 consumer 过期；PG server-only 协调器。 | 不打开/伪造第二 consumer，正常 guardConsumer 未放宽；维护能力独立于业务消费，但只做授权协调。 |
| system anchor 与另组织域 audit head 的受控双连接竞争；晚期审计失败。 | 固定链头锁序，无逆序死锁；域 actor 与真实系统管理员各自正确，任何 audit 失败回滚全部事实。 |
| 派生准备/barrier 正在运行时取消、失租或超时。 | cancel-and-join 后才返回，无下一阶段调用，不把原栈/SQL/DSN/URL/正文/密钥写入诊断。 |
| 最初迁移 + 合法 nullable/PLANNED/terminal legacy + 部分历史字段。 | 原字节/原来源/原分类保留；没有伪造 source/version/MAC，未知活动历史明确 unsupported 并保留原库。 |
| 真正 Worker → freeze → live 完成 + expired 协调 → 实际同视图 snapshot/inventory → AEAD/全文件 readback → durable completion。 | 只在每条真实链路接通后才能声称完整备份 drain 通过；纯候选 fixture、合成 DB payload 或包装层绿色不能代替这项产品验收。 |

## 10. 可直接分工的实施顺序

1. **Repository 候选/暂停基础**：新增专有 backup_drain source/load/apply 文件；先做真实维护授权、全量候选覆盖、精确类型/组织检查、无副作用暂停、系统审计和 fence/取消/末端失租双库红绿。保持现 Claim、consumer 规则不变。
2. **原子域协调**：从现执行/预检/分析/报告恢复提取私有事务核心；只在已验证的维护能力入口调用。sample 的 terminal 与 S1/UNCERTAIN 必须一次提交，不能把后续某个普通 Runner 作为正确性前提。加入全部类型和 pending DISPATCHED 反例。
3. **窄派生能力**：提取实际 recovered preparation 供普通 NewRunReconciler 和 app 协调器复用；真实 TLS → bodyless derived → MAC → 双库提交验证。不得在 repository 引入向上依赖或新增 Secret 检索授权。
4. **App 协调器集成**：接现 Begin/Renew/Observe、以上步骤、实际快照及已实现归档/readback/completion，统一 owner 的取消/等待生命周期；失败走匹配 owner 的 Abort，失租保留冻结待接管。禁止另造孤立“drain service”绕过现 gate。
5. **产品链路验收与历史兼容**：运行最后一项真实端到端、双库多连接、权限/失租/迁移/旧来源回归，再更新备份实现台账。若决定进一步禁止既有 live Job 的 freeze 后 Reserve，另起明确合同变更单元，不夹带在步骤 1–4。

交付判定：以上生产接线和真实回归完成前，状态只能是“设计完成、drain 待实现”；不能据本文件、仅 Observe 为零或既有 archive/readback 单元通过，将 M6 完整备份/恢复标为完成。
