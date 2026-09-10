# M6：共享执行结算核心及原子写入检查

日期：2026-09-10。服务于 M6-05 备份冻结下的域协调；不代表维护租约已经接通完整 drain、派生准备或恢复。

## 私有核心与原权限边界

从 `ReconcileExecutionWithDerived` 抽取 `TenantTransaction.reconcileExecutionData`，只处理已经 terminal 的 Run plan/sample 原域结算。普通消费者入口继续保留 maintenanceRecovery、真实 consumer fence、原 Job 锁、组织 retention → 全局 reservation 锁、原历史 worker actor、来源重读/绑定和 Applied 后的最后 DB clock/fence。AlreadyCompleted 的原 early-return 行为未改变。

核心本身要求同 Store/事务、组织/Job/generation 和 admitted/completing 能力，且原 Job/status/type/object 对应；不导出任意事务，不授予维护权限，不生成 JobLease，不载入凭据、S2 或网络能力。未来备份入口必须在同一事务验证自己的权限、终止原 Job、完成 S1/UNCERTAIN/预算/域事实和最后维护权限检查，不能先提交 terminal 再让普通 Worker 补结算。

## 已复现的共享错误与修复

原路径只检查 UPDATE 的 Error，忽略真实影响行数。SQLite BEFORE UPDATE `RAISE(IGNORE)` 和 PostgreSQL 同条件 BEFORE UPDATE `RETURN NULL` 可以抑制更新而不返回驱动错误；随后却写入成功审计、释放预算或关闭 Run。

新增真实数据库回归通过原 CreateRun/Claim/Reserve/Fail 生产路径取得源，不伪造 consumer 或终态来源。第一次无 Attempt 样本更新抑制实际红：55e33d，0.317s，返回 Applied/nil；补单行检查后新旧 maintenance/core SQLite 三轮 3.100s、实际 TLS Worker 不重发三轮 1.178s 通过。

继续核对共享调用链，并获独立只读复核确认相同问题还在 Attempt、sample、Run 和 Probe 更新中。九故障矩阵首次真实 SQLite 红 d7a4de：1.083s，其中八处假 Applied。预算故障在单样本时被最后 reservation 检查挡住，改为两个真实样本后 dc49af，0.225s 真红，证明其他样本未完成时会遗漏。

修复规则：

- Attempt、单 Sample、Run 预算/闭口/最终样本计数以及对应单 Probe 计数更新必须恰好影响一行。
- 批量 Sample/Probe 闭口在既有 Run/reservation 锁内，对同一谓词先取预期行数，再检查实际更新数完全一致；合法空集合允许零行，部分成功也必须整事务回滚。
- 保留原 uncertain 计费、无 retry、S1 派生约束、组织隔离、审计身份和版本，不另造备份预算或绕过现正常执行入口。
- 原 legacy 无 Attempt 完成入口与同调用链熔断/序号更新一并使用相同检查，不保留同义的假成功路径。

新增矩阵目前包含 Attempt、sample、两个样本下的预算、finalized_sample_count、Run close、Probe close、未启动 Run 的 sample/probe/run、两行批量仅抑制一行的 sample/probe，以及合法空集合。每个失败都比较原 Run/Sample/Attempt/Probe/S1/Job/审计及链头全部行不变；移除仅该精确触发器后，同一原 Source 应一次 Applied、第二次 AlreadyCompleted。实际 TLS/MAC 行为另由既有 Worker 回归验证，本仓储故障夹具不冒充 MAC 验证。

## 当前验证边界

修复后最初九故障加 core/maintenance 的 SQLite 三轮 6.130s 通过。扩展部分行/空集合后，新增夹具曾错误假定 S1 表有 `id`，完整组合 29.170s 真失败，未到故障断言；按实际 `(organization_id,attempt_id)` 主键修正排序后，完整 `^(TestExecution|TestDerivedExecution)` SQLite 三轮 **29.270s PASS**，实际 TLS Worker terminal recovery 三轮 **1.210s PASS**（45036 终态 exit 0）。

独立只读复核最终生产 diff 无新增 P1/P2：已从固定 GORM v1.31.2 源码确认 Count 使用克隆 Statement、保留原谓词/事务连接/context，不污染后续 Updates；单行与批量行数检查保留原权限和锁。复核没有自行运行数据库，真实运行证据以上述命令为准。

General 明确释放后，root 使用实际受控 DSN 执行完整 `go test ./internal/integrity/repository -run '^(TestExecution|TestDerivedExecution)' -count=3 -timeout=6m`，**真实 SQLite/PostgreSQL 三轮 275.069s PASS**（62907 第一条命令，5a534b 输出）。覆盖所有顶层匹配及嵌套子树，不做 driver 过滤，包括全行/部分行触发器、两样本预算、真实1000样本批次、旧迁移/恢复/取消/限额/派生 S1 事务回归。6 分钟是该广泛组合的命令上限，未修改 CI 或生产期限；本次实际耗时仍低于5分钟。root Windows 仓储 vet/lint0、Linux amd64 交叉 vet0（61951 exit0），不等于 Linux 原生或 race。

上述 Worker 真实 TLS/MAC 专项在本次 root 验证中只有 SQLite；该部分的新 PG/远端原生验证仍须后续实际结果，不挪用旧 CI。完整备份协调器、真实同视图 capture 及恢复仍未完成。
