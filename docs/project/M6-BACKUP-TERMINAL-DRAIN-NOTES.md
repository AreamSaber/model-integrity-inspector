# M6 维护冻结下的非执行类终态 Apply

日期：2026-09-10。状态：生产基础单元已实现；最终快速组已完成真实 SQLite/PostgreSQL 三轮、原 60 秒自然租约组两库各一次，代码、测试及本记录冻结。不是完整远端 CI、M6 完成或新的人工批准。

## 范围与实际入口

新增 `(*MaintenanceLease).ApplyBackupTerminalCandidate(ctx, source)`，只返回 `BackupDrainTerminalResult{Applied: true}` 或零结果与闭集错误。仅五类：analysis、report、precheck、retention、notification。未修改原 Claim、consumer、队列字段协议、原域私有核心、执行结算、迁移或应用入口。RUN_PLAN / SAMPLE_EXECUTE 由独立的 execution 单元处理。

这是维护能力下的真实同事务接线，不是先把 Job 设成 terminal 再等待普通 Worker 补域状态。仍不是完整备份 coordinator：尚需全局 drain 循环、真实 snapshot/inventory/资源归档、私有文件发布与恢复隔离的最终产品接线。

## 权限、来源、锁与提交顺序

1. 原 `BackupDrainSource` 必须来自相同 Store、operation、generation、owner；常规 Renew 不因 maintenance row.Version 改变而废掉来源。
2. 复用原 `backupDrainTransaction` 的真实维护门禁、当前用户/会话/系统权限、原 operation 和最终原租约/会话窗口检查；未增加租约、业务超时或后台任务。
3. 重读并锁住原 Job；原完整有界 Job 元数据逐字段比较。再锁同组织的实际域主行，以原固定 SQL 投影重读身份、原指针、状态、版本、计数、时间及既有 commitment 等元数据。变化返回 `Stale`，无成功审计。这里不声称未读取的冻结正文拥有新增整行摘要；原 source/body/outbox 内容不会载入或重写。
4. 按真实组织 ID 升序预锁实际审计参与者：SYSTEM anchor 始终存在，三类域投影另锁该域组织的 head；相同组织去重。沿用原空 head 的 `ON CONFLICT DO NOTHING`、原密钥/签名与 tail 验证。普通纯审计写入者不必持 maintenance gate，不能只依赖 gate。
5. 必需的新 Job 终态更新必须恰好一行。调用 c90f18e 提取的原三类私有事务核心，仍要求其实际域更新；合法 `no_projection` 返回 `Stale`，不计为 Applied。原核心的 SQL/完整性错误继续闭集失败。原 terminal Job 只补域投影，Job 的原错误 NULL/值、完成/更新时间及所有字段不重写。
6. 域审计使用原持久化 creator（离职/禁用不抹掉历史身份）；系统审计使用当前获准的维护管理员，reason 取原维护 operation。系统审计对象仅五个固定十进制身份：operation:generation:organization:job:attempt generation。无正文/路径/远端响应。
7. 系统审计后，重新校验两条链的真实 tail 与精确增加的 event_count；继而由原事务入口重验当前会话和原租约截止。任何晚错、取消、失租全部回滚 Job、域及审计。`Applied` 只在事务成功提交后返回。

## 终态闭集与兼容边界

新 terminal 决策保留原队列优先级：cancel → running 缺 lease → attempts exhausted → organization inactive（保留原 retention 例外）→ 本单元保守 uncertain。

- Analysis：原 ANALYZING、execution 已关闭、无已发布结果、零 reservation、已知 legacy/derived source 版本与原 analyze key；不生成分析或重新读取冻结正文。
- Report：原现代 job/creator 关联，queued/generating 且无完成文件字段；调用原 failure 投影，保留 frozen source、hash、版本与其他原字段。ready 不降级，缺旧指针不猜测补写。
- Precheck：原 queued/running、明确 job 指针、未 finished。真实已 Reserve 的正请求计数且正 attempt generation，即使 Job 已 Retry 成未来 pending，也终态为 `JOB_BACKUP_UNCERTAIN`；原域核心保留请求数/start/冻结 snapshot，并按既有 cancellation → request uncertainty → exhaustion → unavailable 决定域错误。没有把远端状态说成已停止或未发生。
- Retention：现代 planned 批次原指针完整、无既有 deletion receipt 才可按原 terminal 谓词只改 Job；batch、证据和删除收据全部原样。历史 organization sentinel 不造现代 batch，只支持原 cancellation/null-lease/exhaustion/inactive 终态事实；已证明满足这些条件的 pending/expired sentinel 由真实 Load 返回 `TerminalRequired`，同时保留私有 domain 的 `Legacy` 身份。普通可重试 sentinel 及其他未知 legacy 仍 `SourceUnsupported`，应用层必须直接拒绝，不能探测 Apply 作为 fallback decoder。静态旧 terminal 没有新投影，不制造 Applied。
- Notification：没有生产 notification producer/handler；保留历史 outbox 原事实。曾真实 Claim 的正 generation 可以把未决 Job 标记 `JOB_DELIVERY_UNCERTAIN`，绝不改 outbox status/delivered_at 或发通知。未 Claim 的未知状态没有确定投递结论。
- Safe pause、活动未过期 Job、DISPATCHED / 未知执行派生能力、未知/损坏/缺失域关系，以及已无需投影的原 terminal，均不得借此 API 获得新出站、消费或删除能力。

## 实际回归与证据

生产新增三文件：`backup_drain_terminal.go`、`backup_drain_terminal_decision.go`、`backup_drain_terminal_audit.go`。专属测试文件为相同前缀的 apply、queue、fault、source、audit、expiry 六文件。

- 六个真实三域新 terminal / 已 terminal 正向：SQLite 首轮 `1.030s`。冻结期间普通 Claim 不推进；常规 Renew 后来源仍可用；非成员系统管理员接管、原 creator 禁用后仍保留原 creator 审计；同事务 Job/domain 时钟与非目标字段保留；再次 Apply 精确 Stale。
- 真实 precheck Begin→Reserve→Retry、真实现代 retention producer、原 sentinel，以及明确标注的保留 schema notification fixture→真实 enqueue/Claim/Retry：SQLite 首轮 `1.400s`（此初始组合没有据以宣称嵌套 safe 类分支已执行）。
- 三类域各五个真实失败：数据库忽略 Job/domain/head UPDATE，最后 system audit INSERT 后实际 SQL ABORT，实际最后审计后的 ctx cancel。每次完整 Job/域/证据/audit/head 原行比较证明回滚，移除故障后同来源可成功。另自然会话到期、撤销、缺 actor、不同 Store/operation/generation/owner、主动取消。SQLite 首轮 `1.289s`。
- 真实第二组织 producer、另一连接在 maintenance gate 外持实际 audit head 写锁：有界 Apply 失败零结果且不留部分事实；正常 release→join 验证 holder 成功，再证明两个原 head 按升序实际预锁、域/system audit 不混组织。失败清理 cancel+release 后 join。SQLite 首轮 `0.397s`。
- 快速组合三轮 `12.950s`，包括 17 个直接 SQLite 入口。由于 Go `-run` 按 `/` 逐级匹配，两个非直接 driver 层级的入口另单独精确补验：`TestBackupDrainTerminalApplyRejectsSafeAndExecution/[^/]+/sqlite` 三轮 `2.395s`，日志明确六类全部进入 SQLite；纯 `TestBackupDrainTerminalApplyPurePriorities` 三轮 `0.103s`，日志明确 19 个优先级/拒绝分支。不可用带 SQLite 过滤的顶层 PASS 代替纯层或嵌套测试实际执行。
- `TestBackupDrainTerminalApplyNaturalLeaseExpiry/sqlite`：原生产 60 秒租约一次，`60.335s`；最后实际系统审计之后自然跨过截止，所有 Job/domain/audit 回滚；旧 owner 不能继续；真实另一 Store TakeOver 后旧 source 不可用、新读取 source 能成功。未替换时钟、未缩短原窗口、仍在普通测试清单。
- 实际 `go vet ./internal/integrity/repository` 与全 repository golangci-lint 终态 0；lint `0 issues`。

随后 root 集成复核发现：原 loader 把已支持的终态 retention sentinel 仍分类 `SourceUnsupported`，与应用层必须拒绝 Unsupported 的闭集路由冲突。root 单独修正原 `backup_drain_source.go` 并维护独立 routing 回归；本单元仅调整自己合法 sentinel 的 Kind 预期及本记录，不改 root 文件。`TestBackupDrainTerminalApplyLegacyRetentionNotModernized/sqlite` 再三轮 **0.463s PASS**（3e5395）：真实 enqueue/Claim 的普通过期 legacy sentinel 仍 Unsupported 且 Apply 拒绝；注入原 null-lease 后重新 Load 的 Kind 必须为 TerminalRequired，再实际 Apply 成原 `JOB_LEASE_INVALID`，域/收据不变；旧来源重放精确 Stale，随后 Load 无活动候选。另包含该新用例、原 active/static legacy retention、缺旧指针、旧 DISPATCHED generation、disabled modern retention pause 五父级的 SQLite 组合三轮 **2.126s PASS**（77d0aa），不改变其他 legacy 拒绝与原 retention 例外。这是合法来源可达性的修复，不扩大未知 legacy 权限。

最初集成编译曾受平行 execution WIP 未定义 helper 阻断，随后独立真实编译及 SQLite 通过；另一次新测试误用了不存在的 audit sentinel，仅测试修正后通过。不把这些编译错误声称成生产逻辑红绿；上述首次验证阶段尚未做 PostgreSQL，最终双库证据见下节，不声称完整 CI。

## 最终 General 独占双库验证

root 明确授权 General 独占后，按当前代码严格串行执行以下两条，连接仅从既有本地配置私读到进程环境，不输出连接值；不改服务、CI、生产窗口或测试阈值。

1. 从专属 `TestBackupDrainTerminalApply*` 函数清单中精确排除唯一 `NaturalLeaseExpiry`，检查得到 **19 个完整父级**，正则只匹配顶层名称、**没有任何 driver 子路径过滤**，`count=3`。实际 session **25066** 终态 **exit 0**，**66.143s PASS**（147aab）。纯层、六 kind 嵌套分支和每个 SQLite/PostgreSQL 子级均按原完整测试结构执行，不再使用先前局部 SQLite 路径组合。
2. 第一条结束后才启动 `^TestBackupDrainTerminalApplyNaturalLeaseExpiry$`、`count=1 -v`，仍无 driver 路径过滤。实际 session **95058** 终态 **exit 0**，**121.114s PASS**（4c925d）；真实日志明示 SQLite **60.21s**、PostgreSQL **60.77s**。两库均走原 60 秒租约、实际最后系统审计后自然失租回滚、旧 source/owner 拒绝及真实新 owner 重新 Load 后成功。

两条全部终态后 General 已明确只交还 root，无本单元活跃 Go/DB 命令，不转交 app。未跳过测试、未重启旧 CI、未做 Git 写入；本单元代码/测试保持冻结，本节仅补最终证据。

root 已全文复核最终三份生产、六份测试及本说明；合法旧sentinel可达性问题已由独立routing补齐并复测，未发现剩余阻断提交的新P1/P2。root原source/pause/新execution/terminal/routing共71个父级实际枚举，保留三项另有原自然到期证据的慢组单独执行，其余 **68个完整快父级SQLite三轮41.855s PASS**（93691第一命令）。这不是完整app、PG全新旧组合或本批远端CI证明，正式审核仍待统一。
