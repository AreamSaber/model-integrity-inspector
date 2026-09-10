# M6-05：备份完成回执与真实最终授权

2026-09-10。此单元实现协调器的持久化完成阶段，不等于完整备份/恢复、系统内入口或正式审核通过。

## 实现与权限边界

- 新增 migration22 `backup_completion`，不修改原 migration1～21。支持维护操作 `completed` 和 `complete` 事件，并加入不可变 `system_backup_receipts`。SQLite 在迁移事务内重建三个维护表、不禁用外键；PostgreSQL 原位扩展状态/动作约束。原操作、事件、审计、singleton、旧迁移记录不改写。
- `MaintenanceLease.BackupIdentity()` 提供已提交 begin 的备份 ID/开始时间，仅供原 manifest 绑定，不是当前授权。私有 lease owner 不对外返回。
- `CompleteBackup` 接受 **受信协调器内部事实**：真实完整文件已发布并读回认证后，才允许调用；不是 HTTP DTO、文件验证器或快照证明。所有 JSON/YAML/fmt/slog 的通用暴露路径均封闭。
- 最终短事务：维护 singleton 排他锁 → 当前系统管理员/会话/actor 验证 → 原 owner、operation、generation、有效租约 → 全局 running Job/DISPATCHED Attempt 阻塞检查 → receipt → complete 事件/系统 HMAC 审计 → normal gate → 新鲜数据库时钟再次验证会话与 **原** lease window。
- running 的过期租约仍会阻止完成；不能把过期当作已停止。最终阻塞检查不替代同物理快照 inventory、远端请求/子进程停止确认或完整资源闭包。
- receipt 绑定原 manifest 版本/哈希、DB 哈希、归档哈希/长度、明文长度、entry 数、包装 key version、内部生成的 64 位十六进制 object ID、所有时间/发起和完成人/会话/generation/固定原因码。没有任意路径、DSN、原始异常、密钥和请求文本。
- 旧 begin/renew/abort/supersede 保留原 `mii.system-maintenance-event.v1` canonical 字节与 domain。只有新 complete 使用 v2，将 receipt digest 纳入原操作事件认证链；不能用自算 receipt SHA 冒充 HMAC 审计来源。
- `ReadBackupCompletion` 每次重新验证当前真实 gate、系统管理员/有效会话、历史 operation/event/audit 与 receipt。返回前的第二次 receipt 读取必须仍等于已认证 event 的 digest；没有通过“第一次有效、第二次重算 hash”替换事实的窗口。当前组织管理员权限不替代 system admin。
- 共享历史验证同时认证最初 begin 和最新事件各自的原审计锚点：创建时间、deadline、发起人/会话与 generation 必须来自真正的 begin，不能只检查它们是合法正数。CompleteBackup 还核对创建时间与原 lease 持有的开始时间一致；不改变旧事件 canonical 字节。
- 文件和数据库不是一个事务。事务前/事务内失败无完成回执；晚到连接清理/未知提交结果不能声称回滚了已经提交的数据。读取真实 durable receipt 后才能确定结果。文件由上层保留为私有成品或 orphan，此仓储不删除文件、不自动 Abort、不激活恢复副本。

## 已执行验证

全部使用固定 Go 1.26.7，真实 PostgreSQL General 测试实例；每个测试只拥有其独立临时 SQLite 文件/PG schema，未修改 General 配置或 Backup 实例。

1. 原 v1 固定 canonical 字节、receipt 每字段变更、通用序列化/格式化及 key version 边界：纯组首次 **0.102s PASS**。
2. SQLite 完成/新连接历史读取/并发同 owner：**0.373s PASS**；receipt/event/audit/state/cancel 后期失败及已知回滚后重试：**0.609s PASS**。
3. SQLite populated21→22 成功和末尾 SQL 强制失败回滚、所有原行/旧 checksum 保留、FK/terminal guard、会话自然过期、实际原租约 Attempt 结算后才完成：**0.775s PASS**；receipt 变更/重算/missing/duplicate/最后重读重算：**0.615s PASS**。
4. `go test ./internal/integrity/repository -run '^TestBackupCompletion' -count=3 -timeout=5m`：**31.201s PASS，session76856 terminal0**，SQLite/PostgreSQL 全部实际执行。
5. `go test ./internal/integrity/repository -run '^(TestSystemMaintenance|TestBackupCompletion)' -count=1 -timeout=6m`：**155.943s PASS，session90576 terminal0**。包括原实际60秒自然 lease 到期、续租跨到期回滚、第二实例 takeover；新增明确断言自然过期和 superseded 的原 owner 均不能 CompleteBackup。
6. 独立 agent 全文只读复核生产、迁移和完成测试，未发现可证实的阻断缺陷；它没有运行数据库测试，不称正式批准。
7. Windows repository `go vet`、`golangci-lint`（0 issues）、Linux/amd64 cross `go vet` 均终态0（session45284）。Linux cross 检查不是 Linux 原生执行。
8. 状态读取联调实际发现创建时间未绑定 begin：SQLite 原反例 **0.225s FAIL**，共享验证修复后同例三轮 **0.471s PASS**。新增续租后创建时间篡改、begin 重算 SHA、begin 缺失/重复均拒绝完成。`go test ./internal/integrity/repository -run '^(TestBackupCompletion|TestBackupOperationReadCreatedTime)' -count=3 -timeout=5m` 真实双库三轮 **49.039s PASS，session43990 terminal0**；状态读取其他在建代码不据此宣称已完成。
9. begin 绑定修复后重跑第5项完整新旧双库组合：**159.994s PASS，session29273 terminal0**。Windows privatefile/repository vet、lint0、Linux/amd64 cross vet **session19332 terminal0**；本次静态检查也覆盖当前操作读取文件已修复后的可编译状态，不代表其专项完成。

首个手工 SQLite `-run` 使用跨层可选 `/` 导致 Go 子测试正则解析失败，未运行用例；随后按实际子测试层级拆分命令才获得上述成功结果，未改测试或放宽期限。

## 后续真实接线

上层实际归档读回阶段 `internal/app/backup_completion.go` 正在接 `privatefile.Read → BackupOpener.Open → backupmanifest.VerifyStream → 原 Seal/WriteNew receipt 比较 → CompleteBackup`；其测试未完成，不包含在本仓储完成证据中。

还须完成受权操作状态/列表、完整 capture 与结构允许集、所有资源/密钥验证、私有可复读 workspace、保守 drain、异步服务生命周期、CLI/HTTP/UI、隔离恢复和双库真实应用演练。完整77需求/91任务不变，正式审核仍待统一审核。
