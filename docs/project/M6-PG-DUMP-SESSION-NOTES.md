# M6-05 PostgreSQL dump 服务端会话清理

日期：2026-09-09。独立开发切片，不代表完整备份/恢复、M6-05 完成或正式审核批准。

## 接口与授权边界

仓储内部新增 `Store.dumpPostgresSnapshot(ctx, view, executable, connection, request, output)`，返回 `pgbackup.DumpReceipt, error`。调用者必须仍位于 `withPostgresSnapshot` 的同步 consume 内，不能递归从已持有锁的 `view.use` 调用。此方法自身持有 `view.use`，覆盖本地 native 子树与服务端 dump 会话的整个生命周期；库存可在同一个 consume 中先通过独立 `view.use` 读取。任何错误都返回零 receipt；外层 snapshot Commit、维护权限、完整 inventory、私有输出与成品发布仍需协调器完成。

这是受信内部单元，不接受 HTTP SQL、任意 PID 或任意 application_name。它以 OS CSPRNG 为每次 dump 生成 128-bit 随机标识，形式 `mii-backup-<32 lowercase hex>`；拒绝调用者覆盖。request 中的 Snapshot 只能为空或等于当前真实导出值，并最终使用导出值。主线负责将唯一标识接到 pgbackup 的显式 `PGAPPNAME`。

有效 view 上的所有前置拒绝也在 `view.use` 内记入 sticky failure，包括调用者 nonce、预取消的独立子 context、无期限 context 与无效源 Store；即使上层检查错误后返回 nil，也不能再次 use 或将外层 snapshot 提交为成功。只有缺失/不可用 view 不存在可记载的活能力。清理完成及控制连接 Close 后复查取消，避免清理期间晚到取消仍返回 receipt。主线对 snapshot 错误映射的配套修改独立维护。

控制连接预先取自源 `Store.sql.Conn`，不解析 DSN、不读取环境变量、不创建另一套 TLS 配置。检查快照实际 transaction 的 `current_database/current_user` 与受信 connection 参数一致；再检查控制连接的数据库/角色及 OID、服务端地址/端口相同且物理 PID 不同。控制查询使用源池已建立的认证和 TLS 策略，**Dump 参数不能证明或加强源 Store 的 TLS/CRL 配置**；两侧配置等价仍由后续应用适配层负责。不支持在事务间调换服务器 backend 的连接池代理。不会授予 superuser、pg_signal_backend 或改变角色权限。

## 观察、身份与清理

- 每次观察都使用独立 READ COMMITTED READ ONLY 事务，并检查 Commit；不用导出事务的 RR 读视图或跨查询保留的统计快照。statement_timeout/lock_timeout 使用 SET LOCAL，不污染归还到池的连接。
- 按随机 application_name 找最多两条实际 `pg_stat_activity` 行；重复身份直接失败，不挑其中一条或批量终止。完整绑定包括数据库/用户名称与 OID、client backend、PID 和 backend_start；已结束或更换 PID/start 的 nonce 不允许复用。
- 真实重复测试曾出现 `observe_scan timeout=false`：启动早期 application_name 已可见，而 database/user OID 仍为 InvalidOid；非超级用户也可能因此看到 backend_start 等字段为 NULL。现保留明确 pending 状态，等待完整身份，**不以 nonce/PID 单独绑定或发信号**。任一已知字段不匹配仍立即拒绝。依据见 [18.6 backend_status.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/utils/activity/backend_status.c) 的 initial/final 分阶段状态与 [pgstatfuncs.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/utils/adt/pgstatfuncs.c) 的 InvalidOid/权限裁剪。
- 运行中每 10 ms 发起有限观察（每个控制事务最多 250 ms）。取消时，本地进程树停止与服务端清理并行；清理使用独立 1500 ms context，而不是已取消的调用 context。在单独新事务里再次同时约束全部已绑定身份才调用 `pg_terminate_backend(pid,500)`，该事务最多 750 ms；随后新事务确认该 nonce 的会话不存在。SQL/控制通道/权限/Commit/Close/超时错误均闭合，保留零 receipt，不把仅发信号视为清理成功。
- 正常 native 退出也需服务端终态检查。原 native helper 仍只负责自己本地子树；本单元不调用全局 PostgreSQL 设置，不提前释放测试锁，也不延长两秒实际取消断言。
- 驱动错误不保留或传播；诊断只有固定阶段名与 timeout 布尔。源 DSN、账号名、密码、SQL、nonce、backend_start 不进入错误内容。

已完整绑定实际 backend 后，若控制通道发生连接类故障，可在原有 **1500 ms 总 cleanup context** 内从同一 `Store.sql` 再取得独立连接一次，并完整复验源数据库/角色/端点身份后重新观察及精确终止。这只是恢复清理渠道，不重试 dump、不重置总时限。未绑定、重复/替换身份和权限错误不尝试此恢复；数据库明确返回 42501 等非连接错误时，即使本地 context 同时到期也不重试。非数据库网络/连接关闭/本地时限错误，以及闭集连接 SQLSTATE 才可能符合恢复分类。

重获失败、源身份不同或仍不能确认服务端终态都保持身份/清理错误和零 receipt。清理恢复成功也不能把曾失败的 dump 转为成功：原取消继续返回取消；运行中控制故障且成功清理返回 ErrUnavailable；不发布新 receipt。

状态区分：

| 情形 | 结果含义 |
| --- | --- |
| 明确的配置/工具版本前置失败且未发现会话 | 原闭集失败；不声称曾观测或清理 backend。 |
| 成功原生退出，轮询未捕获短命 backend，退出后新观察为空 | 可以保留成功 receipt；只声称完成原生操作并确认当下无会话，不伪造观测记录。 |
| 已完整绑定 backend，取消/异常后确认会话不存在 | 服务端清理已确认，仍返回取消/操作错误与零 receipt。 |
| 取消启动窗口内从未取得完整身份 | 在有限窗口继续观察；仍未确认则 `POSTGRES_DUMP_SESSION_START_UNOBSERVED`，不能把零行解释为已观测清理。 |
| pending/重复/替换身份、权限不足、控制通道失败或清理超时 | 闭合身份/清理失败，可能需要后续受权协调；不会扩大信号选择范围。 |

PostgreSQL SQL 信号 API 最终按 PID 发信号，官方实现承认极窄 PID 复用竞态。本单元在每次 signal 前重新限定全部身份以防协调器误选，但不声称零竞态的 OS 能力句柄。[signalfuncs.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/storage/ipc/signalfuncs.c)、[信号接口与等待语义](https://www.postgresql.org/docs/18/functions-admin.html)

不采用 client_connection_check_interval 作为跨平台保障：Windows 不支持非零值。也没有切换为 pg_dump 的优雅信号，因为固定 18.6 该路径使用弃用的明文 PQcancel，即使数据连接要求 TLS。[PG18 连接参数](https://www.postgresql.org/docs/18/runtime-config-connection.html)、[pg_dump 信号实现](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/bin/pg_dump/parallel.c)、[libpq 取消接口安全说明](https://www.postgresql.org/docs/18/libpq-cancel.html)

## 测试与当前证据

新增 `postgres_dump_session_test.go` 使用 `pgbackup_integration` tag 与 `TestPostgresDumpSession*` 前缀；真实测试依赖显式固定 18.6 工具及授权测试数据库，不 Skip。管理员连接仅在新隔离数据库/随机新角色的 fixture 建立和精确清理阶段使用；生产方法实际使用 NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS，且没有 pg_signal_backend membership 的角色。

- 真实取消隔离：两个不同随机 nonce 的 pg_dump 同时被测试自有 ACCESS EXCLUSIVE 锁阻塞；取消其中一个要求两秒内完成，本轮目标会话消失而另一个仍在 Lock wait，同角色且常量 `mii-backup` 的旁路连接 PID 不变；随后同样取消第二个。所有服务端断言完成后才释放锁。
- 真实成功与身份拒绝：非超级用户完成实际 dump 并给出有效 receipt；错误数据库、角色、来自不同角色 Store 的控制池、调用者 nonce 与错误 snapshot 均失败且没有 receipt。
- 真实控制会话 + 合成 executor 结果：区分前置失败、短命成功、取消时未观测、已观察退出与控制连接关闭。这些状态测试不冒充 pg_dump/恢复输出证据。
- 真实重复与替换连接拒绝、pending 身份纯分类；在新建隔离数据库内撤销函数 EXECUTE 作为权限负控，证明清理失败闭合且不授予新权限。函数 ACL 不作用于配置的 control DB；新库用后删除。
- 真实 control.Close 故障：先让实际非超级用户 pg_dump 到达 Lock wait 并完整绑定，再关闭控制连接；在同池单次恢复后，两秒内本地进程与服务端会话均结束，另 nonce 的 PID 保持不变，原排他锁直到断言完成才释放。补充真正控制连接上的已关闭恢复池/错误角色池拒绝、不得二次恢复的状态用例（executor 结果为合成，不冒充 dump 证据）。
- sticky 真实回归：故意吞掉 caller_nonce、precanceled_child、unbounded_child、nil_source 的失败，后续 view.use 不执行且外层失败。纯分类回归覆盖到期 context 加 42501/57014 不恢复、连接 SQLSTATE/网络/ErrConnDone 分类和驱动 canary 不泄露。

开发中单轮完整专有套件曾 **8.554s PASS**；随后重复测试揭示上述 startup NULL 字段处理问题，因此不把那一次通过当最终结论。修复后的真实取消隔离 **10 轮 13.684s PASS**。恢复/sticky 独立实际三轮 **6.492s PASS**；完整专有三轮 **29.709s PASS** 后，独立复核再收紧明确 PgError 与本地 deadline 同时发生的恢复分类，纯分类三轮 **0.209s PASS**。最终修正版完整三轮与静态检查见下方，不以进行中运行冒称成功。

最终修正版执行记录：

- `go test ./internal/integrity/repository -tags pgbackup_integration -run '^TestPostgresDumpSession' -count=3`：**Windows 原生三轮 34.266s PASS**。所有实际 fixture 清理通过，没有通过放宽服务端取消断言或提前释放锁实现通过。
- Windows 仓储包默认及 tagged lint **0 issues**；最后修正后 tagged lint 再次 **0 issues**。主线通过普通无 tag 的真实 API 前置拒绝测试建立默认 lint 可达性，没有给整个新增文件屏蔽 unused。
- 最终 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` tagged 测试二进制交叉编译、vet、lint **0 issues**；`.tools/postgres-dump-session-linux.test` 仅为本地交叉编译制品，不是 Linux 执行证据。Linux 原生及 race 验证由后续 CI 执行，本文不追认旧 CI。
- 终态后已将数据库独占测试时段交还主线；三个新增文件冻结。主线此前 RoundTrip/ExactSchema/Cancellation 的实际集成与 fixture 修复证据由主线记录，不与本单元的测试结果混用。

本单元不启动/重启 PostgreSQL；使用主任务交接的现有隔离服务器时段，只在自己新建的角色/数据库中运行测试。没有修改主线 fixture 的清理期限、服务器 fsync/checkpoint 参数或 Git。Windows 结果不代表 Linux 原生运行；完整新库恢复及应用端到端验证属于主线后续范围。
