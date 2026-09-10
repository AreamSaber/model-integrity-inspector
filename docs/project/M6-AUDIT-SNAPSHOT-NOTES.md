# M6-05：同一只读事务中的完整审计链校验

开发状态：内部校验单元已实现，真实双数据库定向与扩大范围回归各三轮通过。正式审核状态：待 V1.0 统一审核；本记录不是批准、完整备份交付或恢复成功凭据。

## 实现与调用边界

- `internal/integrity/repository/audit.go` 把既有完整链算法提取为私有 `verifyAuditFull`：仍先核验尾部两条，再按序号、前序哈希和逐条 HMAC 校验，每页最多 500 条，最终核对计数与链头哈希。
- 原公开 `Tenant.VerifyAuditFull/VerifyAuditTail` 仍自己管理事务；PostgreSQL 仍对链头取 SHARE 锁。保留成功和失败的原有诊断字段：组织、总计数、已经验证的计数、尾部时间，以及封闭错误映射。没有改变 canonicalization、密钥选择或签名算法。
- 新私有 `Store.verifyAuditSnapshot(ctx, tx, orgID)` 只使用调用方给定的实际 `*sql.Tx`，不打开替代事务、不结束调用方事务、不取 PostgreSQL SHARE 锁。清除调用方无关的 Where/Limit 等查询条件，但不替换实际连接池/事务。
- 校验成功后才返回未导出的组织 ID、事件数、末尾哈希、历史链头密钥版本与规范化协议版本；任何失败均返回零值 anchor，不返回部分可信链。格式化及日志只呈现固定说明，JSON/YAML 序列化被拒绝。
- 链头及审计 TEXT 继续使用数据库侧字节上界投影；单页限制不是通过先读取无限文本再截断实现的。前序空字符串等可选字段的超长值仍使用不可签名哨兵，不回放空字段的旧有效 MAC。

## 真实事务要求

调用方是受信任的仓储内部协调代码；本 helper 不是对任意持有 SQL 权限代码的安全沙箱，也不是用户授权入口。

1. 必须有尚未取消且带截止时间的 context、正的组织 ID、已配置签名能力，以及与 Store 相同的受支持方言；组织是否存在及全库清单完整性仍由协调方负责。
2. 拒绝裸 `*sql.DB`、裸 `*sql.Conn`、nil 事务（包括接口内 typed-nil `*sql.Tx`）。没有稳定事务时不能逐页获得“看起来相同”的读视图。
3. PostgreSQL 在实际事务内读取数据库设置，要求 READ ONLY 且 REPEATABLE READ 或 SERIALIZABLE；拒绝 READ COMMITTED 或可写事务。真实 READ ONLY 事务不允许原公开校验所需的 SHARE 行锁，因此不能直接调用公开接口替代本 helper。
4. SQLite 必须由协调方连续独占一个专用连接，先用 `sql.Conn.Raw` 验证 native `IsReadOnly("main")` 为真，再在该连接开启本次确切事务，并持续持有到操作完成。`sql.Tx` 没有 Raw 接口；helper 内 `PRAGMA query_only=1` 仅为附加核验，**不是物理只读打开的证明**。仅声明 `TxOptions.ReadOnly` 也不满足该条件。
5. 调用方负责事务的最终 commit/rollback、取消和连接释放。快照内附带的无关查询条件不能改变整链核验范围。

空链保持既有算法语义：无事件且链头计数为零、哈希为空可以成功；返回的规范化版本表示支持的校验协议，不声称已观察到某条事件。保留已被原算法接受的历史 head key，不用当前 ActiveVersion 改写历史。

## 回归覆盖

- 真实 SQLite `mode=ro` + native flag + query_only 和真实 PostgreSQL READ ONLY 事务：实际 UPDATE 被拒绝，合法校验仍通过。
- 同一事务对两个组织独立校验；502 条主链实际 SQL 回读页尺寸为 `[2, 500, 2]`（尾部 + 两页整链），并验证调用方条件不污染结果。
- 另一个真实连接在只读快照存活时提交第 503 条记录；快照仍返回旧 anchor，公开 live 校验看到新计数，随后原事务仍可查询旧视图。这覆盖错误改用 Store 池读和 PG 错误 SHARE 锁。
- 505 条真实签名链仅篡改第 501 条，原 Tail 仍成功，是尾部校验不足的实际反例；公开 Full 返回 `AUDIT_INTEGRITY_FAILED` 和原有 500 条部分计数、505 条总数及原尾部时间。快照读取 `[2, 500, 5]` 后拒绝且返回零 anchor，不能漏掉第二页篡改。
- 原有中间/尾部删除、内容篡改、链头丢失/错误、前序哈希、未知规范化版本、超长字段等均须失败；不是通过关闭签名或减少读取来“验证”。
- 缺少历史密钥、取消发生在第二页、关闭的事务、缺少截止时间、弱 PG 隔离级别、可写 PG 事务、裸池/连接、typed-nil 和错误方言均被拒绝。
- 子 context 校验取消不擅自关闭父 context 的调用方事务；历史密钥选择、空链原语义、anchor 脱敏和禁止序列化均有回归。

## 验证记录

2026-09-09：首次新增测试执行 `go test ./internal/integrity/repository -run '^TestAuditSnapshot' -count=1 -timeout=3m`，结果 exit 1，包耗时 1.297s。SQLite 子测试无失败；5 个 PostgreSQL 子测试全部在创建隔离 schema 时失败，未到业务断言。随后实际 `pg_isready -h 127.0.0.1 -p 15432` 返回 no response，`pg_ctl status` 返回 no server running，确认受管测试实例已停止；不是把观察超时当成测试终止。root 启动既有集群；启动 helper 的等待曾超时，但同一 server 进程实际仍存活并执行 WAL 恢复，继续等待该进程 ready 后再测试，没有重复启动、重建 cluster、删除锁文件或输出 DSN。

后续真实双库组合命令：

```powershell
$env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText('D:/Tokens-Test/Tokens-Test/.tools/test-postgres/dsn.txt').Trim()
& .tools/go/bin/go.exe test ./internal/integrity/repository -run '^Test(Audit|PostgresSnapshot)' -count=3 -timeout=5m
```

结果：exit 0，包耗时 **53.693s**。包括 6 个新审计快照顶层测试、原 TestAudit 前缀回归及 5 个 PostgreSQL 快照顶层测试；PG 导出事务调用该审计 helper 的一致性也经真实导出/导入测试覆盖。本结果不是实际 pg_dump 文件或恢复证据。

原生 Windows `go vet ./internal/integrity/repository` 与 `golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...` 最终 exit 0、0 issues。首次 lint 发现本单元两项简化提示（访问嵌入 Dialector 和冗余显式类型），已修正；未关闭规则。另在 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 下执行相同 vet/lint，均 exit 0、0 issues；这仅为 Linux 目标静态检查，不能当作 Linux 原生测试运行证据。

扩大范围的 `go test ./internal/integrity/repository -run Audit -count=3 -timeout=10m` 最终 **exit 0，包耗时 222.644s**；`go test -list Audit` 实际枚举 49 个顶层测试，覆盖原有 operational、初始化、并发追加、身份/会话、基线/目录、执行、证据读取、报告、复核、保留清理、维护门禁与 Worker 的审计关联路径。执行期间 `MII_TEST_POSTGRES_DSN` 指向真实受管 PostgreSQL 隔离 schema，SQLite 和 PostgreSQL 分别运行。并非所有仓储测试或完整产品回归。

工具实际版本 `go version go1.26.7 windows/amd64`。上述测试和静态检查句柄均已终态退出；数据库独占使用已交回集成方，`pg_isready` 仍 accepting connections，未停止受管集群。源码尚需由 root 统一审阅并按显式文件列表提交；不在本子任务执行 Git 写操作。

## 不在本单元内的交付

本 helper 只认证指定组织在指定一致读视图中的整链，不证明全组织清单完整、不识别所有孤儿记录、不提供初始化/维护门禁、不持有独立外部反回滚锚点，也不授予备份或恢复权限。整库组织枚举、schema/inventory、数据库实际备份、报告/配置文件归档、统一 manifest、激活/回滚、CLI/API/UI 和新环境恢复演练仍由后续协调器实现并验证。未取得真实归档和恢复证据前，不得关闭 M6-05、SYS-008 或整个 Goal。
