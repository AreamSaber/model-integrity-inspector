# M6-05 / SYS-008 PostgreSQL 导出快照事务

更新：2026-09-09。状态：内部生产实现及真实 PostgreSQL 快照共享/失败路径已三轮验证；不是 pg_dump、系统内备份或恢复交付。正式审核仍待全部开发完成后统一进行。

## 范围和约束

`internal/integrity/repository/postgres_snapshot.go` 为受信仓储内部协调器提供 `withPostgresSnapshot`：保持真实 `REPEATABLE READ READ ONLY` 事务，读取服务端版本/事务时间，取得有界的 `pg_export_snapshot()` 标识，并在同一事务中同步消费。业务服务没有获得 GORM/通用 SQL 接口。

- 必须提供有效 deadline，最大沿用维护操作的 24 小时资源上限；这不是完成速度或生产容量承诺。事务局部 statement/lock timeout 为剩余 deadline，不改连接的持久设置。
- 实际检查服务端 RR/RO 状态，不以 Go `TxOptions` 字面值作为唯一证明。服务端版本整数只做元数据合理性检查，不能推导已验证所有 PostgreSQL 版本。
- token 只接受 1～128 字节服务端返回值，并进一步限定三个非空十六进制组；不得接收来自 HTTP/用户的 token，也不得传给 shell。
- `use` 同步串行消费；第一次消费失败会保留，调用者吞错/再次消费仍不能把失败变成成功。外层提交也必须成功才能发布备份。
- 回调结束、失败、取消或 panic 时关闭能力并清空事务/token/元数据；普通错误经过仓储闭集映射，格式化/日志不输出 token，JSON/YAML 序列化拒绝。
- 这是内部信任契约，不能抢占不合作的 Go 回调，也不能阻止有本机代码控制权的调用方保留 SQL 对象或启动脱离生命周期的进程。未来协调器必须等 inventory 和 dump 完成后才结束事务；不能以本 helper 代替维护权限、失租 fence 或原子发布。
- 导出事务结束后不能再导入该快照，但**已经导入的事务可以独立继续**，须由导入方管理。实现不声称能自动撤销已经导入的事务。

语义依据：[PostgreSQL 18 快照同步函数](https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-SNAPSHOT-SYNCHRONIZATION)、[SET TRANSACTION](https://www.postgresql.org/docs/18/sql-set-transaction.html)。测试导入器在新事务的第一次数据查询之前导入快照；SET 的快照 literal 仅由已经独立校验的服务端十六进制 token 构造，不是生产输入拼接接口。

## 可复现验证

本地工具为 Go 1.26.7 和既有 PostgreSQL 18.6。DSN 从忽略目录 `.tools/test-postgres/dsn.txt` 读入 `MII_TEST_POSTGRES_DSN`，禁止输出其内容。

```powershell
$env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText('D:/Tokens-Test/Tokens-Test/.tools/test-postgres/dsn.txt').Trim()
& .tools/go/bin/go.exe test ./internal/integrity/repository -run '^Test(Audit|PostgresSnapshot)' -count=3 -timeout=5m
& .tools/go/bin/go.exe vet ./internal/integrity/repository
$env:PATH = (Join-Path $PWD '.tools/go/bin') + ';' + $env:PATH
& .tools/golangci-lint/golangci-lint.exe run --allow-parallel-runners ./internal/integrity/repository/...
```

真实测试覆盖：

1. SQLite 明确拒绝 PostgreSQL 专有操作且回调未执行；PG 导出事务内验证真实初始审计链，另一连接追加并提交后，原快照与独立导入事务仍保留旧计数/哈希，正常公开校验看到新事件。导出提交后服务端明确拒绝新导入。
2. 实际 UPDATE 在只读事务中失败，吞掉 SQL 错误后外层 Commit 仍失败；回调未知错误、消费错误被吞、nil callback、提前 rollback、取消、panic 均验证能力结束及数据未改变。独立自查后追加每个失败分支的服务端证据：用独立 context 和新 RR/RO 事务尝试再次导入同一个合法 token，最终必须得到服务端快照不存在的 42704；连接失败或 context 取消不算该证据。database/sql 取消回滚可能异步发生，观察有 2 秒上限，不假设返回瞬间已完成。
3. 最大连接数固定为 1，以同一个实际 backend PID 比较事务前后设置，证明 timeout/isolation/readonly 未污染池连接；占住唯一连接后有界请求在获取连接阶段取消且不调用消费者。
4. 独立连接实际观察对应 backend 的 `PgSleep` 等待后才取消正在执行的 SQL，验证不是只测试预取消请求；要求有界返回闭集取消错误。
5. 无 deadline/超长 deadline/已取消/空请求、token 字符与长度边界、格式化与序列化边界。

实际结果：上述组合双库命令三轮 **53.693s PASS**，包含本文件对应的五个顶层测试、六个审计快照顶层测试及原 TestAudit 前缀测试；仓储 go vet 通过，golangci-lint **0 issues**。本机是 Windows 原生 PostgreSQL 18.6，不冒称新代码已通过 Linux 原生 CI。前一提交 `3ffad26` 的 CI34204020837 已确认全部 success，但不用于追认这些新增改动。

最终补强后的 `go test ./internal/integrity/repository -run '^TestPostgresSnapshot' -count=3 -timeout=3m` **15.493s PASS**，随后仓储 vet 通过、lint **0 issues**。追加的服务端失效断言首轮三轮7.027s失败，定向诊断2.167s确认实际SQLSTATE为42704；错误在测试预期22023，并非生产事务泄漏。核对[PostgreSQL 18 ImportSnapshot 源码](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/utils/time/snapmgr.c)后限定正确的42704（有效格式但快照已不存在），没有放宽为任意错误。补强后才获得上述最终通过结果。另有49个审计相关仓储顶层测试双库三轮222.644s PASS，包含原业务审计兼容路径；不是仓储全包或完整产品终审。

恢复测试环境时，最初既有 PostgreSQL 无进程/无监听；启动辅助进程的 30 秒等待超时，但服务端26484实际存活并在异常关机后的 WAL recovery。没有重启或重建该活进程；随后同一实例日志与 pg_isready 均确认 ready，才开始上述双库测试。这是既有测试集群恢复，不是产品备份恢复演练。

## 未完成范围

尚未调用真实 `pg_dump --snapshot`。同快照完整 inventory、schema/对象范围核验、受控 dump/restore 子进程及认证环境、文件/配置归档、备份 receipt、系统内入口、恢复校验/激活和干净环境演练仍需实现。当前测试是 SQL 快照共享证据，不是数据库导出文件或恢复成功证据；M6-05、SYS-008、OPS-03 和整个 Goal 不关闭。
