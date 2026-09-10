# M6-05：同一快照内的全组织审计锚点清单

2026-09-09。开发状态：私有仓储单元已实现，真实双库快照组合三轮通过。正式审核状态：待 V1.0 统一审核；本单元不是完整 backup inventory、系统备份入口、恢复成功或正式批准。

## 依据与初始化边界

已读取 `backupmanifest/manifest.go`、`validate.go`、M6-BACKUP-IMPLEMENTATION-NOTES、M6-BACKUP-MANIFEST-NOTES、组织模型/创建流程、foundation 与 identity 迁移及 `identity.go` 的真实初始化事务：

- `Initialize` 原子创建初始组织/用户等，写 `initialized` 值为精确 `true`，写 `initial_organization_id` 为正 int64 的十进制表示，并追加初始化审计事件。
- 公开 `SetupStatus` 仅检测 `initialized` 行是否存在；新私有备份前提不改动该公开行为。备份候选必须具有精确 `true` 及有对应组织的规范正十进制 initial ID。
- 缺初始化行返回闭集 `SNAPSHOT_AUDIT_NOT_INITIALIZED`，即使已经存在组织也不返回 anchors。该错误表示缺少已提交初始化标记，不证明数据库内绝无其他残留数据。
- 有初始化行但值错误、初始组织设置缺失/超长/非规范/非正数/无对应组织时返回 `AUDIT_INTEGRITY_FAILED`。设置值在 SQL 端分别限制为 4、19 字节后读取；不会先把任意长 TEXT 载入 Go 再截断。
- 上述仅是本清单的只读一致性前提。它不证明用户/角色/所有业务表已通过初始化核验，不认证 marker 的独立来源，也不提供维护门禁或授权。
- manifest v1 的 `audit_history=complete` 不支持密封/删除历史分段；同一快照存在任意 `integrity_audit_segments` 行即返回 `SNAPSHOT_AUDIT_SEGMENTS_UNSUPPORTED`，不能悄悄遗漏。未来分段功能仍须升级格式和恢复实现。

## 实现与信任边界

代码：`internal/integrity/repository/snapshot_audit_inventory.go`。

私有 `Store.snapshotAuditInventory(ctx, tx)` 只用调用方持有的实际稳定只读 `*sql.Tx`。拒绝裸池/连接、typed-nil、错误方言、缺截止时间或取消；实际核对 PG READ ONLY + REPEATABLE READ/SERIALIZABLE，SQLite query_only 只作附加核验。SQLite 必须仍由可信协调方在专用连接上、BeginTx 之前通过 Raw 验证 native physical RO，并连续独占该连接；本 helper 不声称 query_only 或 TxOptions.ReadOnly 能证明物理只读。

固定步骤均发生在同一事务：

1. 清除调用方无关 Where/Limit 等条件，不更换底层事务；核验上述初始化事实。
2. 用仅返回标量的 EXISTS 查询拒绝非正组织 ID、没有组织的审计链头/事件；非法 ID 必须在正 ID 游标枚举前检测，避免被 `id > 0` 静默过滤。
3. 拒绝不受当前 manifest 支持的审计分段。
4. 以 `id > after ORDER BY id LIMIT 100` 枚举全部组织，包括 disabled 组织，不按操作者成员关系筛选。逐组织复用既有 `verifyAuditSnapshot` 完整 HMAC/连续序列/哈希链核验；缺链头等失败不能返回部分集合。
5. 数量上限固定为 `backupmanifest.MaxOrganizations`（16,384），不截断。私有较低 limit 只能收紧该硬上限；实际生产入口不接受可变 limit 参数。
6. 最终取消检查通过才返回独立拥有的私有 anchor slice；格式化和日志固定脱敏，JSON/YAML 序列化被拒绝。任何错误返回零值集合，先前认证过的组织也不作为部分成功输出。

方法不管理事务结束、不锁审计头、不更新源库、不改变维护状态，不验证其他业务表的全部外键或物理 schema/索引定义。协调器仍须分别完成 schema 验证、维护授权和全量 backup inventory；该私有集合不是不可伪造授权凭证或独立外部反回滚锚点。

清单内部返回精确私有错误。root 集成时补充 PostgreSQL 快照外层的三类闭集映射，保留未初始化/上限/不支持分段的分类，同时丢弃错误包装原文；未知错误仍归一不可用。真实未初始化库在外层先出现 `DATABASE_UNAVAILABLE`（1.406s FAIL），随后修复。这仍不是 HTTP 状态映射或产品备份入口。

## 真实回归与反例

所有数据库用例均使用真实 SQLite 与 PostgreSQL；组织、签名事件通过实际迁移和初始化基础建立。Mock 没有替代数据库。

- 101 个组织真实分页为 `[100, 1]`，包含 disabled 组织；逐一比对排序后的 ID、真实事件数和签名锚点，外加传入 `Where(1=0).Limit(1)` 不得污染枚举。
- 验证第一页 100 个组织后，第二页触发更低 cap 时，必须返回 limit 错误与零集合。另有实际 3 行分别超过 1/2 行 cap、恰好 3 行成功及禁止把私有 cap 提高到生产硬上限以上。这证明实际 SQL 触发的上限路径，不声称已进行 16,384 组织的容量验收。
- 快照建立后，另一个真实连接提交新组织及新审计事件；同一快照仍返回原来 101 个组织/旧链头，新只读事务看到 102 个组织及追加事件。修改此前返回的 owned slice 不会污染后续新结果。
- 按真实排序篡改第二组织第 1 条事件；计数签名器证明首组织已成功校验、第二组织的 HMAC 才失败，返回零集合。取消同样发生在第二组织，不能输出首组织的部分锚点。
- 空的已迁移库、已存在组织却缺初始化 marker、错误/超长 marker、缺失/超长/不存在初始组织均被拒绝。真实小 ID=7 组织让 `+7`、`07` 等值既未超长又可指向现存组织，仍因不规范而拒绝，避免被“长度超限”或“不存在组织”掩盖解析反例。
- 1 MiB 的实际设置值另直接核对有界读取结果为 SQL 侧单字节换行哨兵，而不是将超长值返回后才解析失败。该哨兵不可能成为合法初始化标记或规范十进制 ID。
- 缺链头、孤儿链头、孤儿事件、组织 ID=0/-1 均失败。先证明正常约束拒绝非法行，再只在该用例的临时 SQLite 文件/隔离 PostgreSQL schema 内绕开单项约束，真实插入非法数据。SQLite 在离开 fixture 前恢复并实际核对 foreign_keys=1、ignore_check_constraints=0；PG 仅删除隔离 schema 内固定表的固定约束，整个 schema 由既有测试框架清理。没有修改生产库或放宽生产 API。
- 有 segment 实际记录时不允许生成 complete 清单；脱敏、禁止序列化、裸池/裸连接/typed-nil、弱 PG 隔离或可写事务、SQLite 缺 query_only 均有回归。

## 执行记录

首次 `go test ./internal/integrity/repository -run '^TestSnapshotAuditInventory' -count=1 -timeout=5m`：**exit 1 / 9.196s**。两库仅 zero_organization fixture 无法插入 0 ID，因为 GORM 对结构体零主键省略 id 列，实际触发 NOT NULL 而非所需的已绕开 CHECK 反例。测试改为固定列 map 明确发送 id=0；生产实现和约束检查未改变。这是测试构造错误，不是生产缺陷的红绿证据。

修复后初始 6 个顶层测试真实双库三轮：**exit 0 / 28.774s**。首次 lint 发现测试 if 链的 QF1003 简化提示，已改为 tagged switch，没有屏蔽检查。随后补充跨页超限、规范小 ID、SQL 设置投影和真实裸连接回归，扩大至 7 个顶层测试。

首次扩大组合三轮 **exit 1 / 54.386s**：仅新增超长设置直接读取断言失败。原因是测试误把文档字段的空哨兵用于标量：既有 `readBoundedText` 对 <=256 字节标量正确返回单字节换行哨兵，只有大型文档才返回空串。详细诊断命令单轮 **exit 1 / 18.017s**，双库实际返回均为 `error=nil, present=true, returned_bytes=1`。改为精确断言 `"\n"`，保留 4/19 字节 SQL 限额和 1 MiB 实际输入；生产 helper 未改变，不能把这次测试预期修正说成修复了生产内存缺陷。

可复现组合命令（不输出 DSN）：

```powershell
$env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText('D:/Tokens-Test/Tokens-Test/.tools/test-postgres/dsn.txt').Trim()
& .tools/go/bin/go.exe test ./internal/integrity/repository -run '^Test(SnapshotAuditInventory|AuditSnapshot|PostgresSnapshot)' -count=3 -timeout=5m
```

最终上述组合命令 **exit 0 / 230.787s PASS**，包括 7 个 inventory、6 个 audit snapshot、5 个 PostgreSQL snapshot 顶层测试，真实双库三轮。本次比前轮慢；执行时确认同一个 go/test 进程实际存活，PG accepting，没有等待锁的状态分类。继续等待原句柄直到在原 5 分钟时限内成功退出，没有更改 timeout、重新启动测试或 PG、跳过测试；没有足够证据把慢运行归因于特定系统原因。

原生 Windows 仓储 `go vet ./internal/integrity/repository` 和 `golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...` 已 exit 0，0 issues。`GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 下同样 vet/lint 最终 exit 0、0 issues；这仅是 Linux 目标静态检查，不是新的 Linux 原生测试或 race 证据。测试数据库独占权已交回 root，所有本单元 DB 测试句柄均已终态退出，未停止受管 PG。

root 完整读取并集成后，增加真实 PostgreSQL 外层未初始化拒绝及三种闭集错误包装/吞错回归。映射修复后同一组合命令（现 8 个 inventory 顶层测试）真实双库三轮 **54.349s PASS**，保留既有隔离、分页、取消与快照生命周期断言；没有放宽 5 分钟期限。新增错误测试首次 1.406s 失败与修复后的结果分别保留。

## 尚未完成的交付

此处只补齐所有组织及对应完整审计链锚点，不是迁移、报告、工件、密钥引用、Job/Attempt、配置模板的完整清单；没有实际 pg_dump、归档文件哈希、备份 ready/download、恢复校验/激活、CLI/API/UI 或干净环境恢复演练。SYS-008/M6-05 和整个 Goal 继续进行中，正式审核仍待统一进行。
