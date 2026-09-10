# M6-05：同一只读快照内的不可变报告清单

2026-09-10。私有仓储单元已实现并完成真实 SQLite/PostgreSQL 专项测试。此处只是报告元数据、冻结输入与当前内核可重现字节的一致性观察；不是完整备份、磁盘文件验证、可信来源认证、恢复成功或正式批准。正式审核仍待 V1.0 全部开发完成后的统一审核。

## 依据与交付

完整读取当前 `report_source.go`、`report_completion.go`、`run/report_snapshot.go`、报告内核的 `types.go` 与 `validate.go`、实际只读事务夹具，以及相关报告/执行/分析测试。遵循现有 immutable source publication 协议，不修改旧迁移、发布语义、报告格式或授权边界。

本单元仅拥有：

- `internal/integrity/repository/snapshot_report_inventory.go`
- `internal/integrity/repository/snapshot_report_inventory_test.go`
- 本说明。

共享 `postgres_snapshot.go` 的闭集错误接线和真正导出快照外层测试由 root 集成，不在本单元修改范围。它们的最终证据以 root 集成记录为准。

## 事务与完整性

`Store.snapshotReportInventory(ctx, tx)` 只接受匹配方言、持有活跃 deadline 的真实 `*sql.Tx`。`NewDB` 清除调用方残留 Where/Order/Select/Limit；没有回退到 `Store` 的 live pool，没有自行开启、提交或回滚事务。

- PostgreSQL 要求 READ ONLY 且 REPEATABLE READ/SERIALIZABLE。
- SQLite 的 `query_only=1` 只是补充要求。可信调用者必须先在专用连接 `Raw` 上核验 native `IsReadOnly("main")`，再在同连接 BeginTx；本方法不把 pragma 当成物理只读证明。
- 查询全部 `status='ready'` 报告，不按当前组织、成员状态或导出授权过滤，禁用组织的历史仍保留。其他报告状态由后续 Job/全库 inventory 处理，不伪造已完成的文件。
- 按 ID 保留 report ID、organization ID、run ID、analysis revision、report revision、format、document schema、source/content/file hash、source/file byte size 和由现有 `ReportObjectName` 得到的受控对象名；不同修订不会去重或覆盖。
- 核验现存组织、用户、同组织 Run、同分析修订的已发布 Result，以及具有精确 report object/idempotency key 的 completed report Job。该关系检查不是当前权限认证，也不能证明数据库未被协调篡改。
- JSON/HTML/CSV 均调用既有报告内核重建 content hash、文件 hash 和字节数。CSV 直接调用 `GenerateCSV`；document schema 仍为 `mii.report.v1`，不误换成 CSV 导出 profile。
- 冻结 source 严格解码为与 `run.BuildReportSnapshot` 完全相同的私有 `{versions,input}` wire type，和原 `json.Marshal` 字节逐字节相等；拒绝重复、别名、未知字段、尾随文档或额外空白。再核验固定 Run 版本/目标和内核语义，不复制 hash 算法。
- 时间字段接受真实 PostgreSQL TIMESTAMP 文本以及当前 SQLite 驱动实际存储的 RFC3339、无时区文本和 `time.String` 格式，核验 `created <= frozen <= completed`。生成时间来自原报告创建时间，不换成备份时刻。

`snapshotReportInventory` 与 entry 都是独立拥有的私有结果，fmt/slog 固定脱敏，JSON/YAML 拒绝；不返回 frozen source、生成正文、数据库连接或通用文件读取权限。

## 资源与失败边界

报告项上限沿用 manifest 的 `MaxEntries-3`。先用 SQL `LIMIT cap+1` 的 count 拒绝超限，再以每页 100 项 keyset 遍历；最终项数必须与初始 count 相等，不能用被截断的前缀宣称完整。测试 cap 只能收紧上限。

元数据 SQL 投影对数值范围和每个字符串的编码字节数设限；SQLite 另检查真实 integer/text 存储类型。超长值在 SQL 内变成无效哨兵，不先加载完整超大文本。

正文不进入元数据页：每次最多取一个 4 MiB frozen source，使用同样的 SQL 字节界限，核验后不在结果中累积。预解析的 4,096 字节字符串和 2,048 集合项边界与当前报告内核一致，深度上限 64 高于内核的 24；不保留独立的任意 200,000 token 限额，总 token 数自然受原始 4 MiB 文档约束。随后仍由内核执行其完整 preflight 和输出 16 MiB 限制。

这些是拒绝资源过载的政策，不是已验收的生产最大容量；完整 coordinator 还必须为规则、模板、数据库等项目预算整个 manifest/归档大小。

- 配置、deadline 或事务前置不满足：`ErrConfiguration`。
- SQL 故障、实际事务已结束或取消：固定 `ErrUnavailable`，不泄漏底层 SQL/错误正文。
- 不完整、冲突或无法重现的现代报告：`SNAPSHOT_REPORT_INVALID`。
- 超过固定/收紧项数上限：`SNAPSHOT_REPORT_LIMIT`。
- 旧 ready 行缺少 immutable source publication 字段：`SNAPSHOT_REPORT_UNSUPPORTED`。不会跳过旧报告、编造新 source 或改写原哈希。

任何失败均返回 `entries=nil`。包括已完成第一整页及 101 个 source 验证之后的最后一行损坏、第二份 source 查询后取消/故障，不存在携带部分结果的错误返回。

旧报告兼容仍是整个备份 Goal 的后续必需工作：这里显式拒绝无法完整验证的旧格式不等于最终可以不备份这些历史。当前重现器只支持当前开发内核；未来历史版本内核/真实文件载体的保留策略也必须在全 inventory/coordinator 中完成，不能据此宣称完整版本闭包。

## 可复现测试与真实发现

数据库测试使用临时 SQLite 文件及 General PostgreSQL 独立 schema；SQLite snapshot fixture 实际在 BeginTx 前检查 native physical RO，没有 mock 数据库。没有接触 Backup cluster 或调整实例配置。

报告夹具从真实创建的执行计划开始，使用当前编译 bundle 常量，真实完成 sample、发布 analysis，再执行 CreateReport → Claim → LoadReportSource → FreezeReportSource → 既有内核 render → CompleteWith(PublishReport)。S1 输入是绑定真实 run/sample/attempt 的 typed 内核夹具，不是旧存储测试的 `synthetic_s1`，但也不冒称已经调用 `run.BuildReportSnapshot` 或完整 Worker/分析 E2E。

主要覆盖：

1. 101 个真正发布的 JSON/HTML/CSV 报告，实际观察元数据分页为 100/1；逐项比较全部原字段和 source size，污染 GORM clause 不影响完整结果，只有 driver 的 poolless Store 仍成功。
2. 另一真实 Store/连接重新绑定当前会话，关闭旧 consumer 后真正 OpenJobQueue 获取新 consumer，再发布第 102 个报告；旧只读快照仍为 101 项，新快照为 102 项。禁用组织后保留其历史；修改返回项不污染后续重读，原始 101 个 DB 行保持逐字段相等，原调用者事务仍可 SELECT。
3. 正常 ready 行先实际拒绝修改；只对隔离 fixture 保留并重命名原表、创建无约束副本以模拟 offline 损坏。PostgreSQL 副本显式将 timestamp 改为 text、revision 改为 bigint，使正常物理类型会拒绝的损坏确实进入 inventory 测试；清理恢复原表。原迁移和生产约束不变。
4. NULL、非正 ID、重复 ID、孤立/错误组织/Run/Job/creator、非法修订/格式/schema、各哈希、字节数、对象路径、时间顺序、error_code，以及全部 legacy 必需字段缺失；SQLite 另覆盖 REAL/BLOB 混淆。
5. 多个元数据列分别写入约 1 MiB 多字节字符串后，SQL 投影中所有字符串仍不超过 128 字节；超 4 MiB source、伪 source/hash 配对、别名/重复字段/尾随文档及过深结构均失败。
6. 实际两行对 cap=1 拒绝、实际一行对 cap=1 成功；最后第 102 行损坏时前 101 项不泄漏；第二份实际 source 查询后取消/注入含 canary 的错误仍固定 ErrUnavailable/零结果。注入 callback 不冒称实际网络故障或锁等待时延测试。
7. nil context/DB、无 deadline、裸 pool、弱隔离、关闭/取消事务、非法 cap、方言不匹配，以及值/指针的 fmt/slog/JSON/YAML 表示。
8. 纯内核兼容用例分别使用最大 512 样本×3 次 Attempt、256 findings、2,048 behavior patterns：先由实际 `NewDevelopmentSnapshot` 接受，再确认 snapshot source decoder 不施加更窄集合限制；不是用自行发明的阈值作为 oracle。

本轮实际失败均保留在交接记录，不计为通过：

- 首轮双库 **3.708s FAIL**：沿用了存储专用 `reportFixture` 的 opaque `"1"` 版本，真实报告内核正确拒绝；改为在创建执行计划前选用真实编译版本，未修改历史记录或放宽内核。
- 后一轮双库 **9.587s FAIL**：发现 SQLite 真实 `time.String` 持久化格式尚未覆盖；跨 Store fixture 复用旧权限能力被正确拒绝；PG CTAS 保留 timestamp/int4，导致非法 timestamp/过大 revision 在造坏 fixture 阶段就失败。分别修复解析格式、真实重新绑定权限、仅放宽隔离损坏副本类型。随后双库单轮 **10.894s PASS**。
- vet/lint 曾发现旧 WIP 复制含 atomic/noCopy 的 `JobQueue`；改为真正 Close/Open consumer，不复制能力对象或关闭检查。最终 Windows vet **exit 0**，lint **exit 0 / 0 issues**。

固定 Go 1.26.7 的真实命令（DSN 只从 ignored 文件读入环境，不回显）：

```powershell
$env:PATH = (Join-Path $PWD '.tools/go/bin') + ';' + $env:PATH
$env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText('D:/Tokens-Test/Tokens-Test/.tools/test-postgres/dsn.txt').Trim()
go test ./internal/integrity/repository -run '^TestSnapshotReport' -count=3 -timeout=5m
go test ./internal/integrity/repository -run '^TestSnapshotReportInventory101RowsSameViewOwnedAndFormats$' -count=3 -timeout=3m
go vet ./internal/integrity/repository
.tools/golangci-lint/golangci-lint.exe run --allow-parallel-runners ./internal/integrity/repository/...
```

增强后的全部 `TestSnapshotReport` 双库三轮 **35.637s PASS**，terminal 58506 / exit 0；最后唯一后续改动是上述 Close/Open consumer，涉及的 101/102 项跨连接/分页/迟发故障测试再以双库三轮 **12.408s PASS**，terminal 91555 / exit 0。无 PostgreSQL skip。最大集合纯测试另有 **0.178s PASS**。General DB 独占时段已经交还 root；没有遗留本单元运行中的 DB 测试。不把这些 Windows 结果当成 Linux 原生、race 或完整备份恢复证据。

## 后续必须集成

完整 inventory 还要组合完整审计、迁移、Jobs/Attempts、所有保留规则/模板/安装包字节及历史根密钥闭包；在冻结视图对应的受控文件空间逐个核验实际报告文件、收齐同快照 DB 文件/dump；实现认证归档、授权发布/下载、隔离恢复和激活，再做干净 SQLite/PG 灾备演练。此单元不跳过上述任一项，也不更新正式审核结论。
