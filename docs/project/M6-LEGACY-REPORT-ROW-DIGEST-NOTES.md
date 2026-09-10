# M6 legacy 报告原行摘要协议

2026-09-10。新增纯组件 `backupmanifest.DigestLegacyReportRow`，实现已命名的 `mii.legacy-report-row.v1`。此处只有固定原行表示的有界流式 SHA-256，没有 SQL 查询、旧报告路径读取、快照一致性获取、报告真实性判定或恢复激活。`legacy_unverified` 不因此获得任何新权限。

## 固定来源与编码

摘要前像从 ASCII `mii/legacy-report-row/v1` 加一个 NUL 开始，接数据库方言 byte（SQLite=1、PostgreSQL=2），再接列数 byte=20。随后按下列顺序编码全部字段，不依赖 struct 反射、任意 JSON/map、SQL 列排序或现行报告重新生成。

| 序号 | 列 | 类型 | SQL NULL |
| --- | --- | --- | --- |
| 1 | id | integer | 禁止 |
| 2 | organization_id | integer | 禁止 |
| 3 | run_id | integer | 禁止 |
| 4 | analysis_revision | integer | 禁止 |
| 5 | format | text | 禁止 |
| 6 | schema_version | text | 禁止 |
| 7 | revision | integer | 禁止 |
| 8 | content_hash | text | 允许 |
| 9 | storage_path | text | 允许 |
| 10 | status | text | 禁止 |
| 11 | error_code | text | 允许 |
| 12 | created_at | timestamp | 禁止 |
| 13 | completed_at | timestamp | 允许 |
| 14 | created_by | integer | 允许 |
| 15 | job_id | integer | 允许 |
| 16 | source_json | text | 允许 |
| 17 | source_hash | text | 允许 |
| 18 | file_hash | text | 允许 |
| 19 | file_size | integer | 允许 |
| 20 | frozen_at | timestamp | 允许 |

前13列来自 foundation，后7列来自 migration 14。每列前缀为 ordinal:u8、type:u8（integer=1/text=2/timestamp=3）、presence:u8（NULL=0/value=1）。NULL 后无载荷；禁止用空字符串、整数0或空时间值代替 NULL。

- integer：固定8字节大端、有符号二补码。三个 ID 为正；analysis/revision 对齐 manifest 的1..2147483647边界。nullable integer 不改写历史值，负 file_size 等原元数据仍进入摘要，但不表示该记录可作为现代报告。
- text：先写8字节大端无符号 byte length，再写精确原字节。无 UTF-8 修复、Unicode normalization、JSON解析、空白折叠、hash大小写转换、路径清理或业务枚举修正。长度是字节而非字符。存在的零长 TEXT 必须实际读到 EOF。
- timestamp：同样有长度前缀，但使用独立 type=3。表示规则由已绑定的数据库方言决定，详见下一节。

新增数据库列不能在此版本下悄悄加入或遗漏；必须重新定义相应原行协议及适配器。未知/不满足原值投影要求的数据仍保留在数据库快照中，不能通过此纯函数假称已验证或转换为现代记录。

## 时间原表示与方言

初始设计复核确认，只有年月日时分秒的壁钟编码会丢失 SQLite 原 TEXT 中的 offset/原拼写；该未发布设计已替换，不能将整个数据库文件 hash 当作省略原行字段的理由。

- SQLite：未来同快照适配器必须确认原存储类型为 TEXT，再以 SQL BLOB 字节读取；不能把已经过驱动解析的 `time.Time` 再格式化。原始 `+08:00` 与 `+07:00`、纳秒末位、空格与 `T`、空文本等均独立绑定。非 TEXT timestamp 存储形态必须显式 unsupported，不隐式转换。TEXT 的原字节忠实性同样适用于其他所有 text 列。
- PostgreSQL：未来适配器必须获取 `TIMESTAMP WITHOUT TIME ZONE` 的原生8字节 binary 值，即大端有符号的自2000-01-01起微秒数及 native infinity 特值。必须固定实际列类型和 native binary 投影，不受 DateStyle、客户端时区或本地时间转换影响。当前安装 pgx v5.10.0 的 TimestampCodec 源码已核对该 binary 表示，但本轮未运行 PostgreSQL。
- 纯函数只消费这些显式提供的 bytes，不解释时间、不证明字节来自 SQL；PostgreSQL present timestamp 长度必须为8。整份数据库仍需要独立文件 hash、真实一致快照及恢复核验。

## 流式与失败边界

调用者提供固定类型的20列结构；各 text/timestamp 分别提供 Present、Bytes、同步 Reader。先验证全部必需/nullable形态、方言、长度与整体预算，再读取任何 Reader。NULL 的值包装必须保持零值（无隐藏长度、数值或 Reader）。Reader 只借用一次，不关闭、不保存、不异步执行。

`LegacyReportRowLimits.MaxBytes` 包含域、方言、所有 framing、标量和全部载荷，只可收紧现有1 TiB `MaxFileBytes`；没有新增16 MiB原行限额。工作 buffer 为64 KiB，使用后清零。Timeout 必须为正且不超过现有24小时流式上限，并受调用者更早的 context deadline 约束。取消是协作式的，不宣称能够抢占任意阻塞 Reader/内核I/O。

每列准确读到实际 EOF，包括零长列和刚好达到声明长度后的额外读。截断、额外字节、读错、末列迟发错误、取消、panic、不推进或非法 n 全部失败，不返回前缀摘要；`errors.Join(io.EOF, realError)` 不能视为成功 EOF。只返回闭集 `ErrInvalid/ErrLimit/ErrCanceled/ErrRead/ErrMismatch`，不包装底层 SQL/Reader/panic 正文。原行及 text/integer/time 包装的 fmt/slog 固定脱敏，隐式 JSON/YAML 拒绝。

## 实际本地证据

- 独立字节 literal + PowerShell/.NET SHA-256 验证：SQLite前像312字节，`089f52b9dac1a1c3870d6fc2076b86efbc075950277128e23a953d35f74f8220`；PostgreSQL binary合成向量264字节，`c3ec6ca1bae3506164dcbabbbda3aa9974c9c57289b7aaf2c3de45ffcebdc1fd`。未用生产列编码器生成期望前像。
- 原20列逐列变化、全部11个 nullable 列的 NULL/empty或0差异、方言、时区offset、纳秒、原拼写和非法UTF-8/任意JSON原字节均覆盖。
- 真实流过25 MiB+17字节 synthetic TEXT，最大单次读65536；观测累计分配66464字节，并与独立 literal prefix/length/payload/suffix 哈希一致。另对完整1 TiB声明预算作预检边界测试，但故意在首个大源读取时失败，没有实际读取1 TiB，也不宣称生产容量验收。
- 新专项三轮实际 **0.234s PASS**。完成最终测试后当前工作树整个 `backupmanifest` 包三轮 **3.593s PASS，94.9%**；包含父任务v3代码，但这不是双数据库回归。
- `FuzzLegacyReportRowSourceBytes`：10.164s PASS，5/5 baseline，176042 executions，3 new interesting（共8）；单输入超过256 KiB明确跳过，大载荷另有上述确定性测试。fuzzer独立构建变长源列的字节前像作为oracle。
- `go vet ./internal/integrity/backupmanifest` 成功；最终 lint **0 issues**。开发中出现三个命名冲突及 exact-sentinel 断言的 lint提示，均已修复；不把 WIP 编译失败、lint修正或设计审阅意见冒充安全缺陷的实测红绿证据。

后续必须把摘要生成及验证接到同一个真实RO事务的原始20列读取、旧布局有界无跟随访问和可信协调器；目前尚未接线。v3 manifest结构/AEAD通过不等于这些原行事实已来自数据库，更不等于 legacy 报告可信或可激活。
