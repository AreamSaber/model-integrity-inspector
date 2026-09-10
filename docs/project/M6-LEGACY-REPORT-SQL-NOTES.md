# M6 legacy 报告原行 SQL 摘要适配器

2026-09-10。新增 repository 私有 `snapshotLegacyReportRow`，把同一个真实只读事务内的原始报告行投影到已定义的 `mii.legacy-report-row.v1`。它只返回原身份、摘要协议版本及完整原行摘要，不返回路径、JSON、报告正文或 SQL 读取能力。不查询旧文件路径，不判断 modern/legacy 完整分类，不构造现代 source，不授予恢复激活权限。

## 事务与有限原始来源

入口必须提供 positive report ID、带 deadline 的 context、调用者持续独占的真实 `*sql.Tx` GORM 包装及 `1..MaxFileBytes` 的预算。预算含纯摘要协议全部 framing，最大沿用 1 TiB；内部期限不超过既有 24 小时流式上限并服从更早的调用者 deadline。拒绝 Store 连接池、nil/typed-nil 事务及污染配置。使用 NewDB 会话清除调用者旧 Where/Limit，但底层始终是同一个实际事务；不会另开池、开始/提交/回滚或关闭调用者事务。

SQLite 调用者必须在 BeginTx 之前通过真实专有连接的原生接口确认物理只读；适配器中的 `query_only` 只是补充检查，不把它当作只读文件打开模式的证据。PostgreSQL 检查真实事务 READ ONLY 和 REPEATABLE READ/SERIALIZABLE。成功返回前还会在原事务上执行最终身份/外键查询并检查 context，迟发回滚不允许留下可用的部分 descriptor。

有限来源严格是 foundation 的13列与 migration 14 的7列，顺序/必需性/整数编码由纯协议固定：

1. `id, organization_id, run_id, analysis_revision, format, schema_version, revision, content_hash, storage_path, status, error_code, created_at, completed_at`。
2. `created_by, job_id, source_json, source_hash, file_hash, file_size, frozen_at`。

普通原始报告表必须恰有20列。PostgreSQL 在读取前确认每列原生 `pg_catalog` 类型（bigint/integer/text/timestamp without time zone），拒绝 view、domain 及 date/text/timestamptz 隐式转换。SQLite 对实际行的每列先检查原始 `typeof`；整数必须 integer，TEXT 必须 text，时间必须 text。必需列 NULL、坏类型、缺行、重复身份、非法标量或预算异常全部失败，不尝试修复原行。

单次元数据查询只投影固定 ordinal、闭集状态、合法整数及原字节长度，最多21行以检测重复身份；不会把坏类型的大对象或原 TEXT 读入 Go 再验证。所有20列及预算先验证后才启动载荷流。

外键闭集检查组织存在、Run 同组织、分析 revision 对应同组织同 Run 的保留结果、可空 creator 对应全局 user、可空 job 对应同组织 job。它不要求组织启用、当前权限、结果可公开或 job 属于现行报告类型；这些不是历史事实保留资格。真实外键/身份损坏返回零 descriptor，不能把其他组织的行拼到本行摘要。这里的存在性检查不意味着报告 source、签名或业务真实性通过验证。

## 精确原值投影

- SQLite 的 TEXT 和三个 timestamp 都先确认原存储类型，再直接 SQL `CAST(... AS BLOB)` 获取字节。没有 `time.Time`、时间解析、格式化、UTF-8 修补、路径标准化或 JSON 解码。相同壁钟但不同 offset、纳秒末位、空格/T 拼写、空 TEXT、原 NUL/非法 UTF-8 都独立绑定。非 TEXT 的 SQLite timestamp 明确 unsupported；原数据库仍需要保留，不能偷偷转为当前格式。
- PostgreSQL timestamp 必须是实际 `timestamp without time zone`，以 `pg_catalog.timestamp_send` 返回原生8字节，独立于 DateStyle/时区或驱动文本解析；包含 epoch 前负微秒及 infinity 原值。TEXT 使用 `pg_catalog.convert_to(..., 'UTF8')`，且入口明确要求 server_encoding=UTF8，故当前已验证路径不进行字符编码转写。
- **非 UTF8 PostgreSQL 尚未实测，当前适配器明确 unsupported，不表示未来合法历史的永久兼容范围。** 更一般原 TEXT 编码支持需要先定义可复核的真实编码来源、摘要协议与导入/恢复证明，不能在本轮隐式 normalize。数据库完整备份及未知历史形态的后续保留策略仍由协调器负责。
- NULL 与存在的空 TEXT 分开编码。旧13列报告的新增7列保持真实 NULL；部分字段已有值也原样绑定。任意不符合现代 schema 的历史 JSON/hash/status、负 file_size 不在这里重写或提升信任。

每个载荷由只借用本事务的私有同步 Reader 消费，单次 SQL byte slice 最多64 KiB；即使消费者提供2 MiB buffer 也不突破该大小。切片始终绑定同一原身份及预检字节长度；到达声明长度后还执行一次真实 SQL 空切片以证明 EOF 与行仍存在。短读至 EOF、额外字节、缺行、读错及最后一列的迟发错误都不返回摘要。读取过的临时载荷切片及时清零；Reader 在调用结束时清除事务/context 引用，不对外泄露。

此处保证 Go/SQL 传输边界的有限元数据与64 KiB切片，不宣称数据库引擎内部无完整 detoast、字符转换或临时分配。PG 单值受数据库原生大小限制；adapter 也拒绝越过 SQL bytea substring 的 int32 offset 范围。没有为原行另造4 MiB JSON解析上限，也不宣称已完成1 TiB生产容量验收。

错误只暴露本包固定 configuration/unavailable/invalid/unsupported/limit 值；不包装 SQL、私密源或 Reader 正文。descriptor 与 Reader 的 fmt/slog 固定脱敏，隐式 JSON/YAML 拒绝。调用者仍需遵守独占事务生命周期；函数不能阻止调用者在返回之后自行结束事务。

## 实测覆盖与边界

- 真实迁移表中只插入原始13列，SQL确认新增7列均 NULL；partial source/hash/creator/file_size 仍与独立原始种子映射到纯摘要的预期一致。
- 17个可独立更换的原值逐列变化并核对不同摘要；另外3个父身份列以实际外键/不可变约束拒绝及隔离损坏表中的跨组织/孤儿引用拒绝覆盖。纯协议测试另有完整20列逐列变化向量；不把损坏拒绝测试描述成20列均成功独立迁移。
- 隔离测试先确认真实 ready 不可变触发器拒绝更新，才在该测试自己的 SQLite 文件/PG schema 内创建保留原类型的 CTAS 损坏副本。覆盖 required NULL、重复ID、真实另一组织 job、孤儿 creator/Run/result、SQLite大BLOB伪整数、REAL整数、TEXT伪BLOB、非TEXT timestamp；全部在任何载荷切片之前失败。
- 同一真实RO视图中另一独立连接提交原行变化，旧摘要不漂移，新视图看到新摘要；poolless Store 成功证明未回到 Store pool，真实RO UPDATE失败，已结束事务返回零值。
- 超过5 MiB的 opaque source 不做JSON解码；SQLite测试包含NUL/非法UTF-8，PostgreSQL为合法UTF8但非JSON原文本。实际SQL slice计数与独立2 MiB消费者证明分块边界。
- 受控故障在第二段 source 或末列时间处触发实际 SQL错误、context取消、调用者真实rollback；另将实际SQL投影替换为短空片、超长片或缺行，验证截断/多余/缺失均零结果。这是明确的测试查询故障注入，不冒充数据库自然产生错误切片的证据。
- PostgreSQL真表的 date/text/timestamptz 时间列被预检拒绝；真实 timestamp_send 的 epoch+1µs、epoch−1µs、infinity 与独立固定8字节 oracle 相符。SQLite三个时间字段的 offset/纳秒/原拼写/任意原TEXT差异全部改变摘要。
- SQLite专项三轮 **6.288s PASS**。首次 PostgreSQL 专项 **10.268s PASS**。新增双库专项 `go test ./internal/integrity/repository -run '^TestSnapshotLegacyReportRow' -count=3 -timeout=120s` **41.574s PASS**；General DSN 已设置，不是缺环境跳过PG，仅适用指定方言的测试按其定义跳过另一方言。
- 最终 `golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...` **0 issues**；`go vet ./internal/integrity/repository` **exit 0**。开发中曾有 GORM Create(map) 添加测试用 `@id` 导致重插入 fixture 失败，现传入 clone 保留原种子；不将此 fixture 调整冒充生产安全缺陷红绿。

本轮仅原行事实适配器及测试/说明。旧布局的有界、不跟随路径访问，实际数据库文件快照与行 descriptor 的同视图协调，v3 inventory 分类/映射，完整包写入和恢复前逐项核验仍待上层接线。本适配器单独通过不等于 legacy 报告来源可信、可打开旧路径或可恢复激活。
