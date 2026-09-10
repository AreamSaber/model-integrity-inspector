# M6-05：现代／历史 ready 报告完整同快照清单

2026-09-10。新增仓储内部组合层；不是报告文件备份、恢复验证、下载授权、
恢复激活或 M6-05 整体验收。本单元不改变原现代报告 inventory 的拒绝语义、
历史迁移、正式审批、原需求或全局台账。

## 依据与独立范围

已核对原 PRD SYS-008、TECH SPEC 19.5/19.6、开发计划 M6-05/M6 Gate，
以及备份实施边界、manifest v3 历史分类、完整原行摘要与 SQL 适配器。
需求要求数据库与所有保留报告共同备份，不能仅保留今天能重新生成的报告。
foundation 的13列加 migration 14 的7个可空发布字段没有历史回填；真实
CreateReport → Claim → FreezeReportSource → render → PublishReport/Complete
路径的现代发布约束仍是另一种事实，不可由存在旧字段推测或补写。

仅新增 `snapshot_complete_report_inventory.go`、两个同前缀专属测试文件和本说明。
不修改 `snapshotReportInventory`、`snapshotReportVerifyRow`、旧测试或
`snapshotLegacyReportRow`。外层维护／快照／归档协调器接线由后续单元完成。

## 接口与分类

`snapshotCompleteReportInventory(ctx, tx)` 返回两个私有自有切片：

- `modern []snapshotReportEntry`：原7个发布字段全部非 NULL，逐行调用已有
  现代内核验证关联事实、schema/版本、原冻结 source、原 content/file hash
  和渲染字节长度。未知版本、坏 hash、非规范 source、错误身份等直接失败；
  **不能失败后退回 legacy**。这仍只是数据库／内核字节一致性证据，不是实际
  文件已存在、历史来源已认证、当前用户有下载权限或恢复后可启用的证明。
- `legacy []snapshotCompleteLegacyReportEntry`：任一发布字段为 NULL，调用
  同事务原行适配器对固定20列全部原值生成 `mii.legacy-report-row.v1` 承诺。
  返回原组织／Run／报告／修订身份、原行 SHA-256，明确
  `legacy_unverified` 与 `unmapped`。NULL 并不证明该行真实产生于旧版本；
  只说明不能进入现代校验路径，不能据此提升信任。

原始格式、schema、定位、声明 hash、正文、所有 NULL/空串/部分值与时间原
表示仍保留在数据库快照，摘要绑定它们；结果不携带原路径或正文。本层不做
JSON/Unicode/换行/时间规范化，不重签、不使用现代生成器重建历史内容。

这里没有任何文件读取。`unmapped` 是尚待处理的清单事实，绝不是忽略文件的
成功结果；不伪造 `missing`、`observed` 或空文件。后续协调器须使用受批准
布局与有界 no-follow 读取来判定真实文件状态，绑定实际字节/hash，处理所有
未映射项并在隔离恢复中逐项复核。manifest v3 允许记录这种状态不等于备份／
恢复整体成功，更不自动恢复历史文件的下载或执行／评分／激活资格。

## 事务、预算与失败边界

- 必须提供有 deadline 的未取消 context 和调用者持续独占的实际 `*sql.Tx`。
  用 `NewDB` 清除旧查询条件，不回到 Store pool，不开关事务，不读取权限，
  不筛当前活跃组织、用户、TTL 或当前报告版本。
- PostgreSQL 实际 READ ONLY + REPEATABLE READ/SERIALIZABLE；SQLite 调用者
  在 BeginTx 前已对专有连接验证物理只读，本层 query_only 只是补充。
- 全部且仅 `status='ready'` 报告，联合现代＋历史上限 65,533；SQL 有界初始
  count、100条 metadata keyset 分页、严格单调ID、最终同事务 count 闭合。
  非 ready 的原行仍属于数据库快照，但不是此文件候选清单。
- 入口检查当前固定20列原行 schema，即便当前没有 legacy 行，也不静默
  忽略未来新增列。原适配器无法表达的类型、非 UTF8 PG 等仍明确 unsupported；
  不是永久丢弃合法历史的授权，整体兼容性仍待后续协议处理。
- 现代 source 每次只读一个 ≤4 MiB 文档；历史所有 TEXT 沿用原适配器的
  64 KiB SQL 字节切片，不施加现代 JSON 限额、不累计所有正文。返回值只有
  有界元数据及摘要。数据库内部 detoast/编码操作不在 Go 传输内存保证内。
- Limited 接口的 `entryLimit` 约束两类之和；`legacyRowByteLimit` 是**每个原行**
  的 framing＋内容预算，不是总归档预算。最终数据库、报告、工件、配置和
  manifest 总字节／条目限制还必须由协调器统一约束。
- 任一现代／历史行失败、末页失败、末次 count SQL 失败、取消、真实 rollback
  都返回整个零候选，不能返回已验证前缀。成功返回不能阻止调用者随后自行
  结束事务，后续发布仍须遵守外层一致快照和归档成功条件。
- 返回两种私有结果的 fmt/slog 均固定脱敏，隐式 JSON/YAML 序列化拒绝；
  仅返回既有闭集错误，不包装 SQL、原 locator、正文或驱动错误文本。

## 实际验证记录

1. 生产编译 PASS 0.091s（`-run '^$'`，不是功能测试）。
2. 独立纯格式／JSON／YAML／slog 测试三轮 PASS 0.102s。
3. 初始4项专项真实 SQLite＋PostgreSQL PASS 7.956s。
4. 增加真实第二组织、限额／损坏及晚错后全专项双库 PASS 13.447s，
   session 93131 最终 exit 0。此前 vet exit 0；lint 报一次 QF1003
   （要求 tagged switch），随后等价改写，没有放宽校验。
5. 最终 `go test ./internal/integrity/repository -run '^TestSnapshotCompleteReportInventory' -count=3 -timeout=120s`
   真实 SQLite＋PostgreSQL 三轮 **40.134s PASS**，session 80350 最终 exit 0。
   General DSN 仅从 ignored 文件装入当前测试进程环境，未回显；不是缺环境跳过 PG。
   已明确释放独占 General 时段，无后台测试或 DB 命令留存，没有操作 Backup cluster。
6. 最终完整 repository `go vet` **exit 0**、`golangci-lint` **0 issues**；
   本轮没有提高超时、重试吞错、跳过失败案例或降低生产安全阈值。

覆盖说明：

- 3份现代 JSON/HTML/CSV 从真实创建／领取／冻结／渲染／发布／完成事务获得；
  98份明确的原13列历史种子组成101条，实际 metadata 页为100＋1。
  现代 fixture 使用真实仓储和报告内核的受控投影，不是完整 HTTP/Worker
  端到端或实际文件落盘测试。
- 旧 source 超过5 MiB、非 JSON，保留原声明非现代 hash 与负 file_size；
  逐条与独立原种子映射到纯摘要协议的结果比较，不用被测 inventory 作 oracle。
- 对7个发布字段分别置 NULL，完整原行承诺仍保留且不认证；字段齐全却损坏
  的现代报告即使前面已有合法历史项也整笔失败，未知 schema/格式不降级。
- 实际另一个 Store／物理连接插入新的原历史行并禁用组织：旧只读视图和
  既有结果不漂移；新视图包含新行及禁用组织，污染 Where/Limit 不影响结果。
  第二组织通过真实创建组织、目标、Run、Attempt 和分析发布后承载历史种子，
  禁用后仍与第一组织的现代报告一起收录。
- 联合条数上限1/2失败、精确3成功；原行预算1字节失败；NULL/非正ID、
  孤儿组织／Run／creator、required NULL、错误分析修订、重复ID均失败。
  损坏测试先验证真实 ready 触发器拒绝更新，再仅替换隔离测试表的 CTAS
  副本，保留 PG 原类型，未更改生产表或迁移。
- 7种晚错覆盖最后历史行第二段 source 的实际 SQL 错误／取消、第二页
  SQL 错误／取消、现代末项完成后的最终 count SQL 错误／取消／真实 rollback。
  错误必须为固定 unavailable 且整个结果为零；不把受控故障注入描述为自然
  数据库故障或磁盘故障测试。

本单元无 Git 写入。完整文件映射／复制、认证归档、隔离恢复和系统内入口、
CLI/API/Web、干净双库演练及正式统一审核仍未由此完成。

集成补记：root 已全文复核生产组合层及两个测试文件，未确认新增阻断项；纯格式
回归三轮 **0.104s PASS**，编译包含最终完整报告文件。实际双库执行证据为上述
独占测试的40.134s，不把纯格式测试冒充新增数据库回归。由root单独提交本单元。
