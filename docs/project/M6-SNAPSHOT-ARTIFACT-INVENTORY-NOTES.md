# M6-05 同快照规则／模板原始字节清单

本单元接在 `8fe207a` 之后，属于 M6-05 后续实现，不是该提交 CI 的既有验证，也不代表完整备份、还原或最终 Gate 已完成。

## 需求与历史边界

- PRD 的 SYS-008、RUN-004 及 15.1 要求备份／恢复验证、运行版本冻结和历史可复现；TECH SPEC 19.4–19.6 要求数据库、报告、规则与配置一起备份，恢复后验证，不能从备份获得额外信任。
- 开发计划 M5-06 要求保留历史原版本；M6-05 是备份与还原闭环。这里的“可备份”不等于“能被今天的运行态解码器执行”。
- 完整检查了 foundation 中两个 bundle 表、后续 migrations、`bootstrap_bundles.go` 的初始化／新组织／启动协调写入路径，以及 manifest v2 身份约束。现有 migrations 没有 bundle 正文格式回填。
- 正常受控写入验证版本、精确 SHA-256、正文 JSON 和交叉版本绑定，正文上限 1 MiB；备份库存不能把这个当前写入／解析限制施加到既有 opaque 字节上。
- 规则表具有 `status`、`replay_metrics_json`、`created_by` 等字段；模板表只有 `sensitivity`，没有 `status`。本单元保留所有组织，包括 disabled；规则的 development、draft、retired 等状态及模板的 public/private 不参与筛选。原状态、敏感级别、时间及 replay 原列继续位于原数据库快照中，未重写，也未无界加载到 Go。
- opaque 测试行是当前基础表可以表达、具有合法身份／引用和真实内容 hash 的保留数据。这证明字节保留能力，不伪称已经找到某个历史版本曾产生这些特定字节。

## 接口与完整性

仅增加 `snapshot_artifact_inventory.go`、`snapshot_artifact_stream.go` 及对应测试，无 migration、生产写入、Git 提交、文件发布、任意路径或用户上传接口。

`Store.snapshotArtifactInventory(ctx, tx, sink)` 接受调用方持有的真实 `*sql.Tx` GORM 适配层、deadline 和私有 staging sink。它核验实际隔离／只读状态，用 `NewDB` 清除传入查询条件，不访问 Store pool，不新建或结束事务。SQLite 的物理只读打开仍须由外层在 BeginTx 前用原生连接核验，不能把 `query_only` 当成物理只读证明。

规则和模板分别按原 ID keyset 分页，每页 100 条。先用 `limit+1` 的 SQL count 拒绝超额，再核对每表最终消费行数；零／负／重复 ID 不会因分页被悄悄跳过。版本身份按 `(category, organization_id, version)` 唯一；不同组织可以同版本不同字节，规则／模板可以拥有相同数值 ID。清单保留原 category、组织 ID、行 ID、version、SHA-256、实际字节数。

ID、组织引用、规则原创建成员关系、NULL／SQLite 动态类型和字段 SQL 字节边界都先检查。版本最多 128 ASCII 字节，hash 必须原样为小写 64 位 SHA-256。任何一次 SQL、身份、长度、hash、回调或取消失败，整个结果是零值 inventory，不返回已完成前缀。

原始正文没有 JSON parse、canonicalize、运行态 decoder 或版本升级。SQLite 使用 BLOB 字节切片，PostgreSQL 使用 UTF-8 `bytea` 字节切片；每次 SQL 最多取 64 KiB，逐块增量 hash，复制后清除借用 buffer，最后额外读取一个字节验证 EOF。不累积源正文或导出正文。最终 inventory 只累积有上限的元数据。

生产本单元上限为 manifest 的 `MaxEntries-3` 和 `MaxFileBytes`，私有测试 limit 只能收紧；最终协调器仍须扣除数据库、报告、installed artifacts、manifest、config 和归档 framing 的公共预算。PostgreSQL 可能在服务器端 detoast／物化整个 TEXT，这不是数据库服务器 O(1) 内存或大容量性能认证。

## 借用复制能力的失败封闭

sink 接收一次性 `copy(io.Writer)`，必须在本次 sink 生命周期内完成一次复制；不能保存能力供之后调用，也不能把私有 staging 提前发布。

- 未消费、重复、并发重复、Writer 重入、错误被 sink 吞掉，均产生 sticky failure。
- Writer 短写、负数／过大的 n、错误、panic；sink 的错误／panic；迟发 fetch／EOF 错误或 hash 不符，均转成闭集错误，不泄漏原始 SQL、路径或错误 canary。
- sink 返回时若复制仍活跃，先封闭能力、清除 fetch 引用并取消子 context，然后 join 已开始的复制，最终失败。SQL／Writer／sink 外部调用期间不持有状态锁，重入不能死锁。
- 能力封闭后才启动的 goroutine 或保存的 copy 会返回 Closed，不做任何 SQL／Write；成功结果不会被晚调用修改。已通过状态检查的单次 SQL／Write 可能在封闭时仍在执行，join 保证其不会越过 Consume 返回边界，不声称可在 sink 返回瞬间硬抢占已放行的 I/O。
- 对任意不合作的 Go callback／Writer 无法强制抢占。join 只保证本方法正常返回时没有仍在运行的复制写入；不合作 Writer 可以使返回超过 deadline，不能宣称硬超时终止。
- 本方法不拥有发布 API，也不能回滚 sink 已写出的 staging 字节。可信 sink 必须遵循私有暂存协议，协调器只有在**全部库存、数据库导出、其他文件及事务终结**均成功后才能发布；发生任何失败须丢弃／隔离暂存。本单元没有实现该最终协调器或 staging 清理。

descriptor、inventory、借用 copy 和 stream 的 fmt/slog 固定私有摘要；JSON/YAML 序列化拒绝。没有从正文提取或捏造执行许可、发布状态、签名或信任级别。

## PostgreSQL 外层集成复验

主任务为七类 artifact 错误补齐 `postgresSnapshotError` 闭集映射。原映射纯回归
先以错误归一成 DATABASE_UNAVAILABLE 失败（0.089s），修后纯三轮 0.101s PASS。
新增真实 PG 外层用例覆盖七类错误、包装／吞错、sticky failure、禁止第二 consumer，
以及失败后服务端快照重新导入确实返回 42704；关闭后的实际借用 copy 不访问 Writer。
整个新旧 artifact 测试与映射三轮命令
`go test ./internal/integrity/repository -run '^(TestSnapshotArtifact|TestSnapshotInventoryErrorMapping)' -count=3 -timeout=5m`
在真实 SQLite／PostgreSQL 环境 **33.823s PASS**，会话 84853 终态退出 0。
主任务另行完整 repository vet 和 lint 退出 0（0 issues.）；之后仅澄清封闭／join 的注释，未改行为。
该结果不替代完整备份协调器或全产品验收。

## manifest 与暂未完成兼容性

manifest v2 的 rule/template 必须使用 organization scope、原组织与原行 ID；不为跨组织重写 version/hash，也不发明新 ID。归档 EntryID 是独立的全局名字空间，由最终协调器生成，不能拿历史版本直接当路径。

foundation 对 version 与正文只规定 TEXT，因而存在基础表可保留、当前 v2/v3 artifact 结构不能表达的情况：例如非 ASCII／超过 128 字节版本、空正文。这里返回 `SNAPSHOT_ARTIFACT_UNSUPPORTED`，不丢弃或升级数据。全备份 Goal 仍需后续兼容结构及隔离恢复路径，不能以此边界永久拒绝合法历史、或宣布全量备份完成。

NULL／错类型／非小写 64 位 hash 与真实字节 hash 不符目前返回 Invalid。foundation 也未给 hash 加格式约束；如果后续确认须保留任意旧 claimed-hash 表示，必须另存原声明与实际 observed hash，不能在此把原字段替换成今天的 hash 伪造一致性。

尚未完成：Run／estimate／baseline 等所有版本引用闭包、installed tokenizer/scoring 的真实载体、sealed audit、最终多文件协调器、恢复隔离和信任门禁、API／Worker／Web 完整闭环及最终审核。本单元不改变 M6-05 的整体未完成状态。

## 实测证据（2026-09-10）

使用固定 Go 1.26.7。PostgreSQL 是主任务授权的现有受管真实实例；仅从 ignored DSN 文件载入环境，不打印 DSN，不重启、重置或修改实例。`eachDatabase` 在隔离 SQLite 文件及 PostgreSQL schema 上运行，并清理测试数据。

1. 纯 copy 状态机首轮通过：`go test ./internal/integrity/repository -run '^TestSnapshotArtifactStream' -count=1`，0.098s，terminal 0。
2. 新 manifest 组合测试首轮失败：0.106s，原因是测试遗漏固定 `database-snapshot` / `config-template` EntryID 和空审计 anchor 的 canonicalization version。补正测试；未放松生产验证。
3. 首轮真实双库全部 artifact 测试通过：`-run '^TestSnapshotArtifact' -count=1`，5.368s，terminal 0。
4. 扩展后真实双库三轮通过：`-run '^TestSnapshotArtifact' -count=3`，16.734s，session 11724 / terminal 0。随后明确释放数据库时段，没有继续运行数据库测试。
5. 数据库覆盖包括：正常初始化／新组织真实 bundle seed；103 规则＋3 模板、100 条分页边界；disabled 组织、private 模板、retired opaque 历史；跨表相同 ID、跨组织相同版本不同字节；原事务与另一连接提交后的新视图；5,250,004 字节 opaque 历史正文；NULL、超长字段、SQLite 错类型、重复身份、版本精确 128 字节；迟发 hash 故障和真实事务 rollback 后的 SQL 故障；取消及 sink 吞错后零 inventory。
6. 随后纯层三轮通过：`-run '^TestSnapshotArtifact(Stream|InventoryRepresentation)' -count=3`，0.111s；包含 chunk ±1、EOF、重入／并发重复、async start/return、panic、封闭格式化和 v2 身份组合。
7. `go vet ./internal/integrity/repository` 通过。lint 首次因 shell PATH 未含固定 Go 无法加载；加入固定路径后发现测试 errorlint／nil-context 风格问题，已修正。copy 状态机测试明确检查固定 sentinel 本体（禁止携带私密上下文的包装错误），因此仅该测试文件用有说明的 errorlint 豁免保留精确等值断言。
8. 期间一次 lint 被其它同时编辑的 `legacy_report_row.go` 尚未完成的编译错误阻断；未擅自编辑该文件、未将该次计为通过。其它文件稳定后，最终纯层三轮再次通过 0.112s，`go vet` 通过，`golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...` 返回 `0 issues.` / terminal 0（ee0eae），`git diff --check` 返回 terminal 0。数据库释放后仅调整了测试断言风格、测试 lint 注释和本说明，未改变三轮双库验证的生产行为。

环境 `CGO_ENABLED=0`，没有运行 race detector；并发反例的普通测试通过不等于 race detector 通过。所有双库通过对应当时的实际生产源码；之后若仅改测试断言／文档，应明确区分，不虚称重复运行了数据库。
