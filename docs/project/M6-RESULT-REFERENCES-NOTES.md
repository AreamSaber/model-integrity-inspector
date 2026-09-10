# M6-05：保留结果的历史资源根引用观察

2026-09-10。此单元仅观察 `integrity_run_results` 历史原结果的资源引用，不是完整备份闭包、完整备份、恢复或上线批准。全局计划及 M6-05 状态不在本单元修改。

## 原始依据与真实来源

PRD SYS-008、RUN-004/15.1，TECH SPEC 18/19.5 及开发计划 M6-05 要求保留完整数据、规则和配置版本，并在干净环境验证恢复；不能仅归档当前 builtin。

- `analyzer/analyze.go` 的真实 `Document` 为 `mii.analysis.v1`。外层 `features/tokens/behavior/scores` 使用显式小写 JSON tag；`scoring.Result`、`tokenrisk.Result` 的身份字段没有 JSON tag，真实字段是 **PascalCase** `Version/RulesHash/TokenRulesHash/Series`，不能替换成猜测的 snake_case。
- `worker/analysis.go` 将真实分析文档 `json.Marshal`，上限 4 MiB。`repository/analysis_result.go` 是当前唯一结果写入路径，验证 org/run/manifest/评分版本及摘要，但没有要求参数哈希或 tokens 字段齐备。现有 `analysisPublicationFixture` 通过真实 `PublishRunAnalysis` 保存缺少这些字段的文档。因此，未提供且旧写入允许的字段明确计为 incomplete，不能因 `analysis_source_version=derived` 就将它们当损坏；提供而冲突、非法或 NULL 则拒绝。
- foundation migration 1 的结果主键是 `(organization_id, run_id, analysis_revision)`，revision 只要求正数，`is_published` 可以为 false。当前 writer 仅发布 revision 1，不代表历史库存可以只扫 revision 1。SQLite INTEGER 的真实 64 位正值不被人工裁成 PostgreSQL INTEGER 的 32 位范围。
- TECH SPEC 18 保留聚合结果；当前 `response_retention_cleanup.go` 清理 S2 正文/展示证据，不删除原结果。过期、未发布、旧修订和 disabled 组织都不能因线上读取政策而被丢弃。
- `run/result.go` 的在线 `decodePublished` 限制当前版本/参数、revision 1、published；它不是历史备份准入规则。本 observer 不调用它，不重跑分析器替代历史结果。

## 接口、引用角色与一致快照

私有入口 `Store.snapshotResultReferences(ctx, tx)` / `snapshotResultReferencesLimited` 必须使用调用者同一个实际物理只读 `*sql.Tx`，要求 deadline、正确 dialect，调用现有物理事务检查，并通过 GORM `NewDB` 清除误带查询条件。不回到 Store 的连接池，不开启/提交事务，不写数据库。

全结果行数 + SQL 重复复合键检查；按组织/Run/revision 三元组 keyset 每页 100 行；结尾同事务重新 COUNT。没有任意限制全部历史结果行数。distinct 引用集合上限只是本单元资源预算，不表示通过最终 manifest 全局记录数/总字节预算。

每条结果重新观察真实原 Run 及原 config/manifest 字节，复用已经完成的 Run 引用观察，而非当前默认版本。引用同时包含 organization、原 Run 四版本和以下独立角色：

| role | 原来源 | 边界 |
|---|---|---|
| scoring_parameters | scores.Version / RulesHash | 原参数哈希，不是规则包或归档文件哈希 |
| tokenrisk_parameters | tokens.Version / RulesHash | tokenrisk 算法，不是 tokenizer bundle |
| scoring_tokenrisk_binding | scores.TokenRulesHash | 已提供双方时必须与 tokens.RulesHash 一致 |
| feature_implementation | features.version | 仅原实现版本 |
| behavior_implementation | behavior.version 及样本 behavior.version | 已提供版本必须一致 |
| structure_implementation | features.samples[].structure.version | 可选未测量对象缺失不被伪造为零值 |
| template_member | features.samples[].template_id / template_version | 独立于模板包版本，保留原模板 container 版本和 hash |
| tokenizer_configuration | features.samples[].local.bundle_version / bundle_hash | 与原 Run manifest 的 tokenizer 资源绑定 |
| tokenizer_implementation | local.tokenizer_version / tokenizer_id，tokens.Series[].TokenizerVersion / TokenizerID | 与配置及 encoding 命名空间独立 |

当前 BPE 实现版本包含 `+`、`@`：`mii-bpe-v1+github.com/tiktoken-go/tokenizer@v0.8.1`。它不符合 execution bundle label，故 tokenizer metadata 单独采用原 `tokenrisk.normalize.identifier` 的 UTF-8、128-byte、无 NUL/CR/LF 规则。真实 `plateauAnalysis` 只对非 unavailable 的 countable 样本产生 Series，其身份必须非空；合法 unavailable/no-attempt 产生空 Series，而不是无身份 Series。真实 exact/heuristic/unavailable/no-attempt 回归覆盖这些不同情况。

## 原始样本与历史分类

已知 codec 中提供的 `features.samples[].sample_id` 和嵌套 behavior 样本 ID 必须在同一事务内对应真实同 org/run 的 logical sample 及唯一 probe，SQL 转移前先界定标量类型和长度；每批不超过 100 个原 ID。提供的模板成员必须同时对应原 manifest/Plan 和原 probe。不会以仅存在的外租户 ID 通过绑定。

`features/mapping.go` 把 SampleBinding.Ordinal 写入 `mii.analysis.v1`；`features/build.go` 要求它等于 execution_ordinal 及 manifest 全局顺序。故已知 codec 的 ordinal 按全局 execution_ordinal 校验。完整现代来源另外要求物理 sample.ordinal 同值。合法旧 writer 的 probe-local ordinal 可以不同；legacy 来源不猜该局部值是全局序号，其原值进入样本来源摘要，结果仍 incomplete。

未提供的元数据不补默认值；unknown/缺失 schema 的 JSON 对象保留原字节摘要和 unknown/incomplete 精确计数，不猜其中类似当前字段名的语义，也不自动准入。已知 schema 的语法/键/元数据冲突不能通过 legacy 降级。继承的未知原 Run manifest codec 返回 Unsupported，不能借当前签名/实现填补历史。

原数据仍在数据库快照中；此私有 observer 只返回去重排序的元数据、精确 rows/published/unpublished/incomplete/unknown 计数及摘要，不保存正文。结果及引用禁止 JSON/YAML 暴露，fmt/slog 封闭。原字节哈希、原 SQL 复合键、原 Run 字节、原样本/probe/顺序标量和分类采用固定 domain + 带长度帧的结构编码计算摘要，不用不定长字符串直接拼接。字节 SHA 是本视图观察证据，不冒充外部 MAC 或参数真实性证明。

JSON 在转成 map 前做完整 UTF-8、EOF、重复及 Unicode SimpleFold 别名检查；depth 64、200000 值 token、单对象最多 8192 键、键 128 byte，原结果最多 4 MiB；样本数组观察上限 1000，与历史 repository writer 的样本预算兼容，不施加当前 feature Builder 的 150 样本准入条件。每项已知身份有独立有限长度。所有失败（含取消、晚页损坏和晚 SQL 错误）返回零候选。

## 回归记录

- 首次真实 analyzer exact 路径产生红例：把 BPE 实现 ID 按 execution label 检查导致 Invalid；按真实 tokenizer metadata 协议修正后，纯组 3 轮 0.360s PASS。
- 首次真实 SQLite + PostgreSQL 专项 1 轮：4.178s PASS，含 102 修订分页、101 unpublished、disabled、另一连接提交但同视图不漂移、真实 publication writer 缺字段、跨结果 distinct union 限制、最后样本读取后的真实 rollback。
- 新增 101 物理样本、离线 NULL/重复/跨租户、schema17 原结果迁移与 native revision、晚页取消/损坏、SQL 预界，以及真实 DeriveAttempt → MAC Seal → 删除所有 S2 Evidence → BuildDerived → analyzer 回归。曾被并行 privatefile 单元缺少原生实现阻断编译；该完整实现落地后才实际执行，不将这些编译失败计为通过。
- 扩展首轮 13.335s FAIL：仅 legacy ordinal 正向夹具使用 `map[string]any` 解码导致大整数 target ID 被 float64 舍入。已改为真实 typed `executionSnapshot`，仅删除 manifest，不改写大整数；没有降低生产校验。
- 扩展完整双库 1 轮：session `11062`，14.979s，terminal exit 0。
- **最终完整双库 3 轮**：`MII_TEST_POSTGRES_DSN` 指向 General 独立测试实例，`go test ./internal/integrity/repository -run '^TestSnapshotResultReferences' -count=3 -timeout=5m`；session `23410`，**43.655s PASS，terminal exit 0**。使用当前完整 schema22（也验证 schema17 原历史写入后实际迁移）；没有跳过 PostgreSQL、扩展原 30 秒只读期限或 5 分钟整体期限。终态后明确释放 General，没有后台 DB 测试，未操作 Backup。
- Windows repository `go vet` terminal 0；Linux/amd64 cross `go vet` terminal 0。
- root 完整复核本单元后，将 Invalid/Limit/Unsupported 三类错误接入 PostgreSQL 快照外层。闭集映射回归先实际失败 **0.098s**，修复后实际原行损坏、限制、未知格式均验证错误包装、吞错后 sticky 失败、第二 consumer 不执行及导出快照关闭后服务端拒绝重新导入。`go test ./internal/integrity/repository -run '^(TestSnapshotResultReferences|TestSnapshotInventory)' -count=3 -timeout=5m` 真实双库及新旧 PG 外层组合 **106.165s PASS，session62095 terminal0**。
- Windows 与 Linux/amd64 cross repository `golangci-lint run --allow-parallel-runners ./internal/integrity/repository` 均 `0 issues`、terminal 0；本单元 Go 文件 gofmt 完成。期间仅他人新 `backup_completion.go` 的 gofmt 暂挡全包 lint，由该文件所有者修复后重验通过。

其中常规结构 fixture 并不声称通过完整 Worker 流量。另有独立真实 compiler/features/analyzer fixture 验证合法原输出，以及真实 `PublishRunAnalysis` writer 验证原先允许的缺元数据文档。生产文件没有上层 generator/secret/analyzer 依赖、没有复制 MAC 算法、没有 Git 或全局计划写入。

## 明确未完成边界

此单元只观察结果历史资源根，不能证明原参数内容已归档、原参数确实被使用或重算等价；原 publisher 对 hash 字段未提供外部认证。仍需 rules/findings/derived/projection 及其他依赖闭包、历史 installed 资源映射、统一 manifest 预算、数据库/资源单载体归档、密钥与恢复准入、原子激活/回滚及真正恢复演练。未知 codec 和 incomplete 记录保留，不被升级为现代可运行或发布授权。M6-05、SYS-008 和整个开发 Goal 不能据此结束。
