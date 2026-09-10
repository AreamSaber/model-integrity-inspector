# M6-05：报告与任务清单的 PostgreSQL 外层集成

日期：2026-09-10。正式审核：待完整开发后的统一审核。

同快照报告与 Job/Attempt 读取器新增六个闭集错误。PostgreSQL 外层原本把这些错误
归一为 DATABASE_UNAVAILABLE，丢失源数据损坏、限额、未排空和历史不兼容的分类。
纯层真实红测 0.105s 后，加入精确 sentinel 映射；不透传包装中的数据库或业务诊断。
取消优先级、清理不确定性优先级、sticky failure 和视图关闭规则保持不变。

新增实际 PostgreSQL 测试从真实读取器触发全部六种错误，而非仅向回调注入错误：
未初始化组织、超限组织、租约已过期但仍 running 的 Job、实际报告文件大小元数据
损坏、报告数量超限、合法历史报告缺少 source。每项同时验证消费者包装及吞错两条
路径，失败后第二次消费者不能运行、外层仍返回原闭集错误，且 PostgreSQL 服务端
重新导入已关闭快照明确返回 42704。所有失败均无部分候选。

根任务完整组合命令（固定 Go 1.26.7，真实 General PostgreSQL DSN 仅从私有文件装入环境）：

```text
go test ./internal/integrity/repository -run '^(TestSnapshot(Report|Job|Inventory|Migration|Audit)|TestPostgresSnapshot|TestAuditSnapshot)' -count=3 -timeout=5m
```

session 51154 实际终态退出 0，195.166s PASS；涵盖 SQLite/PostgreSQL 的报告、
任务、迁移、审计库存及 PostgreSQL 外层生命周期组合。此结果不等同完整全仓回归、
新远端 CI、实际文件归档或完整备份恢复演练。M6-05 仍进行中。

## 历史密钥与原报告行读取接线（2026-09-10）

新增 `SNAPSHOT_KEY_*` 和 `SNAPSHOT_LEGACY_REPORT_*` 的 invalid/limit/unsupported
六个闭集映射。纯映射真实红测 **0.089s FAIL** 后修复，三轮 **0.100s/0.098s PASS**。
实际 PostgreSQL 组合不是只注入 sentinel：密钥 envelope/列不一致、联合版本超限、
真实旧 gateway 签名，以及缺报告行、原行摘要预算超限、PG 原 timestamp 被替换为
TEXT 均经真实读取器失败；每项覆盖包装/吞错、禁止再用、零候选及服务端 42704。

最终 key 单元已修 envelope 合法空白/顺序过拒、空审计头过拒和 Unicode SimpleFold
别名，专项真实双库三轮 **64.732s PASS**；legacy SQL 专项双库三轮 **41.574s PASS**。
根任务针对最终文件重新运行：

```text
go test ./internal/integrity/repository -run '^(TestSnapshotInventory|TestSnapshotKeyInventory|TestSnapshotLegacyReportRow)' -count=3 -timeout=5m
go test ./internal/integrity/repository -run '^(Test.*Snapshot|Test.*Migration)' -count=1 -timeout=5m
```

真实 General PostgreSQL DSN 已设置。session **23589 / 135.530s** 与 **5348 /
125.375s** 均终态退出 0；第二条覆盖新旧快照与迁移组合，未放宽业务期限或跳过失败。
最终 repository vet/lint 退出 0、0 issues。此证据不覆盖之后新增完整报告库存或配置
载体，不等于完整备份/恢复、真实主密钥认证或最终 CI。General 已交完整报告库存
单元独占验证，根任务不并发运行数据库测试。

## 历史资源引用接线与最终读取边界（2026-09-10）

新增 Reference invalid/limit/unsupported 三类闭集映射。原纯映射回归真实失败
**0.102s**（被误转为 DATABASE_UNAVAILABLE），修后全部映射三轮 **0.125s PASS**。
真实 PostgreSQL 从原 Run manifest hash 损坏、五引用配四条预算、保持原字节 hash
一致的未知 generator 三种来源触发错误；原包装/吞错、禁止再次使用、零候选和
服务端 42704 快照失效断言全部复用。新引用及新旧外层完整三轮 session36051
**75.780s PASS**，设置真实 General DSN，未通过注入 sentinel 冒充来源错误。

根任务另在最后一条 Baseline 的原 result 正文 SELECT 成功后，执行实际 sql.Tx.Rollback。
先前仅在页读取后 rollback 的测试会被后续查询检出，未覆盖此边界；初版在 SQLite/PG
均仍返回成功。新回归真红 **0.745s**，每源末尾在原物理事务再次 COUNT 后同用例三轮
**1.957s PASS**。该终结检查不是调用方未来 Commit/归档发布的成功保证。

全部 Snapshot/Migration 组合单轮 session44821 **149.426s PASS**；该次编译先于之后的
Unicode model/旧 ordinal 兼容修正，后续最终组合证据须另记录，不追认。

另一独立复核指出旧 SQLite 样本 ordinal 可以是 int64，而原观察器强行套用了 int32
上限。实际 validateExecutionPlan 只要求本 probe 非负且唯一，SQLite INTEGER 支持
64位、PG原列INTEGER支持32位；移除人为上限，不改当前 manifest 连续 ordinal 绑定。
纯回归先红 **0.127s**，真实 CreateRun→原DB字段→库存观察使用 SQLite int64最大值和
PG int32最大值，三轮 **2.194s PASS**。仍分类 legacy_incomplete，没有补写或升级历史。

最终纳入模型512字节兼容、末尾rollback、旧ordinal及全部原引用/外层的组合：

```text
go test ./internal/integrity/repository -run '^(TestSnapshotArtifactReferences|TestSnapshotReferenceModelCompatibility|TestSnapshotInventory)' -count=3 -timeout=5m
```

真实 SQLite/General PostgreSQL，session2604 **83.168s PASS**、终态 exit 0。
完整 repository vet 无诊断；当前共享工作树 lint 的35项均属于后续尚未提交的
snapshot_result_references 两文件（34 unused、1 QF1001），没有将整体 lint 记为通过。
第一引用单元独立提交后仍须按该提交身份执行检查/新CI，后续 Result 单元不随之发布。
