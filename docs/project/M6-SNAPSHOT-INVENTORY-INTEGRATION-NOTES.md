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
