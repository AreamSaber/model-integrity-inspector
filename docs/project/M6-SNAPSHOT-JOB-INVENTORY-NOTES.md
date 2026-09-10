# M6-05：同一只读快照的 Job / Attempt 清单

日期：2026-09-10。开发单元：`snapshot_job_inventory.go`。正式审核：待全部开发完成后的统一审核。

## 职责与边界

该私有投影只使用调用者已持有的真实 `database/sql.Tx`，不读取 `Store` 的池，不启动新事务，不 claim、reconcile、补写、取消或修复任务。必须有 deadline；PostgreSQL 必须是实际只读 repeatable-read/serializable。SQLite 的连续持有连接必须已由可信调用者验证原生物理只读标志，`query_only` 只是附加检查，不能替代物理只读证明。

所有 active/disabled 组织都进入候选，每页最多 100 个组织。Job 五状态 pending/running/completed/failed/cancelled，以及 Attempt 的 DISPATCHED/UNCERTAIN/COMPLETED/历史 PLANNED 和 legacy 计数完整保留。SQL 做标量关系校验及当前组织页的 GROUP BY；不把 Job、Attempt 逐行加载进 Go，不对合法历史任务总数另设任意上限。源数据的 payload、配置、正文、密钥、lease owner 和时间戳均不进入候选。

所有七种 Job 类型均按其保留的业务对象关系校验。历史已完成 retention batch 不能复用只接受 planned 的 enqueue 校验。明确使用 `response-retention:` 前缀的 Job 必须走 batch 身份校验，不能因为 object_id 恰好等于 organization_id 进入 legacy organization 分支；真正 batch 必须 object_id 不等于 organization_id，这与现有清理消费者相同。sample retry 会更换当前 `sample.job_id`；旧 Attempt 的 Job ID 保持原值，只验证它自己的类型、对象、组织和不超过该 Job 已有代次，不能强制等于当前 sample 指针。提供的当前指针仍必须绑定同组织、同对象和正确类型，包括没有任何合法关联 Job 的 precheck 指针。

组织、Job ID、Attempt ID 及同一 logical sample 的 attempt_no 先做 SQL 唯一性检查。组织重复 ID 恰好落在第 100 项时，单靠下一页 `id > after` 会漏掉重复行，因此必须在 keyset 分页之前拒绝。

running（包括 lease 已过期）或 DISPATCHED 导致 `SNAPSHOT_JOB_NOT_DRAINED`。任何源损坏、组织数量超限、取消或查询失败都返回零候选，不能泄露前面成功读取的组织。错误不携带 SQL、数据库诊断或源数据。候选及单组织记录禁止常规 JSON/YAML 序列化，格式化和结构化日志只显示固定占位符。

## 历史状态不是恢复授权

schema 7 添加 run_id/job_id（允许 NULL）和默认零的 lease_generation；schema 17 的合法历史数据中仍可能存在这些缺失身份，基础 schema 的 Attempt 状态默认 PLANNED。读取器不能把全部这类历史记录当作损坏，也不能为了通过新规则补写或删除历史。

候选区分 `verified_current` 和 `legacy_incomplete`。后者精确保留合法 legacy 计数，不表示这些缺失执行身份已经得到认证。提供的身份如果孤儿、跨组织、对象不符或代次冲突，仍必须失败；活动身份缺失不得成为可执行能力。成功返回仅证明这一次完整、一致的观察，不是完整备份、可恢复性、发布收据、Job 重放或恢复后启用授权。

后续完整协调器仍需保存原始 legacy 行、定义隔离恢复策略，完成其他清单、数据库导出、文件与密钥闭包、加密验证及显式启用。不得将这个单元写成 M6-05 已完成。

## 验证记录（持续更新）

- 首轮编译发现测试 fixture 类型名写为不存在的 `Target`，改为实际 `TargetRecord`。没有修改产品行为以迁就 fixture。
- 纯测试 `go test ./internal/integrity/repository -run '^TestSnapshotJobInventoryCountAndRepresentationGuards$' -count=3 -timeout=30s`：PASS，0.119s。覆盖整数边界、加法溢出、状态总和、legacy 子集及私有表示。
- `go vet ./internal/integrity/repository`：退出 0。
- `golangci-lint run --allow-parallel-runners ./internal/integrity/repository/...`：0 issues。
- root 授予独占共享 PostgreSQL 时段后，两个专门回归在 SQLite 和 PostgreSQL 都取得真实红：第 100 个组织 ID 跨页重复、明确 retention batch key 被误当成 legacy organization Job 均错误返回 nil；整次 1.969s。修复后同两项在实际双库通过。
- 首轮全套 11.128s 失败：测试角色没有 `target.precheck` 权限、测试误把 UNCERTAIN 恢复当成创建新 retry。修正为给测试角色授予该项权限，以及先通过真实 HTTP 429 outcome 创建 retry，再对 retry 的中断执行做 UNCERTAIN 恢复；没有绕过鉴权，没有更改生产“不重放可能已计费请求”的恢复语义。
- `go test ./internal/integrity/repository -run '^TestSnapshotJobInventory' -count=1 -v -timeout=5m`：实际双库 PASS，15.198s。覆盖真实 create/claim/reserve/complete/analyze 发布、7 类 Job、真实 429 retry 与 UNCERTAIN 恢复、schema17→21 合法历史、101 组织、65,537 个历史 Job、独立连接提交且旧视图不变、迟发 busy/取消/查询错误、孤儿/跨租户/NULL/SQLite 动态类型/重复行/超过 1 MiB 的 SQL 字段。
- `go test ./internal/integrity/repository -run '^TestSnapshotJobInventory' -count=3 -timeout=5m`：实际双库 PASS，48.138s，同一进程终态退出 0 后释放共享 PostgreSQL 时段。没有放宽 timeout、物理只读或工具链要求。最终 Windows `go vet` 退出 0，`golangci-lint` 0 issues；`GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 的交叉 vet/lint 同样退出 0、0 issues。此证据不等于原生 Linux/race 测试或完整备份恢复演练。
