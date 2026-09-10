# M1：普通队列终止更新的原子性补强

日期：2026-09-10。状态：限定修复已实现，真实 SQLite/PostgreSQL 三轮及静态验证通过；不代表完整备份协调已完成。

## 缺陷与最小修复

此缺陷在 M6 非执行域共享核心的只读复核中发现，但**在提取前的普通 `JobQueue.reconcile` 已经存在**，不是该提取新引入的回归。

普通 `Claim` 先执行 `q.reconcile`。后者按原数据库状态选择取消、耗尽、组织失效或缺失租约的候选；此前对选中的 Job 执行 terminal UPDATE 只检查 `Error`。数据库 `BEFORE UPDATE` 触发器可以忽略实际更新且不报 SQL error，代码仍继续预检失败投影和审计，导致 Job 仍 running、Precheck 已 failed，而 `Claim` 返回 nil error。

本单元仅修改 `job_queue.go` 的这一处 UPDATE：保留原 SQL/字段和错误传播，要求实际影响恰好 1 行；否则返回原有闭集 `ErrJobLeaseLost`，由外层真实 Claim 事务回滚。检查发生在任何预检域投影之前。

没有改变候选谓词、取消/耗尽优先级、retention disabled-organization 例外、最大批量、lease/heartbeat、重试、原 actor、旧错误码或任何 shared domain/execution/drain 核心。不修改迁移，不添加公共能力，不借故暂停或绕过队列。没有扩大成对所有 SQL 写入的泛化重构。

## 真实回归范围

新增专有 `job_queue_terminal_atomic_test.go`，复用原公开生产入口及测试 fixture，不替换普通 `Claim` 为测试专用事务：

1. 真实预检入库 → 实际 Claim → 同一 `WithLease` 中真实 Begin/Reserve 1；随后明确把原实际 Job 的 lease_until 调为已过、attempt_count 调为 max_attempts。这两项是受控故障状态，不冒称等待了自然 60 秒或真的重发多次请求。
2. 对原 Job terminal UPDATE 安装真实 SQLite `RAISE(IGNORE)` / PostgreSQL `RETURN NULL` 触发器。分别验证 exhausted failed、cancelled 优先于 exhaustion 且已有真实请求的两种情况。
3. 正常 Claim 必须零 lease + `ErrJobLeaseLost`；Job、Precheck、audit events、audit chain head、SQLite consumer lease 和 queue fairness 全部与失败前精确相同。
4. 只移除本测试的精确触发器/函数，再调用原 Claim，原 Job 正常 terminal，未增加 request_count/attempt_count，没有新 Claim 或新请求；Precheck 保持原 uncertain/cancel 优先级、原 started_at/snapshot 和其他所有非投影字段。Job/Precheck 完成时间相同。
5. 原 creator 已在数据库 disabled，外部传入 spoof actor/reason/IP；实际审计仍是原创建者、`target.precheck.reconcile`，只有一条且真实 `VerifyAllAudit` 通过。重复空 Claim 不重复写域事实。
6. 独立正例验证真正空队列仍是 nil,nil；合法未领取的 retention Job 取消后可正常终止，没有预检投影或额外审计。选中 Job 必须更新 1 行，不等于空候选/无域投影也必须有更新。

触发器仅使用代码内固定表/谓词，清理只删除本测试安装的具名对象。没有更改共享 fixture、生产超时或测试重试策略。

## 实际红绿与静态证据

- 红：`6c64ac` / session `81598` → `3055fd`，exit 1，repository 0.444s。`cancelled_false/sqlite` 与 `cancelled_true/sqlite` 均实际到达原普通 Claim，错误地返回 nil error。合法空队列/非预检无投影正例没有失败。
- 最小生产修复后：`be28af`，exit 0，2.041s；新 `TestJobQueueTerminalUpdate` 与原 `TestPrecheckReconcile` 全前缀三轮。
- 扩大旧队列/预检回归：`a17741` / session `63306` → `7504cb`，exit 0。全部 `^(TestJob|TestPrecheck)` 三轮 6.575s，随后 Windows repository `go vet` 和 golangci-lint 通过（0 issues）。
- `fd8c32`，exit 0：Linux/amd64、CGO=0 交叉 repository vet、限定 diff-check/gofmt 检查通过；不是 Linux 实际执行证据。

以上 agent 命令均仅在当前 shell 移除 `MII_TEST_POSTGRES_DSN`，未读取 DSN、未操作 General/Backup PostgreSQL 或服务。数据库 fixture 的未配置 PostgreSQL 分支不计为真实 PostgreSQL 通过。

root 全文复核生产 diff、新测试及说明后，独占 General、实际在进程环境载入受控 DSN（不输出），执行完整 `go test ./internal/integrity/repository -run '^(TestJob|TestPrecheck)' -count=3 -timeout=4m`，**真实 SQLite/PostgreSQL 三轮 39.835s PASS**（18160 第二命令；e3e485 终态 exit 0）。无 driver 子路径过滤，包含新两类真实 trigger 场景、所有原队列与预检嵌套组。前一次8a0ac4在其他并行文件缺 helper时编译终止，未进入DB；没有删除WIP或将该次记为通过。

此修复不是完整 M6 drain、备份或恢复验收；也不代表已经证明所有相邻队列写入均具备相同检查。
