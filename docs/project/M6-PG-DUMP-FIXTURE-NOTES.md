# M6 PostgreSQL dump fixture 清理诊断

状态：只读诊断完成，提出的单活 owned database 生命周期调整已交由 root 实现；本记录尚不包含调整后的真实通过证据。测试正文断言通过但数据库清理失败，仍是整个测试 **FAIL**，不能计为 PostgreSQL 备份集成通过或 M6 完成。

后续 root 实际验证（优先于以上诊断时状态）：单活数据库夹具已实现，三个原始实际顶层测试三轮 **16.690s PASS**（session70217），包括所有源/目标数据库清理。RoundTrip 每轮2.49–2.86s、ExactSchema1.92–2.32s、真实取消0.69–0.86s；所有原数据/哈希/迁移/审计/失败断言和10秒DROP期限保留，fsync与现存server配置不变。RoundTrip及取消已接真实会话协调器；后续控制连接恢复等修改仍须独立重验，不以此结果追认新代码。完整M6-05/系统备份恢复入口仍未完成。

## 已发生的真实失败

root 提供的原始运行结果：

- 第一轮三个 `TestPostgresDump` 顶层测试合计 `59.657s`，FAIL。RoundTrip 的真实 26 MiB dump/新库 restore/审计比对正文通过，但源/目标库各一次清理失败；ExactSchema 正文和三类错误反例通过，但两次清理失败。另一个真实锁等待取消测试的服务端会话清理失败是独立问题，不能用本 fixture 调整掩盖。
- 初次四个残留库经 root 独立核验后精确 DROP 成功，合计约 `1.68s`。这是 root 的清理结果，不是本诊断单元执行。
- 两个顶层测试原样三轮重跑合计 `68.011s`，仍 FAIL。每轮只剩 RoundTrip 的一次清理失败，ExactSchema 均通过。因此不能停留在“旧的大检查点尚未结束”这一初次解释。
- root 在清理连接上取得实际 backend PID，并通过另一个连接作有限只读观察。单轮 RoundTrip（session `92056`）`13.986s`，FAIL；唯一失败为目标库 DROP 的 10 秒 context 过期，观察结果 `waits=map[CheckpointDone:187]`。这次直接观测到的是检查点已经开始但尚未完成，不是连接占用或等待旧检查点开始。

早期外部 40 秒观察窗口为 `15:28:45.530–15:29:25.135 CST`，没有覆盖到 DROP，只看到空闲 checkpointer。该窗口不是清理无等待的证明；上面的内嵌 PID 观察才是本次直接证据。

## 本机日志与环境证据

日志来自受管本地实例的 `.tools/test-postgres/server.log`，该文件被 Git 忽略。下表保留当时日志行号，后续追加不会改变已有行号。

| 时间（2026-09-09 CST） | 类型与耗时 | 同步量 | 当时日志行号 |
| --- | --- | --- | --- |
| 15:16:17.255–15:20:13.122 | 较早 WAL checkpoint：write `182.862s`，sync `48.935s`，total `235.867s` | 32,390 个同步文件 | 6232、6252 |
| 15:25:16.530–15:25:27.093 | immediate force wait：write `0.071s`，sync `10.376s`，total `10.563s` | 1,284 buffers，413 个同步文件 | 6265（完成） |
| 15:25:38.788–15:25:49.159 | immediate force wait：write `0.045s`，sync `10.250s`，total `10.371s` | 1,284 buffers，468 个同步文件 | 6279（完成） |
| 15:26:01.536–15:26:11.840 | immediate force wait：write `0.052s`，sync `10.129s`，total `10.304s` | 1,284 buffers，452 个同步文件 | 6295（完成） |
| 15:29:49.215–15:29:59.516 | immediate force wait：write `0.056s`，sync `10.133s`，total `10.301s` | 1,284 buffers，387 个同步文件 | 6309（完成） |
| 15:34:49.208–15:34:59.348 | immediate force wait：write `0.064s`，sync `9.193s`，total `10.140s` | 1,284 buffers，382 个同步文件；平均每文件约 `25ms` | 6312、6314 |

对照：三轮 ExactSchema 对应检查点为 984 buffers、306 个同步文件，sync 分别 `6.213s`、`7.671s`、`7.996s`（6274、6288、6304 行）；各轮随后的第二个 DROP 检查点通常仅 1 buffer、2 个同步文件，total 约 `0.120–0.955s`。

本机受管实例仍为 `.tools/test-postgres/data`、loopback `15432`、控制库 `mii_test`。`scripts/test-postgres.ps1` 未设置性能放宽项；只读设置检查见 `fsync=on`、`synchronous_commit=on`、`checkpoint_timeout=300s`、`checkpoint_completion_target=0.9`，均为默认值。`postgresql.auto.conf` 未包含覆盖项。D 卷为 Healthy NTFS，读取时可用空间约 1.96 TB；这些证据不支持磁盘空间耗尽，也不能据此推断具体硬件、杀毒软件或驱动故障。

结论是：此实例上数百个文件同步的累计耗时本身贴近或超过 10 秒；“26 MiB 逻辑载荷”不是 DROP 的工作量边界。仅降低 checkpoint pacing 或等待旧 checkpoint 结束，不能消除新 DROP 自己触发的这些同步工作。

## 固定 PostgreSQL 18.6 源码依据

- `dropdb` 先检查其他 backend（1675 行），随后持久标记数据库无效（1721 行），过滤目标库同步请求（1747 行），再请求 `IMMEDIATE | FORCE | WAIT` 检查点（1753 行）。失败后允许再次 DROP；这不是仅 Windows 才有的分支。[dbcommands.c](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/commands/dbcommands.c#L1675)
- `datconnlimit=-2` 明确定义为删除中途的无效数据库，而不是普通无限连接值 `-1`。[pg_database.h，第 115 行](https://github.com/postgres/postgres/blob/REL_18_6/src/include/catalog/pg_database.h#L115)
- `ForgetDatabaseSyncRequests` 只按目标 `dbOid` 发送过滤请求；匹配函数也只排除同一 `dbOid`，并不清空其他数据库的待同步工作。[md.c，第 1483 行](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/storage/smgr/md.c#L1483)、[第 1843 行](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/storage/smgr/md.c#L1843)
- 检查点在 `fsync` 打开时逐项处理待同步文件；请求方等待检查点完成，对应 `CheckpointDone`。[sync.c，第 339 行](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/storage/sync/sync.c#L339)、[checkpointer.c，第 1034 行](https://github.com/postgres/postgres/blob/REL_18_6/src/backend/postmaster/checkpointer.c#L1034)

现有 fixture 用 LIFO cleanup：恢复目标库后，先关/删目标库，再关/删源库。目标库 DROP 会过滤自己的同步请求，但源库及其 migration/catalog 的待同步请求仍在，因而目标库清理可能承担这些全实例同步工作。这是基于上述源码与生命周期的可检验归因；未启用逐文件 DEBUG 日志，不能把全部 382 个文件的具体归属宣称为直接实测。

## 已选定的调整与验收边界

优先只调整 fixture 生命周期，保留 `fsync=on` 和每次 DROP 的原 10 秒期限：

1. 完成源库上所有断言与 dump：导出快照、真实晚提交、26 MiB 输出范围、文件 `Sync`、独立 SHA，以及源库晚提交行数 27/审计事件 2。把当前位于 restore 后的源库断言提前，不删除断言。
2. 同步结束源库访问，显式 Close，再精确 DROP 该次新建源库；只有 DROP 真正成功才标记 released。失败仍使测试失败，兜底 cleanup 后续成功也不能抹掉先前失败。
3. 之后才创建目标库、真实 pg_restore，并继续原有 migration ledger、26 MiB/26 行、每行 MD5 和捕获的 owned audit anchors 比对，最后关/删目标库。已关闭源库不影响磁盘 dump 文件与内存 owned inventory。
4. ExactSchema 的“exporter 结束后旧 snapshot token 必须失败”要在源库仍存在时验证，再删除源库并恢复目标库；不能等源库消失后靠连接失败伪造失效 token 反例。

这样减少同一实例内同时存活的两个新 fixture 数据库造成的额外同步工作，且不增加生产权限、不修改活 server 配置、不添加 `FORCE`、不关闭 fsync、不减少数据量，也不触及独立的真实取消断言。

仍需 root 用原测试期限进行单轮定位和完整定向三轮复核，记录业务断言与所有 cleanup 的最终结果、同步耗时及残留清单。底层存储不是硬实时系统，不能保证任何机器永远在 10 秒内完成；若仍受共享实例其他工作负载影响，应单独设计独占临时测试实例，而不是修改现存 `mii_test` 或用放宽期限/关闭错误检查隐藏失败。本记录不授权启动新实例。

## 只读残留快照（尚未由本单元删除）

2026-09-09 `15:46:35.018–15:46:35.019 CST`，通过只读 psql 会话、5 秒 statement timeout 查询取得以下精确清单。owner 均为 `mii_test_owner`，`datallowconn=true`，`datconnlimit=-2`，`pg_stat_activity` 会话计数均为 0；无匹配的 src 残留。此时 checkpointer 为 `Activity / CheckpointerMain`。

| 精确数据库名 | datconnlimit | 会话数 |
| --- | --- | --- |
| `mii_dump_dst_3667998956227126948` | -2 | 0 |
| `mii_dump_dst_49199359953047321` | -2 | 0 |
| `mii_dump_dst_527191828813469532` | -2 | 0 |
| `mii_dump_dst_7552707817674657031` | -2 | 0 |
| `mii_dump_dst_9028658416772803239` | -2 | 0 |

这是有时间点的诊断证据，不是以后删除数据库的实时条件或扩大目标集合的授权。root 必须另行确认这些身份确由本轮 fixture 新建，清理前再次核验状态；本单元没有执行 DROP、terminate、restart、配置修改或 Git 写操作，所有诊断连接均已退出。

后续清理已完成：root 在三轮通过后重新只读核验这5个精确身份，仍均为current owner、INVALID/-2、零会话；然后逐个使用原10秒statement_timeout执行精确DROP（无FORCE），2.291s exit0，独立SELECT该精确集合count=0。只移除已知合成测试残留，未更改业务源库、活server配置或扩大匹配集合；测试内容可由夹具重新生成。

## 后续组合失败与独立 cluster 复核

单活夹具的窄三轮16.690s通过后，完整audit/snapshot/dump组合三轮实际
161.907s FAIL：3次源库DROP仍在10秒期限耗尽，实查为CheckpointDone/Start。
General审计套件对同一cluster其他数据库产生的同步工作仍未被隔离。

root随后只在原不存在的固定 `.tools/test-postgres-backup` 建立新cluster，
15433 loopback，原General进程26484未重启/改配置；新实例实际设置为PG18.6、
fsync=on、synchronous_commit=on。fixture强制MII_TEST_PG_BACKUP_DSN，若General
亦配置则实查两端pg_control_system的system_identifier必须不同；改变URL
scheme指向相同cluster的负控拒绝且不创建测试库。

原完整选择、三轮、5分钟总上限重跑，session85274终态**108.814s PASS**，
全部正文/源销毁前断言、真实恢复、取消及cleanup均通过。Backup查回无fixture
数据库；旧General仍有 `mii_dump_src_4047502431173381134`，只读核对为
INVALID/-2、current owner、0会话。本轮未删除此旧残留，不将新实例零残留
冒充所有历史环境均已清理。独立cluster不隔离物理盘调度，故不承诺任何主机
负载下10秒的硬实时保证。详见M6-PG-BACKUP-TEST-ISOLATION-NOTES.md。
