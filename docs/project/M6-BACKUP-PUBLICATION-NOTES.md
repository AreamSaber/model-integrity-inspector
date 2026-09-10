# M6-05：私有归档构造、发布与最终完成

## 交付范围与尚未完成的业务边界

本单元新增 app 私有 `publishBackupArchive`，真实连接 `BackupWorkspace → canonical manifest → BackupSealer → privatefile.WriteNew → finishBackupArchive`。同时新增通用、预算、生命周期、Windows/Linux/unsupported 专属测试；根任务独占新增 `backup_publication_database_test.go` 的真实双库授权/提交/回滚验证。没有修改已有 privatefile、manifest、AEAD、配置、仓储接口或已冻结的 completion 单元。

对照 SYS-008、TECH SPEC 19.5 和 `M6-BACKUP-IMPLEMENTATION-NOTES.md`，这只是**受信任 capture 与归档发布之间的实际内部桥接**，不是完整备份/恢复交付。它既不调用 HTTP，也不向 capture 暴露任意 SQL、目的路径或目录扫描能力。实际同快照数据库导出、全量历史库存与引用闭包、现代/历史文件来源观察、部署资源及配置采集仍由后续真实协调器负责。测试中的数据库/资源/config payload、对应 manifest 迁移和库存内容明确为合成 fixture，不能因真实完成了加密与 DB 提交就声称备份了整个应用数据库。

M6-05 仍需完成系统内触发/状态/授权下载、真实完整 capture、隔离恢复校验与恢复演练。此单元未改变审核状态，也未将未知 legacy 文件布局视为可永久忽略的成功条件。

## API、所有权与严格顺序

私有 API 输入已有真实 `MaintenanceLease`、可信私有父目录、backup-only sealer/opener、显式累计限制及同步 capture。capture 只拿到受控 workspace，返回 `Manifest` 与非 manifest `EntryID → BackupObject` 精确映射。该结构封闭格式化、JSON/YAML 序列化，不是 HTTP DTO。

capture 返回即转移 manifest/map 的所有权，禁止保留并并发修改、启动脱离上下文的工作，或吞掉外部来源失败。生产函数不从看似有效的 manifest 猜测来源真实性，不把任意 object.Info 当作 DB 授权。workspace 只存最终 payload；数据库 staging 等中间对象应在自身受控生命周期完成并清理，不能把额外暂存文件隐藏在归档工作区中。

执行顺序：

1. 检查上下文、目录、能力、限额；创建一个整个调用共同继承的 deadline，实际 `lease.Observe` 验证当前授权。生成内部随机 32 字节、64 位小写 hex ObjectID，不采用调用者文件名或备份 ID 派生路径。
2. 实际 `WriteNew` 的受控 producer 内嵌实际 `WithBackupWorkspace`。capture 所有对象经真实 Put 完整写入、Sync、原生身份校验和 Close 后，才可取得 opaque object。
3. 校验 manifest 的 BackupID/StartedAt 精确绑定实际 lease；Encode 后 Decode 为独立 owned 列表，并用 Entries 派生完整确定顺序。非 manifest 映射必须与计划精确相等。各 object 的原 Size/SHA256 必须精确匹配 manifest，不能多、少、截断或改写。
4. 协调器自行 Put canonical `backup-manifest`，拒绝 capture 冒充提供该条目。每个真实 object 经本 workspace 的 Read 重新检查原身份/完整 EOF/hash/大小，使用一份 64 KiB copy buffer 向真实 Seal 的对应 entry 输出。另一个仍活着的 workspace 中即使同大小/hash 的 object 也不能借用当前所有权。
5. Seal 必须完成全部条目和 AEAD 最终帧，收据版本、entry 数、实际重复输出的明文总数与原 manifest key-version 集合一致。
6. **先等待 WithBackupWorkspace 最终失效、取消/等待活跃 I/O、身份检查、关闭与清理成功**，再比较它的 unique-object 数量/字节收据。只要存在未映射对象（包括空对象）、晚错误、清理/关闭失败，WriteNew producer 就失败，密文不能被发布。
7. 只有真实 WriteNew 整体返回 nil，且 Published、CiphertextBytes/SHA256 与原 Seal 一致、共同上下文未取消，才调用既有 finish。finish 重新原生 Read、AEAD Open、manifest VerifyStream，核对原写入/加密收据，再由真实完成事务最终鉴权和提交。

成功完成事务之后没有新的文件清理、校验或其他可能失败的步骤，因此返回的是最终提交结果。任何此前失败均返回零完成收据，不自动 Abort、重新 capture、重试提交或释放冻结门。已经私有发布但 finish/最终 DB 失败的密文保留为未完成 orphan，不能被当作授权可下载备份，也不会因失败被删除或重写。

## 两种累计字节预算不能混淆

- `MaxWorkspaceBytes`：每个 unique opaque object 的实际内容仅计一次，加协调器新建的 canonical manifest 一次。
- `MaxPlaintextBytes`：每个实际归档 entry 输出均累计，包括同一 object 供两个合法 entry 复用时的两次输出，以及 manifest 本身。
- `MaxArchiveBytes`：独立限制最终私有密文，包括头、各 entry/chunk 和最终认证 framing。
- `MaxEntries`：限制完整归档条目（含 manifest）和工作区对象上限；workspace 最终实际 unique-object 数必须与映射推导结果相同。
- `Timeout`：所有子层从同一父 context 派生，后续 Seal/Read/finish 不重新获得一个独立更长的总预算。

多个合法 EntryID 可以复用一个原 object；没有错误地要求 object 身份唯一。归档 ID 仍必须唯一，manifest 仍逐条完整校验，不能因 dedup 丢失条目。真实零字节 legacy observed-file 通过显式 AllowEmpty Put 保存 empty SHA256；空对象计入数量，即使它的逻辑字节为零。既不将 missing 虚构为空文件，也不通过省略 empty entry 来节约计数。

workspace+ciphertext 同时存在的逻辑内容上界是两项预算之和，**不是磁盘空闲空间预约、文件系统 cluster/metadata 的物理占用上界或已测容量保证**。中间数据库 staging、已保留的其他 orphan 和恢复临时空间不包含在该和内；完整协调器仍须设置整体预算与空间策略。单个 manifest 有内核 16 MiB 上限；capture 自身如何获取或暂存来源正文不是该桥接的流式证明。

## 实际回归与反例

全部 fixture 都真实执行 prepare/迁移、Initialize、活会话写入、BeginBackupMaintenance，然后使用原生文件与实际加密，成功后真实 ReadBackupCompletion 和完整审计校验；没有模拟完成收据或仅手工 INSERT ready。

- 默认成功：随机 ObjectID、七个实际条目、持久化收据相等；已关闭的 workspace/object 不能继续使用。
- 缺/未知/自供 manifest 映射、错误 hash/size/BackupID/StartedAt、零 object、已关闭与仍活跃的外部 workspace object 均拒绝。
- 多余非空/空 scratch、capture 返回错误/普通 panic/panic(nil)、取消，均无完成记录且无已发布密文。
- 共享对象正例按精确 unique workspace budget 成功，独立读取真实归档逐字节比较两份重复输出和 manifest；数据库合成 payload 大于两个 64 KiB 帧。workspace 少 1 byte、明文错误地只给 unique 总数、entry 少 1，均拒绝。
- v3 两个明确 synthetic、legacy_unverified、observed-empty 条目复用一个实际空 spool，真实输出两个 empty entry 并完整认证；不赋予旧报告下载/可信恢复授权。
- 实际成功 Seal 到 discard 取得精确 framing 长度，再把真实 publication 的密文预算设为少 1 byte，真实最后认证帧写入失败，整包不发布。没有用未知失败点的假 writer 冒称尾帧失败。
- 正在进行的真实 Read 与 Put 分别使用确定性 barrier，在 capture 返回后必须取消并等待 I/O 结束；所有测试早退路径也 cancel-and-join，不能让 goroutine 使用已 cleanup 的文件。
- 完整消费之前返回、晚用借出 reader/writer、吞掉真实写入上限错误、重入 Read 均由实际 workspace sticky-error 封闭；capture 返回 nil 不能清除失败。
- workspace 最终错误/取消/错计数/错字节，以及 WriteNew 成功发布后报告错误/取消/panic(nil)/错误 Published 或 hash 均返回零完成。**这些特定晚结果用每调用私有 dependency wrapper 在真实 native 调用成功之后注入，只证明 app 传播/发布顺序，不能虚称本测试真的触发了 native cleanup/Close 故障**；真正 native 故障覆盖属于已提交 privatefile 专项。无全局可变 hook，无公共 native 接口变更。
- 错误 opener 在真正密文发布后无法完成；原正确 opener 仍能认证保留的同一私有文件。错误 key 不触发删除。

根任务的专属双库用例额外覆盖实际成功完成、capture 前/期间/真实 WriteNew 后正常 RevokeSession、最终维护门 UPDATE 的真实 SQL 拒绝。该 SQL 位于完成 receipt/event/audit 之后，触发失败应整笔回滚、无 ready、原 gate/operation 保留且原文件可独立认证。显式移除唯一测试触发器后，相同文件及原 WriteNew 收据可 finish 成功，用于证明因果，不是生产自动重试。该系列不是「原生读回完成后精确并发撤权窗口」测试，也不是完整库快照采集证明。

## 原生夹具与真实红绿证据（2026-09-10，Go 1.26.7）

首个默认真实正例红：e662a7，app 0.418s，MI_BACKUP_PUBLICATION_FAILED。添加真实 WithBackupWorkspace 目录预检定位为 MI_PRIVATE_FILE_PERMISSIONS：e03e78，0.406s。Windows 默认 Temp 的祖先可有其他用户命名空间修改权限，与 workspace 较严格祖先策略不兼容；普通 completion 的最终私有目录检查不足以证明整条祖先链安全。

仅新增 publication 专属 Windows fixture：在当前 profile 下创建随机测试子目录，对该新目录设置 current-user + SYSTEM 受保护私有 DACL，固定原生目录身份和规范路径，并让真实 workspace 独立检查全部祖先。未修改现有 profile/Temp ACL 或生产拒绝规则。测试只清理自身精确随机目录中的既定归档文件，不递归删除未知子目录。Linux 复用既有 Statfs 实测本地类型/必要时经验证 tmpfs 的私有 fixture；未接受 overlay 或 skip 原生错误。

实际执行记录分别归属如下：

- fixture 修正后默认真实正例：ebd992，terminal 0，0.481s。
- 第一轮原五组实际 SQLite/文件专项：89ef24，terminal 0，5.617s。
- 新预算/生命周期补充期间，共享 root backup-drain 文件处于未完成编译阶段，ac8bfa/e5c5ec 构建失败，未运行任何测试；没有改动他人文件或用通过结果覆盖失败事实。共享实现齐全后 compile-only 7eca1e terminal 0，0.095s。
- **完整 `go test ./internal/app -run '^TestBackupPublication' -count=3`：session 14954，60db01 → 9fe2a0，terminal 0，42.762s。** 当前 shell 明确移除 PostgreSQL DSN；SQLite/纯文件分支真实运行，根任务 DB 文件内 PostgreSQL 分支本次未执行，不能算该 agent 双库结果。
- **Windows app vet 与 golangci-lint：b9422c，terminal 0，0 issues。**
- **Linux amd64 app 测试交叉编译及 vet：91ec13，terminal 0。** 不是 Linux 原生运行或 race。
- **`GODEBUG=panicnil=1` 下 capture/write panic(nil) 专项三轮：4316bc，terminal 0，1.688s。** 其他环境未据此扩充结论。
- 根任务实际执行其专属 DB 系列，报告 session 4786 terminal 0，12.558s，SQLite/PostgreSQL 全子树三轮，包含 DB 提交、真实撤权和最终 SQL 回滚/同归档恢复。此为根任务执行证据，不冒称由本 agent 独立重复执行。
- 根任务随后完整读取 production、全部测试及 native fixture，未发现确认阻断；只读复核本身不计额外实测。之后实际给 General DSN，执行全部 `TestBackupPublication` 前缀、无 driver 子树过滤三轮：**session 60214，terminal 0，48.692s**。包括本 agent SQLite/native 故障与预算组，以及根任务 DB-aware SQLite/PostgreSQL 组；不是每个纯文件反例都各跑了一次 PostgreSQL。

本单元新增代码不受此前 9765605 / CI 34439268496 覆盖；没有运行或声称完整 app 全包、Linux 原生或 race 通过。CI 及最终整体集成结果由根任务按新提交实际运行后记录。本 agent 没有 Git 写入，没有读取 DSN 或操作 PostgreSQL/Backup 服务；完成上述终态后无后台测试继续运行。

以上新增 production、六个 agent 专属测试文件及本文档现已停止编辑，供根任务最终集成；根任务的 database test 文件从未由本 agent 改动。
