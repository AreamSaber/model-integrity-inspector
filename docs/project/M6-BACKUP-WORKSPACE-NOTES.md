# M6-05：私有、有限、可复读工作区单元

## 范围与状态

本单元是完整备份／隔离恢复协调器的 scratch/spool 能力，不是完整备份、数据库 ready、生产恢复验证或发布授权。实现依据已完整阅读的 `M6-BACKUP-IMPLEMENTATION-NOTES.md`、`privatefile/file.go`、Windows/Linux 原生文件策略及 SQLite staging 生命周期；未修改既有原生 helper、SQLite API、仓储、配置或业务协调器。

新增 `internal/integrity/privatefile/backup_workspace*.go`。调用者只取得不可构造有效身份的能力和显式 size/SHA-256；无文件路径、数据库 URI、目录导出、任意名称写入或任意路径删除接口。

## 接口与预算

`WithBackupWorkspace(ctx, trustedParent, BackupWorkspaceLimits, callback)` 创建内部随机私有子目录；callback 内可使用 `Put(BackupObjectLimits, producer)`、`BackupObject.Info()` 和可重复的 `Read(object, consumer)`。外层返回 `BackupWorkspaceReceipt{Objects, Bytes}`，且只有 callback、所有原生检查、最终关闭与精确清理全部成功才非零返回。零对象的成功工作区也允许；收据是否有效必须检查 error，不靠字段非零判断。

- 全局 `MaxBytes` 是所有对象实际逻辑内容字节上限，最大 1 TiB；允许零预算仅用于显式真实空对象。单对象也有 MaxBytes，实际写入同时受单对象剩余额度及全局剩余额度约束。不替换对象、不退还配额、不自动重试失败生产者。
- `MaxEntries` 必须显式为 1～65,536；空对象也占一个条目。对象名完全由内部随机生成，随机名称碰撞失败，不覆盖现存文件。
- `Timeout` 必须显式为正且不超过 24 小时，继承更早的调用上下文期限。所有对象共用一个期限。IO 采用既有 64 KiB 原生流边界；只保存有限条目元数据，不累积大正文。
- **逻辑 MaxBytes 不是物理磁盘预留**：不等于文件系统 allocation clusters、目录/ACL 元数据或空闲容量预约，也不覆盖其他独立 SQLite staging／最终密文输出文件的预算。协调器必须对这些并存资源另行计入总体磁盘、时间和容量控制。硬上限不是已实测容量承诺。
- 普通对象禁止空内容。只有 `AllowEmpty:true` 才可保存实际零字节文件，并产生 SHA256(empty)；不把 missing 文件变成空文件、不假造历史文件存在或信任等级。

## 生命周期与失败封闭

Put 必须完成 producer、有限写入、同步、原生身份/权限与实际大小检查、实际 Close 后才返回对象。Read 重新打开原始文件身份，要求消费完整大小、真实末尾 EOF、与 Put 相同的 SHA-256、前后大小/mtime/身份及最终 Close；不重新生成内容。每次复读独立校验，且不提升原内容的真实性。

工作区一次只允许一个 Put/Read。重入、并发操作、借用流重叠 IO、已有流在操作结束后继续使用、吞掉本能力的 IO/限制错误、panic（包括旧 `panicnil=1` 语义）均使当前工作区 sticky 失败。失败 Put 返回零对象，失败 Read 返回零观察，整体失败返回零工作区收据。

callback 结束先原子关闭能力，再取消并 join 未完成操作，最后检查与清理。因此晚启动的工作不会与清理争用原生句柄。借用 IO 本身也有独立关闭/在途屏障；producer/consumer 返回时仍有在途 IO 会取消并 join，而不是把它当已完成。任意不合作的 callback 或阻塞内核调用不能被 Go 强制中断；本接口只供可信内部协调代码使用，不是任意插件执行沙箱。

callback、对象、reader/writer 能力在作用域结束后失效；返回之后的非法调用只能拒绝，不能撤回已经完成的历史调用收据。工作区不能识别调用者故意吞掉的外部来源／AEAD 错误，因此协调器仍必须传播外层来源校验失败，且不得在工作区成功返回前发布任何结果。已交给可信 consumer 的字节不能被追回。

默认值与指针的 fmt/slog 输出固定；工作区、对象、元数据、收据和借用流 JSON/YAML 序列化拒绝。底层 native/path/callback 错误只返回既有闭集错误码，不回显路径或正文。显式 Info 字段是内部业务所需的受保护观察，不应拼入日志。

## 原生边界和精确清理

Windows 复用 `sqliteWindowsStaging.openChain/inspectDirectories`、`sqliteWindowsOpen`、NTFS 文件身份、严格 ACL、canonical handle path 和原生 `removeTemp`；祖先及随机工作目录持续固定且拒绝其他 delete-open，文件写入和每次复读为独占打开。Linux 复用 `openLinuxSQLiteParent`、`linuxSQLiteEntry`、`createTemp/openInput` 和原生单链接/no-follow/owner/mode/文件系统策略，读取及删除均以固定 dirfd 和原始 inode 身份校验。未放宽 Windows 短名/reparse/DACL 或 Linux overlay/FUSE/NFS 拒绝策略；其他平台明确 unsupported。

目录枚举仅是有限的拒绝检查，每页至多 100 个名字，总数按已拥有条目闭合；不是可导出的来源清单。每次打开/最终检查会核对所有已拥有条目的身份、大小和已封存 mtime。按条目逐一检查意味着多次 Put/Read 的元数据成本可能呈 O(N²)；本单元没有宣称 65,536 条目规模的性能已验证。

清理逐一重新打开并验证自身原始对象身份，仅删除已证明是自己的对象；发现未知名称、硬链接、身份替换、权限变化或失败的最终 Close，会整体失败，不删除未知/替换文件来制造成功。可确认的自身文件仍会精确清理；不安全的私有残留会保留，不递归猜测清除。测试 fixture 的最终清理只操作本测试新建且身份验证的随机目录，不等同生产清理策略。

正常清理不等于安全擦除；进程崩溃、磁盘故障或身份变化可能留下私有 scratch。生产孤儿诊断/回收及故障协调仍需上层另行设计，不能对任意路径执行清理。Windows 原生目录 sync 不提供额外断电持久化证明；该工作区本来也不是持久发布物。

## 实际组合和反例

纯文件测试包括实际 Put/Read、三次相同字节/hash 复读、真正空文件、总量/条目/单对象上限、普通空对象拒绝、部分消费、真正已关闭文件造成的读写 IO 错误且被吞、producer/consumer/外层 panic、最后一块取消、最终对象 Close、最终 cleanup Close、晚出现未知文件、零对象取消及格式/日志封闭。

原生测试实际构造同大小/同身份/恢复原 mtime 的正文变更（确实进入流式 hash 检查后失败）、missing、硬链接、替换身份和未知文件；检查零候选和原文件保留。Windows 实际复读期间额外写打开和重命名均被原生策略拒绝。独立在途 writer/reader 屏障及 callback 提前结束的 Put 屏障验证取消和 join；不是等待任意重试通过。

真实 `WithSQLiteStaging` 运行 SQL 创建表和行、关闭原连接、只读重开执行 integrity/foreign-key 检查并证明写入被拒绝；其完整输出进入工作区，待 SQLite staging 自身最终清理成功后再两次复读同一字节/hash。该测试是实际 SQLite staging 输出，不声称已对生产活库执行在线备份。

外部包组合测试将同样真实 SQLite 输出及实际 empty 对象先入 spool，再由已观察字节构造有限测试 descriptor 并取得最终哈希，之后才调用真实 AEAD Seal；所有对象从工作区重新读取，最终密文通过 `privatefile.WriteNew` 在工作区关闭/清理成功后才发布。该 descriptor **不是产品 manifest schema，也不是完整数据库库存**，仅证明「先取得最终哈希、后复读加密」的依赖顺序。隔离 Open 将三个条目再次写入另一私有工作区；破坏最后密文字节时，三个明文 callback 已全部完成，Open/工作区仍零收据，后续复读/激活阶段不执行。另有「AEAD 已完成但工作区最后取消」反例，最终密文文件不发布。

25 MiB + 17 字节单对象实际写入并两次复读；独立 hash 逐次一致，三轮测试中每次整体 TotalAlloc 增量均在测试的 12 MiB 上限内，未把整份对象累积到内存。此为专项流式资源证据，不代表全量产品备份容量结论。

## 本地验证记录（2026-09-10，Windows，固定 Go 1.26.7）

- 初次真实 native 代码 compile-only：terminal 0，0.090s（93250d）；此前仅 common 文件短暂 WIP 导致 undefined constructor，已完整落真实实现，无占位。
- 第一批专项：0.273s（1946f7）。扩展原生测试真实失败（0541ba/3cf486）：Windows 目录固定句柄阻止 `os.Rename` 的父目录 delete-open，且 missing 后安全策略允许空私有残留。修正测试为保留原代的实际 link+unlink+新建替换，并停止错误要求安全失败必须无残留；未放宽生产策略，后续 0.309s（bfea2c）。
- 组合 fixture 初次编译错误为既有 assertEntries 参数类型误用（1cdb17）；修正为真实数量断言，0.421s（3d0778）。测试曾误引用旧 YAML import，触发 go.mod 提示，已改用项目现有 `go.yaml.in/yaml/v3`，未改 go.mod。
- **最终专项三轮：terminal 0，2.379s（40175d）**；同调用中 `GODEBUG=panicnil=1` 三类 nil-panic 三轮 terminal 0，0.146s。
- **最终 privatefile 全包单轮：terminal 0，1.625s；Windows vet 0，golangci-lint 0 issues（51e373）**。lint 最初环境 PATH 缺 Go、随后报告明确测试故障夹具路径的 G304；补固定工具链 PATH 及精确 scoped fixture 注释后通过，不忽略生产扫描。
- **Linux amd64 test 交叉编译与 vet：terminal 0（9dd2f2）**；较早误用 `-exec` 方式的 harness 失败（f3aa81）不算 Linux 实测，已改真正 `test -c`。没有在本机运行 Linux 二进制。
- **race 未运行**：本机命令因 CGO 未启用失败（fdf1c0），没有可用的本地 gcc/clang；未安装工具链、未把失败记为通过。实际 Linux/Windows CI/race 由根任务后续执行。
- 未使用 General/Backup PostgreSQL、未改服务、未读 DSN、未执行 Git 写入。完整备份/隔离恢复协调、真实产品 manifest/库存绑定、最终审计与 DB ready 状态仍由后续业务单元完成。

root 集成复核：完整阅读 common/native Windows/Linux 实现、原生清理依赖及全部新增测试；Windows `go test ./internal/integrity/privatefile -count=3 -timeout=5m` **4.676s PASS**。privatefile/repository Windows vet、lint（0 issues）和 Linux/amd64 cross vet 同次命令 **session19332 terminal0**。交叉静态验证不等于 Linux 原生或 race 执行；后者仍需本批提交对应的新 CI。

独立只读复核未发现可证实的生产阻断缺陷，未运行测试或数据库。两层取消/join、sticky failure、失败零输出和精确清理均逐路核对；Linux 仍为原策略的同 UID/root 可信边界，不能宣称 fstatat→unlinkat 是抵御同权限并发替换的原子 inode 条件删除。
