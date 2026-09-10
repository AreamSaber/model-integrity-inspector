# M6-05：归档读回与最终完成的组合验证

## 本单元范围

这是实际生产 adapter 与组合验证的集成交付，不是只有测试的提交：根任务实现 `internal/app/backup_completion.go` 中的 `finishBackupArchive`，并新增 `backup_completion_versions_test.go`；本 agent 新增其余五个专属测试文件（通用流程、数据库故障、Windows/Linux/unsupported fixture）及本文档。agent 没有改根任务生产实现、仓储、privatefile、AEAD、manifest 或已冻结的工作区单元。完整阅读并对照 app/repository 完成接口、维护授权/最终事务、真实文件、secret backup 和 backupmanifest Encode/Decode/Entries/VerifyStream 契约后实施。

独立复核结论为只读检查未发现阻断；该独立复核没有运行测试，不能把复核结论计为额外实测通过或完整备份证明。实际执行证据按本文记录的命令、终态和执行归属分别列明。

验证的是以下实际调用组合，而非模拟完成回执：

`prepare → Initialize → CreateSessionIfPasswordCurrent → BeginBackupMaintenance → Seal + WriteNew → finishBackupArchive(Read → Open → VerifyStream → CompleteBackup) → ReadBackupCompletion`

prepare 使用真实应用初始化和迁移；SQLite 采用独立测试文件，PostgreSQL 分支为测试专属新 schema。初始化管理员和活会话均经真实仓储写入及审计，维护操作的 BackupID/StartedAt 来自实际已提交 Begin。为避免把单元测试说成登录安全证明，密码 hash 和调用者已验证凭据的输入是明确的合成 fixture；没有测试 HTTP 登录/Argon2id。

归档密文、目的专用密钥派生、加密 trailer、原生独占写、原生完整读及最终完成事务都是真实实现。**数据库/规则/模板/tokenizer/scoring/config 明文和对应 manifest 库存事实是明确合成内容**：实际运行 canonical manifest v1 编码和七个条目的字节/hash 校验，但没有采集生产数据库快照、完整引用闭包、实际恢复 SQL 或激活生产系统。本测试不声称已完成完整备份/恢复；manifest v2/v3 历史分类本单元没有新增实际完成组合证据，其专用内核测试属于其他单元。

## 成功与故障断言

成功流程要求 Begin 后不能读取完成记录；真正 Seal/WriteNew 后经 finish 完成，原 ArchiveSHA256、ArchiveBytes、ObjectID、七条 Entries、StartedAt 精确写入持久化完成收据。随后真实授权 ReadBackupCompletion 返回完全相同记录；维护门恢复 normal，完整审计链实际验证成功，原私有文件仍存在。

每份 fixture 写完后，测试额外独立执行真实 privatefile.Read + Open 并完整消费，要求返回的 AEAD 收据与最初 Seal 相同，原生读得的字节/hash 与 WriteNew 相同。因此错条目/缺条目/错正文反例并非只用了损坏密文：它们的 AEAD 本身有效，失败发生在完整 manifest 库存绑定。

物理/输入故障矩阵覆盖：

- 同 key-version label 的错误实际密钥；正确 AEAD 但错 entry ID、错 kind、缺 entry、同长度错正文、短正文。
- 最后密文字节被截断及额外尾字节。独立 Open 确认七个完整明文 callback 都已消费后，末尾认证/EOF 仍失败且无收据。adapter 的额外尾字节也可能由更外层真实文件大小上限提前拒绝；不把该提前拒绝虚称 adapter 已走到 AEAD EOF。
- 错 manifest 内容、错 BackupID、错 StartedAt；WriteNew 未 Published、写入大小/hash 不符、原 Seal 计数字段不符。
- 文件真实缺失，以及已取消上下文。

每个失败要求零 BackupCompletionReceipt、无 system_backup_receipts、无 complete maintenance event、无 system.maintenance.complete audit；原操作保持 active、门保持 backup_freeze，且不可授权读取为完成。存在的输入文件在调用前后实际比较所有密文字节、原生 SameFile 和 mtime；失败不能删除、重写、换代或 touch 原文件。missing 是测试主动移除自身已创建的文件，不把它补成空文件。

## 文件读回后的真实数据库失败

在已经独立证明 Seal/WriteNew 成功的归档上，分别对实际完成 receipt INSERT、complete event INSERT、complete audit INSERT、维护门 UPDATE 安装专属 SQL 拒绝触发器。adapter 只有完成其自身完整文件/AEAD/manifest/原回执检查后才会到达这些 SQL 写入，因此这些反例覆盖文件读回后的数据库拒绝与原子回滚。

SQLite 的 `RAISE(ABORT)` 是 SQLITE_CONSTRAINT_TRIGGER，依据现有 `store.go` 归一为 ErrConflict；PostgreSQL 的受控 P0001 exception 应归一为 ErrUnavailable。测试不放宽为任意错误，也不允许原始 canary/路径出现在错误文本。

拒绝后要求完成记录/event/audit 全部为零、门和原操作未被 Abort 或释放、已有完整审计链仍可验证、私有原密文保持逐字节不变。随后**仅显式移除同一个测试故障**，要求相同的原归档和 lease 正常完成且可持久授权读取，以证明失败确由触发器且整体回滚。此为受控回滚因果验证，不是生产自动重试、吞错或重新生成一份归档制造成功。

另有真实 `RevokeSession`（正常仓储 logout）后的完成拒绝，要求 ErrManagementSession、零完成记录和原文件保留。该撤销发生在 finish 之前；**没有声称覆盖「文件完整读回后、最终 DB 授权前，另一连接恰好撤权」的精确并发窗口**。本单元没有为测试添加生产 afterRead hook，也没有在持锁事务内通过伪造授权数据冒充正常并发撤权。仓储自己的自然会话/lease 到期与最终授权回归属于其他单元。

## 原生 fixture 与安全边界

Windows 只对本测试刚创建的 TempDir 读取 GetFinalPathNameByHandle 的真实规范名，重新打开比较卷和 FileIndex，拒绝 reparse/非目录/不支持的 canonical volume；设置该随机目录的 current-user + SYSTEM 私有继承 DACL。生产仍独立执行 NTFS、ACL、路径、单链接/no-follow 和原生字节校验，未接受短名作为产品输入，也未修改用户现有目录 ACL。

Linux 首先实际检查测试目录文件系统类型；仅在 overlay/其他未证明类型时选择经 Statfs 证实的 `/dev/shm` tmpfs，创建新的随机 owner-only 目录。没有放宽生产 overlay/FUSE/NFS 拒绝，也没有跳过原生失败；cleanup 只作用于本测试实际创建的精确随机目录。其他平台 fixture 明确不支持。

测试没有后台服务器/Worker、没有外网请求；General/Backup 实例不被重启或重置。原生夹具构造和生产 readback 均不回显密钥、DSN、正文或原生路径错误。

## 已获验证记录（2026-09-10，固定 Go 1.26.7）

- 初次编译因新测试 string 与 MaintenanceMode 直接比较失败（e5aacb），修正为显式模式字符串比较，未改生产。
- SQLite 真实成功流程：terminal 0，0.420s（e2ab26）。
- 第一轮 17 类物理/输入矩阵和成功流程：terminal 0，3.944s（session 32645 / 0c7e25）。
- 增加数据库拒绝后的真实失败：四个 SQLite trigger 用例因测试错误期待 ErrUnavailable 而红（9871b8，5.469s）；核对现有错误分类后改为精确 ErrConflict。没有调整超时、并发、生产错误分类或移除断言。
- **完整 SQLite 专项三轮：terminal 0，13.903s（session 16250 / 362bbe）**。运行时仅在当前 shell 移除 `MII_TEST_POSTGRES_DSN`；PostgreSQL 分支未执行，不作为双库通过。
- **Windows app vet 与 golangci-lint：terminal 0，0 issues（a4ea4f）**。
- **Linux amd64 app 测试交叉编译与 vet：terminal 0（a7197f）**；仅 cross-compile/static，不是 Linux 原生运行或 race 成功证据。
- 测试源码现已冻结供根任务复核；无 Git 写入。PostgreSQL 专项代码及实际 SQL trigger 已编写，等待 General 明确移交后运行，并在下方追加真实终态记录。

## PostgreSQL／后续实际验证

本文首次交付时尚在等待独占 PostgreSQL 时段；其后实际终态追加于下方，保留此前证据归属。不新增完整 app 全包或 race 运行结论。

### 根任务版本兼容扩展（SQLite）

根任务独占新增 `backup_completion_versions_test.go`，不属于上述五个冻结文件；实际复用相同 prepare/Begin/Seal/WriteNew/finish/历史授权读流程，补充 canonical manifest v2 的组织归属 artifact 身份、v3 observed-empty/missing/unmapped 历史分类，以及「真实 AEAD 有效但实际非空内容替换已观察 empty 文件」失败反例。v3 正常样本只有 observed-empty 增加一个实际归档条目，missing/unmapped 不凭空生成文件。

这些版本兼容样本仍为合成库存与历史行哈希。特别是 v3 中存在 unmapped 的成功只证明底层格式和可信输入的完成 adapter 兼容；**不能推导完整协调器可以跳过未知布局的真实历史文件并宣称完整备份 ready**。实际同快照原行和文件布局闭包、历史文件存在/缺失判断及下载信任不提升，仍须协调器独立证明。

- 根任务报告的 versions 专项 SQLite 三轮：terminal 0，1.935s（bdfd37）。
- 根任务报告的新旧全部 app completion 前缀组合（无 DSN）三轮：terminal 0，14.541s（98321），不是完整 app 全包或双库回归。
- 根任务报告 Windows app vet/lint 0；共享 NULL 修复后 repository/app Windows vet/lint 0、Linux cross-vet 0（4599 terminal 0）。以上为根任务实际执行证据，与本 agent 的 a4ea4f/a7197f 分别记录，不合并声称独立重复执行。
- PostgreSQL 仍待 job 单元 18475 的独占慢组终态及根任务明确移交；本 agent 未自行并发启动数据库验证。

### 完整前缀双库三轮终态

job 单元明确释放 General 且根任务明确移交后，本 agent 仅将 ignored `.tools/test-postgres/dsn.txt` 读入当前 shell 的 `MII_TEST_POSTGRES_DSN`，不回显。执行固定 Go：

`go test ./internal/app -run '^TestBackupArchiveCompletion' -count=3`

未使用 driver 路径过滤，因此包括成功流程、全部嵌套 physical/manifest/receipt 故障、四类真实完成 SQL trigger、真实会话撤销，以及根任务新增的三个 v2/v3 模式；SQLite 与 PostgreSQL 均实际执行。

**terminal exit 0，65.945s；启动 361a5a，session 73895，最终 cfec0b。** 没有在失败后重启实例、改变超时、降低并发或删除用例。PostgreSQL 的 P0001 精确闭集错误断言及受控移除 trigger 后的原归档完成也实际通过。

收到 terminal 0 后已立即向根任务明确释放 General；没有本 agent 的 DB 测试继续运行，也没有操作 Backup 实例或服务。此次仅新增组合专项证据，不代表完整 app 全包、Linux 原生、race 或完整业务备份/恢复已完成。五个 agent 测试文件始终冻结，root 版本扩展文件未触碰；本文在追加该终态后也停止编辑。
