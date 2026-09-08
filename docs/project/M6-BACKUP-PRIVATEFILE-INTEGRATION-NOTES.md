# M6-05 私有文件与认证归档组合验证

更新：2026-09-08。状态：新增真实组件集成测试与有界解析 fuzz 已完成 Windows 验证，供主任务最终复核；**没有新增备份/恢复业务协调器，也不是数据库恢复验收或正式批准**。

本单元只新增：

- `internal/integrity/privatefile/backup_integration_test.go`
- `internal/integrity/secret/backup_fuzz_test.go`
- 本说明

已冻结的 crypto 生产实现、privatefile 生产实现、密钥文件/应用配置、数据库和既有台账均未修改；未执行 Git。边界沿用 `M6-BACKUP-IMPLEMENTATION-NOTES.md` 第 5～7 节、`M6-BACKUP-CRYPTO-CHECKPOINT.md`、privatefile README，不改变原始 PRD/TECH/ADR 要求。

## 1. 真实组合与发布边界

集成测试位于 privatefile 同包，但归档加密只调用公开 `secret.NewKeyRing`、`NewBackupCapabilities`、`Seal`、`Open`；不填手工密文、不使用假 opener、不调用 privatefile 内部发布 hook。所有文件和 synthetic master 都由测试独立创建，没有使用用户真实密钥、数据库或归档。

加密路径为 `privatefile.WriteNew` 的私有密文 staging 内调用 `BackupSealer.Seal`。精确核对 crypto receipt 的 ArchiveBytes/ArchiveSHA256 与 privatefile publication receipt 的 Size/SHA256，并验证 Published=true。

解密路径的测试辅助组合为：

```text
WriteNew(明文 staging)
  └─ Read(完整有限的密文文件)
       └─ Open(预期 backup ID + manifest hash)
            └─ 认证后逐块写到尚未发布的明文 staging
       完整 Final/EOF 认证通过
     同一原生句柄、文件属性、权限、父目录、EOF 复核通过
   两种读取 receipt 的长度/hash/entry 范围核对通过
明文才允许执行既有 no-replace publication
```

目标文件不存在的检查覆盖每次明文块写入、Open 已完整成功但 Read 尚未返回的阶段、Read 已完整成功但外层 WriteNew callback 尚未返回的阶段。成功后再通过生产 Read 读取明文成品，独立核对最初生成流的 SHA-256、长度及成品 receipt。

测试辅助组合明确传播每层错误。privatefile 本身不认识 AEAD，不能让一个故意忽略 Open 认证失败、仍返回 nil 的不可信协调器变安全。“吞错”回归验证的是消费 callback 吞掉 Reader/Writer/取消错误后，所属组件的 sticky failure 仍阻止成功；**不是宣称忽略任意上层认证错误也能自动阻止发布**。后续生产协调器必须保留全部传播和 receipt 核对。

## 2. Windows 实际覆盖

新增五个顶层集成测试：

1. **25 MiB+17 字节真实流**：生产私有密文写入、真实 AES-GCM 归档、生产密文读取、解密至私有明文 staging 和成品读取；401 个以上块级路径、有界分配量断言（本次累计 Go heap allocation 增量小于 12 MiB）、独立 SHA-256 与全部 receipt 精确一致。没有把完整文件载入 RAM。
2. **九种失败场景**：尾随字节、末尾认证截断、Data 截断且消费 callback 吞掉读取错误、错误 master、错误 backup scope、吞掉明文 staging Writer 限额错误、吞掉中途取消，以及分别在 crypto 完成后、原生源文件读取完成后取消。均没有明文成品，也没有遗留本次明文 staging；原输入文件保留。错误 key/scope 另外明确断言明文 consumer 调用次数为零。
3. **密文及明文 no-replace**：已存在的密文文件逐字节不变；明文即使已通过完整归档认证，也不能替换已存在的目标，其原有字节保持不变。
4. **明文与密文限额区分**：实际 1,024 字节明文在 1,024 字节文件预算下因认证封装开销失败且不发布；独立提供足够密文预算后成功。两种 1 TiB 硬上限分别做输入校验反例，不分配/写入 1 TiB 文件，也不把两个上限当作同一计量。
5. **完整认证后的非取消类源文件最终复核失败**：仅在 `crypto_complete` checkpoint 用 `os.Chtimes` 修改本次测试自建密文源文件的 mtime，实际 Stat 确认时间发生变化；不取消 context、不改目标目录/权限、不改密文内容。此时 Open 已取得完整 receipt、全部 257 字节已经写入仍不可见的 staging，原生 Read callback 尚未返回、源文件原句柄仍打开。随后 Read 的真实同句柄最终 Stat 检出时间差，必须返回 `ErrUnsafe` 和零 source receipt；组合向外传播为 `ErrCallback`，没有明文成品或遗留 staging，源密文字节独立复读保持不变。

`swallowed_output_limit` 特别要求内部 Open 已成功且存在完整 archive receipt，最终仍由外层 privatefile 的 Writer sticky ErrLimit 阻止发布。两个末尾取消场景也分别断言已经取得相应内层 receipt，避免只测试到过早取消。

第五项不是用取消间接阻止发布：它同时要求原 context 保持未取消、archive receipt 的 entry/明文总长/密文总长/hash 精确完整、`source_complete` 阶段不可到达、源错误精确为 `ErrUnsafe`。这补上了原先仅有末尾取消测试不能独立证明的错误传播路径。测试没有生产 fault hook 或假的 Read 返回值。

Windows 本地实际允许该次 `os.Chtimes` 元数据修改，因此此反例真实执行并通过，没有 Skip，也没有增加原生辅助句柄或放宽生产共享标志。普通数据写入/删除共享限制不能被扩大解释为禁止所有元数据访问；属性访问的共享例外见 [Microsoft CreateFileW 文档](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)。本测试只修改自己的合成文件，且不宣称这类共享策略可以抵御同一可信主机操作者改变属性。

这些受控失败均发生于发布前；不改变既有 privatefile 的通用合同：发布之后的 close/sync/取消失败可能返回 Published=true，已发布成品不能被当作回滚删除。上层 DB ready/audit/授权凭证仍是独立的必要门槛。

## 3. 平台与容量控制

直接复用 privatefile 既有 `privateDir` 平台夹具，不复制或放宽安全策略。Windows 只规范本次 TempDir 的实际长名称并复核同一目录身份，仍使用私有 ACL、无 reparse/alias 和原生 no-replace；Linux 保留真实本地文件系统检查，Docker overlay 不被接受，只允许既有经验证的 `/dev/shm` tmpfs 夹具回退。

大测试明文加密文同时约 50 MiB，使用 25 MiB+17 而不是两份 32 MiB，避免在常见 64 MiB tmpfs 内自身超量。测试放在同一个 privatefile 包且不调用 t.Parallel，与该包既有 32 MiB 资源型测试自然顺序执行；各案例清理自己创建的目录，避免跨包并行同时占用同一 tmpfs。没有调整 CI 内存、扩大挂载或接受 overlay 来使测试通过。

本次只实际执行 Windows。Linux 本轮没有原生执行，也没有新 cross-compile 证据；现有平台夹具与同包串行设计不能替代后续真实 Linux CI。25 MiB 仅证明组件流式组合，不是数据库规模、生产卷容量、断电持久性或灾备 RTO/RPO 验收。

## 4. 有界 Open fuzz

新增外部 `secret_test` 的 `FuzzBackupOpenArchive`，调用真实公开 Opener。独立固定 v1 encoder 用公开 synthetic key/DEK/nonce 生成确定性语料，不覆写生产随机源，各 fuzz worker 拥有完全相同的 baseline。

- 17 个固定种子：合法空归档、小归档、多块/多 entry、超过 entry 限额，及头/密文/尾部篡改、截断、尾随、非法帧长度；selector 使用更小的明文字节或 entry 预算验证已认证归档仍不能越限。
- 每输入不超过 256 KiB；Open 明文上限 192 KiB、entry 上限 16、2 秒期限，消费内再次独立计量；更大输入跳过，不宣称这一 fuzz 覆盖任意归档容量。
- 对已知合法且预算足够的种子要求成功并核对明文摘要，防止“全部拒绝”被误判安全。已知坏或超预算种子必须失败。
- 失败必须返回零 archive receipt 和精确闭集 error sentinel；测试刻意拒绝带原文的包装错误，所以对该身份断言作带理由的局部 errorlint 豁免，而不是放宽为 errors.Is。
- 成功要求消费 entry/明文字节、输入 SHA-256、完整消费/EOF、receipt 全部一致；Opener 不得修改输入切片。测试不把随机构造的错误认证数据当作真实恢复工件。

## 5. 命令与最终证据

固定 Go 1.26.7；没有数据库测试或实际数据库文件。

```text
go test ./internal/integrity/privatefile -run '^$'
PASS 0.091s                 # 实际确认同包测试依赖无环

go test ./internal/integrity/privatefile -run '^TestBackupPrivateFile' -count=1 -v
PASS 0.466s

go test ./internal/integrity/privatefile -run '^TestBackupPrivateFile' -count=3
PASS 1.214s

go test ./internal/integrity/privatefile -run '^TestBackupPrivateFileSourceRecheckFailureAfterAuthentication$' -count=1 -v
PASS 0.091s                 # 新增非取消类源文件最终复核反例，Windows真实执行

go test ./internal/integrity/privatefile -count=3
PASS 1.848s                 # 最终五项集成 + 既有privatefile全包，Windows三轮

go test ./internal/integrity/secret -run '^$' -fuzz '^FuzzBackupOpenArchive$' -fuzztime=10s -parallel=2
PASS 11.130s
17/17 baseline；2 workers；159084 executions；5 new interesting，total 22

golangci-lint run --allow-parallel-runners ./internal/integrity/privatefile/... ./internal/integrity/secret/...
0 issues
```

fuzz 的 10 秒是指定 fuzz 时长，11.130 秒为实际工具报告的完整包耗时；未发现失败语料。五个新增 interesting 是覆盖语料，不是五项缺陷。未运行 race detector，也不能把有限 fuzz 零失败称为完整密码安全证明。

主任务此前独立回报的复跑：整个 privatefile 包三轮 **2.183s PASS**（当时尚不含新增 mtime 反例）；`FuzzBackupOpenArchive` 全部 seed 三轮 **0.111s PASS**（不是第二次持续 fuzz）。新增 mtime 反例后本单元最终全包结果为上述 **1.848s PASS**，两包最终 lint 仍 **0 issues**。本轮未改 fuzz 文件或重跑持续 fuzz，原 **11.130s / 159084 executions** 保持为此前实际证据；不混同为新的数据库或恢复链路测试。

主任务补充完整阅读新增 mtime 场景与对应消费断言，独立复跑该真实 Windows 场景三轮 **0.104s PASS**。这不是全包第二次复跑，也没有新增 Linux 或数据库恢复证据。

后续仍需生产备份协调器、维护/租约门禁、SQLite/PG 一致快照及 manifest、外部锚点、完整历史密钥与 Secret/报告/schema/审计验证、隔离恢复、CLI/HTTP/UI 和真实干净环境灾备演练。不存在授权批准或“可直接恢复生产”的结论。
