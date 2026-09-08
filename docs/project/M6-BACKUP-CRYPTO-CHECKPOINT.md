# M6-05 认证加密归档纯组件 checkpoint

更新：2026-09-08。状态：纯加密流生产实现及 Windows 专项已完成，供主任务复核；未接数据库、维护门禁、CLI、HTTP 或恢复流程，不能据此将 SYS-008 / M6-05 标为完成或正式批准。本单元不修改原备份实施设计、全局台账、历史迁移或 Git。

已阅读依据：`M6-BACKUP-IMPLEMENTATION-NOTES.md` 全文及其 PRD SYS-008、11.1/11.2、15.1/15.3，TECH 13.6、18、19.5/19.6、AC-23，ADR-0002/0004/0005/0006；沿用现有 Secret 用途隔离与 `privatefile` 的可信暂借 callback 边界。

## 1. 文件与稳定 API

修改 `internal/integrity/secret/envelope.go`，仅在既有 KeyRing 派生集合中追加 `backup-archive-wrap` 用途。新增 `backup.go`、`backup_format.go`、`backup_stream.go`、`backup_test.go` 及本说明。没有反向导入 repository、app 或 privatefile；没有导出原始主密钥、包装密钥、DEK、文件路径或原生句柄。

```go
KeyRing.NewBackupCapabilities() (*BackupSealer, *BackupOpener, error)

BackupScope{BackupID int64, ManifestHash string}
BackupLimits{MaxBytes int64, MaxEntries int, Timeout time.Duration}
BackupEntry{Kind string, ID string}

BackupSealer.Seal(ctx, scope, limits, dst io.Writer,
    produce func(context.Context, *BackupArchiveWriter) error) (BackupReceipt, error)
BackupArchiveWriter.WriteEntry(entry,
    produce func(context.Context, io.Writer) error) error
BackupOpener.Open(ctx, scope, limits, src io.Reader,
    consume func(context.Context, BackupEntry, io.Reader) error) (BackupReceipt, error)
```

上述代码块是接口摘要，省略了重复类型名。`BackupReceipt` 仅包含版本、key version、归档 SHA-256、entry 数、明文总字节和归档总字节。它不是审计、授权、原子发布或恢复成功凭证。

- 两种窄能力只复制备份用途 key，不保留 KeyRing。Sealer 使用当前版本，Opener 接受显式提供的历史版本；真实多版本 key 文件配置由另一独立单元接线。
- Scope 必须来自可信协调器的**预期** backup ID 与 manifest hash。归档内自带 hash 不能自证来源、授权或抵御整个旧合法备份替换。此层不会生成 manifest，也不证明它与数据库快照一致。
- Kind 闭集为 `database / manifest / report / rule / config`。ID 是 1～64 字节规范小写 ASCII 标识符，首字节为字母或数字，其他字节允许字母、数字、`_`、`-`；所有 Kind 之间 ID 也不能重复。ID **不是路径**，没有自动解包或名称到路径的映射。
- 显式 Limits 硬上限为 1 TiB **明文**、65,536 entries、24 小时；空 entry 也计数，空归档合法。它们是资源上界，不是生产容量、RTO/RPO 或恢复验收。
- ArchiveWriter 及借出的 Reader/Writer 生命周期共享私有 state；复制句柄不能重新获得生命周期。Scope、Entry、能力与借用对象的 value/pointer 通用格式化、JSON、slog 均有保护。错误只返回闭集标识，不带 callback、I/O 或 panic 原文。

## 2. v1 二进制格式与认证边界

全部整数为大端。归档没有压缩、路径表或任意扩展字段；未知类型、非零保留位、非法长度与非规范 entry 数据均拒绝。

固定头共 208 字节：

| 字节区间（半开） | 内容 |
| --- | --- |
| 0～8 | `MIIBKP`、零字节、版本字节 `1` |
| 8～9 / 9～12 | key version 长度 1～64 / 保留零 |
| 12～20 / 20～52 | 正数 backup ID / 32 字节预期 manifest hash |
| 52～84 / 84～96 | 每归档随机 salt / 随机 12 字节 wrapping nonce |
| 96～160 | key version，未使用字节必须零 |
| 160～208 | 随机 32 字节 DEK 的 AES-256-GCM 包装密文及 16 字节 tag |

Wrapping key 沿用 KeyRing HKDF 结构，新增独立 info `mii/v1/backup-archive-wrap/<key-version>`。Wrapping AAD 为固定域 `mii/backup-wrap/v1\0` 加前 160 字节；完成包装后计算**整个 208 字节头**的 SHA-256，用于后续数据 AAD，不存在 wrapped DEK 与 header hash 的循环依赖。每个归档独立随机生成 DEK，不用主密钥直接加密全部数据库内容。

每条记录为 20 字节明文记录头及 `plaintext length + 16` 字节认证密文。记录头依次为 type 1 字节、保留零 3 字节、明文长度 uint32、全归档序号 uint64、entry ordinal uint32。全序号从 0 连续增加，entry ordinal 从 1 连续增加。

| type | 认证明文 | 语法 |
| --- | --- | --- |
| 1 Begin | 固定 68 字节：Kind 代码、ID 长度、保留零 2 字节、ID 零补足 64 字节 | 不可嵌套，ID 不可重复 |
| 2 Data | 1～65,536 字节 | 同一 entry 最后一个 data 允许短块；短块后不能再有 data |
| 3 End | 固定 8 字节，entry 明文总长度 | 必须和已认证 data 精确一致，允许空 entry |
| 4 Final | 固定 12 字节，entry 总数 uint32 与归档明文总长 uint64 | entry ordinal 必须 0；必须位于 entry 外；之后必须真实 EOF |

每 4,096 条记录（包括所有控制记录）更换 epoch key。该 key 从原随机 DEK 经 HKDF-SHA256 派生，info 为固定域 `mii/backup-data-epoch/v1\0`、完整 header hash、epoch uint64；不会由前一 epoch key 串联派生。记录 nonce 为 `BKP`、版本字节 `1`、全局序号 uint64；数据 AAD 为 `mii/backup-record/v1\0`、完整 header hash、20 字节记录头。重复、乱序、跨 entry 重放、跨归档替换与截断不能产生成功 receipt。

读取记录头先检查有限长度与序号，再读取最多 65,552 字节密文，认证成功后才借出明文。全局帧数、entry 数、明文总量和密文总量同时有界；uint64 结束长度只做精确比较，不转换为可溢出的有符号累计量。实现不把完整归档或完整 entry 读入 RAM，仅保留固定块、有限 ID 去重集合和增量 hash。

## 3. 失败、生命周期及必须保留的上层责任

- callback 必须同步且配合 context。短写（即使 err 为 nil）、完整写带错误、非进展读取、非法读取计数、取消、超限、异常、未消费完 entry 均使本归档失败；错误一经记录不能被上层 callback 吞掉并变为成功。
- 底层 I/O 的 panic 在最接近 I/O 的边界转成 sticky 闭集错误，避免持锁调用期间异常展开造成重复加锁死锁。Begin 锁段以独立 helper 与 defer 解锁；entry callback panic 同样留下 sticky failure。
- callback 返回时借用能力先原子关闭；已进入 I/O 的调用返回后再次验证 closed/context，不能向消费者补发明文或返回成功。任意阻塞 callback/操作系统 I/O 不能被 Go 强制抢占，这里不声称已经获得实时硬中断。
- Seal 只在 Final 写完和取消复核后返回 receipt；Open 只在完整 Final 认证、总数/长度、真实 EOF 和取消复核后返回 receipt。之前逐块消费的明文**不等于可信完整归档**。
- Opener 只能交给可信私有 staging 消费者。调用方必须等 Open **及外层 privatefile.Read** 都成功，完成所有预期 manifest/entry 哈希与数据库验证后，才能发布或执行恢复内容。此层不能撤回消费者已经复制的明文，也不把任意 PG dump 变成沙箱。
- 所有自身持有的 DEK、临时 epoch key、明文与工作缓冲按生命周期 clear；标准库 AES 展开密钥对象只能释放引用，没有强制清零接口。不声称清除栈副本、消费者副本、交换文件或所有进程内存。
- `BackupLimits.MaxBytes` 计明文，封装有额外字节。privatefile 自身的 1 TiB 文件上限必须由协调器独立处理；不得假定 1 TiB 明文一定能写进 1 TiB 文件。任何失败都可能已产生部分密文，必须由受限 staging/no-replace publication 协议管理；本层不删除或发布文件。

## 4. 实际测试与独立复核

本轮使用仓库固定工具链 Go 1.26.7，Windows，CGO_ENABLED=0；没有启动数据库或修改真实归档。新增 13 个顶层 `TestBackup...` 测试，覆盖：

1. 0/1/65,535/65,536/65,537 字节与空归档、精确 count/byte 上限、bytewise 写入规范化、独立归档随机性、完整 receipt/hash 一致性。
2. 每个已有用途 HKDF 输出保持原值，使用任一其他用途包装 key 的归档均拒绝；匹配历史版本成功、错误/缺少主密钥拒绝、KeyRing key 切片清除不影响已派生独立能力。既有用途/golden 测试没有修改。
3. 固定头逐个 208 字节篡改、外部 scope 不符、短归档每个截断位置、记录每个字节篡改、额外字节/第二归档尾随；没有完整认证时 receipt 恒为零。
4. 独立构造带**有效 AEAD tag** 的非法语法，涵盖未知类型、无 Begin、嵌套、空 Data、错误 entry、错误 End/Final 长度及 count、短块后再 Data、提前结束、重复/非规范 ID、65,537 字节 Data、最大 uint64 结束长度及最大 uint32 count，避免仅用 bitflip 冒充语法证明。
5. 2,050 个空 entry 跨越第 4,095/4,096/4,097 条记录：独立编码器及生产 Sealer 均能完整 Open，边界整帧重复和乱序均拒绝。
6. I/O 短写/错误/非进展/panic、合法短读与同次返回数据+EOF、尾随数据+EOF、吞掉限额/取消/entry 异常、未完整消费、嵌套 entry、归档及借用对象复制/返回后调用、value/pointer JSON/fmt/slog 脱敏。
7. 明确 barrier 调度：callback 返回但底层单次读/写仍在进行，关闭已发生后释放 I/O；Reader 零输出且原目标字节未动，Writer 和整个操作均不成功。
8. 合成 32 MiB+17 字节流经真实 AEAD 与临时密文文件，逐块独立明文 SHA-256、写读 receipt 精确一致，累计 Go heap allocation 增量小于 8 MiB。这只是组件流式证据，**不是数据库备份、privatefile 集成或恢复演练**。

独立子 agent 源码复核确认了初稿的两项 P2：Begin 写入 panic 可能持锁异常展开导致死锁；entry producer panic 被外层恢复吞掉后可能继续 Final。已修复并增加确定性回归。未执行修复前红测，故不把这些记录为“实测红→绿”。复核还提示 in-flight 回调后生命周期再检，亦已加入上述 barrier 回归；目前没有其余已确认未修复的 P1/P2。

最终命令与实际结果：

```text
go test ./internal/integrity/secret -run '^Test(Backup|Envelope|TenantAAD|Rewrap|Sensitive|Consumer|InputValidation|DeletedAnd|Nonce|Probe|ResponseEvidence|DerivedSource|Display|RequestReproduction|Baseline)' -count=3
PASS 0.837s

golangci-lint run --allow-parallel-runners ./internal/integrity/secret/...
0 issues
```

这个 regex 特意排除需要 SQLite 的 Secret service 测试；不是整个 secret 包 DB 回归。未执行 race detector、Linux 原生/交叉运行、privatefile+crypto 合成流水线、实际 SQLite/PG 快照、维护门禁、恢复隔离、全部 key 版本加载、schema/报告/Secret/审计恢复验证、CLI/HTTP/UI 或真实干净环境演练。后续由主任务完成独立最终复核与端到端接线，本单元不代替 TL、OPS/SEC、QA 的最终批准。

## 5. 主任务提交前复核

root完整读取全部4个新生产/测试文件及envelope用途增量，复核Begin持锁段defer释放、sticky panic、in-flight关闭后复验、独立有效tag语法与epoch边界反例。最终纯Backup/既有用途/golden及另一个keyfile单元三轮合并PASS1.174s，contracts/secret/app组合lint0。此前独立测试13项与外层privatefile集成仍应区分；privatefile实际嵌套及fuzz正由后续独立测试单元补充，不在此提交中追认。此提交没有数据库门禁或真实恢复入口。
