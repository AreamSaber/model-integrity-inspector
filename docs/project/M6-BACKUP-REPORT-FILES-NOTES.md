# M6-05：现代报告实际文件复制组件

2026-09-10。仅新增 `internal/app/backup_report_files.go`、两个专属测试文件及本记录。
本单元是 SYS-008 / TECH SPEC 19.5 报告归档的一项底层能力，不是完整备份、恢复、
系统内入口、正式审核或 M6-05 完成。没有修改 Store、Repository、Config、迁移或旧测试。

## 接口与信任边界

私有 `copyBackupReportFile(ctx, store, ref, sink)` 只返回私有字节复制收据。
未来协调器必须从完整同快照库存取得 `ref`，维护数据库/文件之间的一致性并确认备份权限；
本函数不查询数据库、不接受或解析 `storage_path`，不遍历目录，不接收任意文件路径，
不重新渲染报告。一个可读的合法 ref 并不证明调用者拥有数据库授权。

源端直接调用现有 `reportstorage.Store.Read`，完整复用其内容寻址、原生 no-follow、
目录/文件权限、Lstat 与已打开 handle 身份、单链接、大小及 SHA-256 检查；未另造或放宽
Windows/Linux 存储安全策略。格式仍只有现代 `json` / `html` / `csv`。

源读取每次至多持有一份成功 `Read` 返回的 **16 MiB 完整 owned 文件载荷**；输出同步分块
上限为 64 KiB。不能将其描述为源端 64 KiB 纯流或整个归档只有 64 KiB 内存。
成功读取的 owned 载荷在函数返回前清零，错误、取消与 writer panic 也清零。
源读取内部失败时未返回的临时内存仍由既有 Store 实现管理，本单元不冒称已改变其生命周期。

必须传入有效、有 deadline 的 context，以及可信同步 `io.Writer`。每块写入前后及最终
生成收据前都检查取消。writer 任意非零错误、`n != len(p)`（包括短写且错误为 nil）、
负数/超长计数或 panic 均立即失败，不重试、不补写，不格式化或记录 writer 的错误/恐慌值。
nil sink 失败，typed-nil sink 的 panic 被闭集接住；不导致进程 panic。
所有失败返回零收据；错误仅为配置错误、现有三个固定 storage 错误或固定复制错误。
收据的值/指针 fmt、slog 输出固定文本，JSON/YAML 序列化拒绝。

sink 必须遵守不修改/保留输入切片的 `io.Writer` 契约，并配合 deadline；本函数无法抢占
任意阻塞的 Write，也不能验证恶意 writer 是否真的持久化了它声称接收的字节。
未调用 sink 的 Close、Sync 或 publish。失败时 sink 可能已有前缀，甚至已有完整明文；
零收据不代表回滚写入。调用方不得吞掉复制错误或提前发布，必须将暂存目的地保持私有，
等待整个 AEAD 归档及私有原子文件生命周期完成后再发布。

## 真实测试范围

- 通过真实 `NewDevelopmentSnapshot`、`Generate`、`GenerateCSV` 生成三种格式，再用实际
  受限目录 `Put` → 复制。独立计算 SHA-256，核对全部原字节和 org/format/size/hash。
  fixture 是内核接受的 S1，不是数据库授权、真实报告 Job 或机器发布闭环。
- 新开独立物理 Store 执行安全 `Read`，证明成功/错误后原值不变；成功场景同时比较原文件
  identity、大小、权限及 mtime。没有用报告再渲染冒充原文件读取。
- 1、64 KiB−1、64 KiB、64 KiB+1、128 KiB+37、精确 16 MiB 边界；每块 len/cap 均受限，
  全字节不截断。测试专用同步 spy 暂借切片仅用于检查返回后清零，真实 sink 禁止保留切片。
- 实际缺失、同长度篡改、文件变长、错误 size/hash/org/format、非法路径式 hash/format、
  非正 org/size、超过单文件上限，均在任何输出写入前失败。错误 org/format 场景是对应
  内容寻址文件不存在；不将此测试扩张为本组件能拒绝另一个合法存在的组织 ref。
- 创建真实硬链接使原文件 nlink=2，复制拒绝且零输出；只移除该测试自建别名后原值可复制。
  该测试无 skip，不修改系统 ACL 或共享目录。
- 迟发短写、零进展、负数/超长计数、部分写+错误、完整写+错误、panic，均在已经接收
  首块后拒绝；不再次调用 writer。错误对象的 Error 方法本身会 panic，证明没有泄漏/格式化。
- 无 deadline、nil context/store/sink、零 Store、typed-nil 指针/函数、提前取消/过期，
  以及第一块和最后一块完整写入后取消；最后一种明确证明已接收全部字节仍返回零收据。
- 实际 AEAD `Seal` / `WriteEntry` / `Open` 组合：合法 CSV 全字节往返；复制失败、
  被外层吞掉的真实 entry 错误，以及复制完成后的 producer 迟发失败，都没有整包收据。
  截断最后一字节或追加尾字节的 Open 在已完整消费报告 entry 后仍拒绝，零整包收据，
  调用方不发布明文。这是内存暂存的真实加密组合测试，不冒称已集成原子磁盘发布/恢复。

## 本地证据与限制

固定 Go 1.26.7，Windows 原生文件系统；测试 shell 移除当前进程的
`MII_TEST_POSTGRES_DSN`，未运行 DB 测试、未操作 General/Backup cluster 或服务。

- 初次核心专项：`go test ./internal/app -run '^TestBackupReportFile' -count=1 -timeout=90s`，
  PASS 0.479s，exit 0。
- 补入 AEAD/真实硬链接后专项三轮：PASS 1.161s，exit 0。
- 首次静态检查实际失败：仅测试 `QF1003` 要求将两分支判断改为 tagged switch；已修复，
  未改动任何超时、阈值、断言、并发或失败语义。
- 修正后同专项三轮：PASS 1.053s，exit 0；`go vet ./internal/app` exit 0；
  固定工具链 `golangci-lint run --allow-parallel-runners ./internal/app/...`：0 issues，exit 0。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o .tools/backup-report-files-linux.test ./internal/app`：
  exit 0，仅交叉编译。尚未运行本单元的 Linux 原生测试、race、新远端 CI 或完整 app/双库回归。

## 不得永久省略的后续工作

根任务已完整阅读生产文件、两个测试文件与本说明；与既有安全配置模板组合执行
`go test ./internal/app -run '^(TestBackupReportFile|TestBackupConfiguration)' -count=3 -timeout=2m`，
Windows 实际终态 exit 0，**1.593s PASS**。这是纯文件/配置/实际 AEAD 组合，不含 DB
或整套应用流水线；没有用旧 CI 结果追认本次尚未推送的新增文件。

尚未把同快照完整报告库存连接到实际文件复制，也没有实现数据库快照/规则/配置/密钥闭包的
完整归档协调器。合法历史 `legacy_unverified` 的安全布局映射与实际文件状态必须另行实现，
未知布局仍须明确 `unmapped` 并由后续协调器处理，不能永久跳过或伪造文件存在，不能重签
旧 source、提高信任或自动恢复下载权限。整包校验、隔离恢复、显式激活、系统内 CLI/HTTP/UI
及真实灾备演练仍独立待完成；本组件收据不授予以上任何能力。
