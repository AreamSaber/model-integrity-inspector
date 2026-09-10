# M6-05：Tokenizer 完整安装资源载体

日期：2026-09-10。开发状态：独立资源导出、验证、从归档重建计数器已实现；正式审核：待统一审核。本单元不代表完整备份恢复、历史代码兼容或 M6-05 完成。

## 原始要求与实施范围

PRD SYS-008 要求系统配置/数据备份及恢复校验；TECH SPEC 19.2 要求受控 tokenizer 配置包启动 SHA-256 校验，19.5 要求干净环境恢复；开发计划 M6-05 与 M6-08 要求恢复完整性、制品身份及许可证。仅保存 `builtin.json`/版本名不能保存其真实词表资源。

当前产品安装 tokenizer `1.0.0`，实现为 `mii-bpe-v1+github.com/tiktoken-go/tokenizer@v0.8.1`。原始 1,548 bytes 配置和 `BuiltinHash` 完全不变。本次没有修改算法、质量标签、旧版本绑定、Worker 接线、bundle 或备份 manifest。

## 单一载体及身份

新 carrier schema：`mii.tokenizer-installed.v1`。

- `(e *Engine).InstalledArtifact(ctx)`：从该 Engine 实际使用的 `boundedBPE.ranks` 输出完整资源。检查实际类型、编码集、词表数量/连续 rank/重复/摘要、MII 正则及超时；不重新调用 tiktoken.Get、NewBuiltin 或下载/读取磁盘词表来替代损坏或未知来源。
- `VerifyInstalledArtifact(ctx, data, expected InstalledRef)`：先复制有界输入，再校验外部锚定身份、全部内容及内部受控资源身份；失败不返回部分候选。
- `InstalledArtifact.Ref()` / `Bytes()`：返回 detached 身份值和 owned bytes 副本。Ref 区分原配置 `ConfigurationSHA256` 和完整载体 `SHA256`/`Bytes`。
- `InstalledArtifact.NewEngine(ctx)`：重新验证载体，然后从归档中的真实 rank-file bytes 构建新的 map 和 BPE。不会调用 NewBuiltin、Load、依赖词表、网络或 module cache；多次恢复的 map 不共享。

外部 expected Ref 必须由可信备份锚点提供。调用者同时提供数据和自己计算的摘要并不构成来源认证。常规 fmt/slog 只显示固定占位符，Ref/Artifact 不允许普通 JSON/YAML 序列化；显式 Bytes 才能输出资源。API 不接受文件系统路径、URL、归档解压路径或插件。

固定 framing 为 magic `MII-TOKENIZER-INSTALLED-V1` 加 LF、资源数量 byte=5，接着严格按序写每个资源的 uint16 大端名称长度、名称、uint64 大端内容长度和内容。名称仅是固定资源标识，不是路径。无填充、扩展字段或尾部内容。

| 固定资源 | 内容 | 单项上限 |
|---|---|---:|
| implementation | canonical metadata；版本、原配置/许可摘要、实际 MII 两个正则、regexp2 版本、ordinary-text/heuristic/input-framing/budget 语义及工作上限 | 16 KiB |
| configuration | 原始 builtin.json，包含末尾 LF | 32 KiB |
| cl100k_base | 完整官方格式 rank 文件 | 2 MiB |
| o200k_base | 完整官方格式 rank 文件 | 4 MiB |
| notices | 仓库已有完整第三方 MIT notices 原文 | 16 KiB |

总上限 8 MiB；读取 uint64 长度后先验证 4 MiB/remaining/单项边界，再转换为 int，兼容 32-bit 安全范围。rank 文件严格为 `base64(original bytes) SP decimal rank LF`，不能 Unicode 规范化；原始单个 token 可非 UTF-8。完整 rank 连续性、数量、canonical base64/padding、重复 token、最终 LF 和官方 SHA-256 均校验。编码/字段未知、重复、乱序、截断、追加、错 hash 或超限均拒绝。取消/过期 deadline 返回标准 context 错误，零 Artifact/Engine；每 1,024 rank 或 64 KiB hashing 检查取消，不产生后台工作。

## 主任务集成复验

2026-09-10，主任务复核最终源码后执行完整 tokenizer 包三轮：
`go test ./internal/integrity/tokenizer -count=3 -timeout=30s`，**11.424s PASS**。
同一命令会话随后 `go vet` 退出 0，golangci-lint 返回 `0 issues.`，会话 57437 终态退出 0。
保持原 30 秒期限及完整用例，不使用旧载体摘要或其他提交的 CI 追认本单元。

## 实际资源证据

| 资源 | 实际 bytes / rows | SHA-256 |
|---|---|---|
| 原配置 | 1,548 bytes | `e63605c54793bca24d79c89ae4e0a66f37e4c8c5409cea795f52e63e7e5024ae` |
| cl100k_base | 1,681,126 bytes / 100,256 rows | `223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7` |
| o200k_base | 3,613,922 bytes / 199,998 rows | `446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d` |
| 完整 notices | 2,058 bytes | `01e032a74984f7b521bbf668f26cb1a118cf75a662035015bdc893fbd05edebc` |
| 完整新载体 | 5,300,206 bytes | `4d17c03ccb0ea4fbbb122d1fc9091375b5c21a06958e8ef8967872641549675b` |

完整载体 golden 是**本次新格式**首次实际导出后，由独立 wire reader、每份官方摘要、原始配置/许可字节及全语料检查验证，再显式固定的值，不声称是旧版本历史文件。第一次占位 golden 断言有意报告新摘要/长度并失败 0.845s；同次其余实际资源/重建语料检查已完成。未修改原有 tokenizer/rule/report golden 来制造兼容。

本轮未提交草稿曾产生 5,300,062 bytes / `7f53625e77d3b54b646903bf5856b6c6b07941c4a14ca42363b0ee10947424a7`。最终核对真实 EstimateInput 时发现新 metadata 简写遗漏已有 JSON-object +8 输入附加量、未知模型 heuristic reserve 公式及 never-exact 限制。补全说明后，新增从归档恢复的 known-input 18 tokens /23 budget 与 unknown-input 对照均通过，旧草稿 golden 如期失败 0.458s，再固定上表最终新格式摘要。变化是补全归档说明，不是改变产品计算、旧版本身份或原有 golden。

## 验证记录

- 真实 exporter → 独立 framing reader → 两词表逐行校验 → Verify → **从归档构建 Engine** → 现有 759 条 frozen OpenAI tiktoken 0.14.0 语料 × 两编码。刻意没有调用内部使用 NewBuiltin 的 `checkReferenceCounts` 作为恢复证明。
- 原始 map 删除或相同数量交换 rank 会让导出失败，证明没有当前默认资源 fallback；修改归档、返回 Bytes 或输入 bytes 不影响已拥有的其他载体/Engine。验证先取 owned 输入，随后在真实检查点修改调用者输入不会替换已验证 bytes。
- 覆盖外部 Ref、metadata unknown/duplicate/case alias、原 config 版本/LF、真实二进制名称 unknown/duplicate/path/order、两词表单字节/rank/order/count/base64/pad/EOF、许可缺失/变更、uint64 最大长度、8 MiB 边界、恢复源类型/正则/超时和 nil/cancel/deadline。
- 完整 tokenizer 测试三轮已 PASS 7.776s；显式整数/索引界限补强后再次三轮 PASS 7.766s，均保持 `-timeout=30s`。初次 lint 提示边界/直接 nil-context 负例后通过显式长度范围与 typed nil context 修正，没有关闭检查或增加 suppression；最终 lint `0 issues`。
- `go test ./internal/integrity/tokenizer -run '^$' -fuzz '^FuzzInstalledTokenizerArtifactFraming$' -fuzztime=5s -parallel=2 -timeout=30s`：PASS 5.223s，378,795 executions；成功 framing 必须精确 canonical round-trip，失败不得返回部分资源 slice。
- 后续 owned-input/deadline/8 MiB 边界测试整套三轮 PASS 9.307s、vet/lint 退出 0。最终补全输入语义说明和新断言后，`go test ./internal/integrity/tokenizer -count=3 -cover -timeout=30s`：PASS **8.964s**，整个 tokenizer package statement coverage **87.9%**，同一进程终态退出 0。
- 最终 Windows `go vet ./internal/integrity/tokenizer` 与 `golangci-lint run --allow-parallel-runners ./internal/integrity/tokenizer/...`：退出 0、0 issues。`GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 同范围交叉 vet/lint：退出 0、0 issues；此处没有声称原生 Linux 执行或 race 已通过。

## 未完成边界

本载体只支持当前真实安装实现和受控资源。它不是 Go 代码/二进制，也不能执行未知历史实现；恢复仍需匹配的应用制品和独立备份外部锚点。若旧快照引用未安装/不支持的 tokenizer，不能拿当前资源改名或默认替代，必须保留原始历史、报告不兼容，随后由完整版本兼容机制处理。

Scoring 未在本单元实施。其 tenant-specific Scoring/TokenRisk 参数必须由对应原始 rule artifact 保存，不能用当前 Parameters 重建或压成全局同名版本。备份协调器、完整资源引用闭包、archive/manifest 接线、数据库恢复、权限/主密钥校验、隔离启用和真实干净环境恢复仍是后续工作。已有第三方 notices 随 carrier 保留；无新依赖或联网授权变更。
