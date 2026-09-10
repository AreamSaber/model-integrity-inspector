# M6-05：原 manifest 输入估算器引用观察补充

2026-09-10。实现 `M6-SNAPSHOT-REMAINING-CLOSURE-DESIGN.md` 第 3.3 节；复用已有 Run / Estimate / Baseline 引用遍历，不新增全表 observer。本单元不是完整资源闭包、完整备份、恢复启用或正式审核批准。

## 原来源与兼容依据

- `internal/integrity/probe/generator/manifest.go:86` 将实际 `tokenizer.Estimate` 原样放入每个 manifest sample 的 `input_estimate`；`generator.go:399` 调用 `EstimateInputFor`，错误或没有 token 结果时拒绝生成。`replay.go:77` 核验既有 sample 身份及估算预算，`replay.go:132` 使用原预算构造执行 sample，不重新生成历史估算元数据。
- `tokenizer/estimate.go:37` 的原 JSON 身份字段为 `bundle_version`、`bundle_hash`、`tokenizer_version`、`tokenizer_id`、`quality`。前两者是配置的版本及配置原内容 hash，不是实现版本、词表或归档 carrier 的 hash。
- `tokenizer/estimate.go:192` 的成功输入估算只会返回 compatible BPE，或 heuristic；输入 framing 本身只是估算，即使模型映射可以精确编码可见文本，也不会把输入质量写为 exact。BPE 实现的实际公开字符串是 `mii-bpe-v1+github.com/tiktoken-go/tokenizer@v0.8.1`，编码是 `cl100k_base` / `o200k_base`。未知模型或复杂度回退使用 `unicode-byte-v1` + `unicode-byte-heuristic`。不能给 heuristic 强塞顶层 BPE 实现。
- `repository/run_estimate.go:57` 的存储 writer 要求非空 manifest，但不会逐项认证以上五字段；现有 `snapshotReferenceTestFixture` 正是可真实保存的缺省 input 元数据结构性 wire。低层合法存储不等于当前真实 compiler 生成，更不等于已验证 MAC。
- 原 Run 的无 manifest legacy、schema18 原 `legacy_fixture`、旧 probe-local ordinal、Baseline migration12 默认/未签名组合，继续由原观察单元解释。没有因为缺少 input 元数据而把它们永久拒绝，也没有补写旧字段或使用当前默认资源。

## 私有协议与边界

入口仍为 `Store.snapshotArtifactReferences(ctx, tx)` / `snapshotArtifactReferencesLimited`；没有新增公开 API。原 manifest sample 循环同时观察 input 身份，沿用真实只读 `*sql.Tx`、deadline、`NewDB`、SQL 长度预检查、每源初始及最终 count、100 行 keyset，以及全部状态 / 禁用组织 / 已过期未删除记录的覆盖。不读 live Store pool，不开新事务，不写数据库。

新增引用类别 `input_tokenizer_implementation`，六字段含义固定如下：

| 字段 | 原身份含义 |
|---|---|
| organizationID | 原来源组织 |
| category | `input_tokenizer_implementation` |
| version | 原 `tokenizer_version`，不是 tokenizer 配置版本 |
| memberID | 原 `tokenizer_id`，不是模板成员 |
| containerVersion | 同一原 manifest 顶层 tokenizer 配置版本 |
| sha256 | 同一原 manifest 顶层 tokenizer 配置 hash，仅容器上下文，不冒充实现 / 参数 / carrier hash |

原 input 已提供配置 version/hash 时必须逐字节匹配同一 manifest；hash 保持既有小写 64 位格式。缺少嵌套配置声明时，仍使用同一原 manifest 的容器上下文区分引用，但不补入缺失的原 JSON 字段、不伪称该声明存在。原实现/编码没有从配置或当前安装资源推导填充。

完整解释的组合是 compatible + 当前 BPE 实现 + 两个已知 BPE 编码之一，或 heuristic + 原 heuristic 实现/编码。已知实现与已知编码/质量互相矛盾返回 Invalid，不能降级成兼容历史。未知但有界的原实现、编码或质量保留为 input incomplete；未知身份不是已证明有效、可用或可执行。exact / unavailable 不会在此伪装成当前成功 input producer。

缺少对象/字段或原存储允许的空实现、编码、质量，分别保留缺证据分类；提供的 NULL、非字符串、空配置版本/hash、配置不一致以及坏类型不能作为“缺省”绕过。输入身份按有效 UTF-8、最多 128 字节且无 NUL/CR/LF 观察，允许真实实现中的 `+/@` 和合法 Unicode，不误用执行版本 label 正则。超过该界限为本单元不接受的数据，不截断、规范化或重新编码。

原全树严格 JSON 校验继续拒绝重复键、Unicode SimpleFold 别名（包括 s/ſ、k/K）和不精确的已知字段名。保留既有 8 MiB Run/Estimate、2 MiB manifest、150 samples 及全树深度/token 预算；每 sample 检查取消。不重新调用 tokenizer，不导入上层 generator/secret/bundle，不复制 MAC、计数器或密码学。

新增 `inputIncomplete [3]int64` 统计受影响的 Run / Estimate / Baseline **来源行数**，不是不完整 sample 数。它与原 `legacy [3]int64` 分离：前者不改变原 probe-local / execution ordinal、来源版本或 Baseline scope 语义。Baseline 继承它实际绑定原 Run 的 input 缺证据，不凭此拒绝其合法 scope。整体分类在任一类不完整时仍为 `snapshotReferenceLegacyIncomplete`，完整解释也仅表示观察完成，不是授权。

引用进入既有组织及原容器 hash 参与的有限去重 union；不设全部历史行数新上限，不跨租户或按同名版本覆盖。该 distinct 上限仍只约束本单元资源，不等于最终 manifest 全局条目/字节预算。失败均返回零整体结果，不能留下已扫描 Run 前缀。

原 `mii.snapshot.artifact-root-observations.v1` 摘要 framing **没有变更**：仍绑定固定域/来源、原 SQL 元数据、原正文 SHA、结构性 legacy 与收尾计数。本次新增分类从这些已绑定的原字节派生，不把它宣称成新增摘要格式，也不将 inputIncomplete 计数混入旧 framing。不同原字节仍有不同摘要。输出不持有原正文；新增私有中间身份关闭 fmt/slog，拒绝隐式 JSON/YAML。此处不是 Go 堆所有临时字符串均强制清零的承诺。

## 实际验证记录

固定工具链 `.tools/go/bin/go.exe`（1.26.7）。本单元以下运行均明确令 `MII_TEST_POSTGRES_DSN` 为空，只执行纯层与真实 SQLite 文件；没有读取 General DSN，没有启动 PostgreSQL 测试、重置服务或操作 Backup。

1. 修改生产前，真实 Generate / MAC 验证后 ExecutionPlan 的 cl100k、o200k 与合法未知中文模型 heuristic，以及实际存储来源，均因没有 input 引用失败：命令输出标识 `e1ec8b`，exit 1，0.394s。这是缺边的真实红例。
2. 初版补边后相同新组通过：`0ea287`，exit 0，0.403s；随后全部既有及新 ArtifactReferences SQLite/纯单轮 `decff0`，exit 0，3.532s。
3. 扩展用例后的命令 `6cd2e7` 在编译阶段因同期共享 `backupDrainReadDomain` 尚未定义而 exit 1，没有执行任何 DB 测试，不能记作回归通过。共享实现就绪后正常继续，没有重启或追认该失败命令。
4. `go test ./internal/integrity/repository -run '^TestSnapshotArtifactReferences' -count=3 -timeout=5m`：session 57814，terminal exit 0，11.142s。全部匹配顶层测试及其嵌套子树均执行，没有 `/sqlite` 或 `/postgres` 之类可能漏掉 mode 层的过滤。
5. 加入真实同快照 input 身份变化及末源失败后，最终 SQLite/纯组合：

   ```powershell
   $env:MII_TEST_POSTGRES_DSN=''
   & ./.tools/go/bin/go.exe test ./internal/integrity/repository -run '^(TestSnapshotArtifactReferences|TestSnapshotReferenceModelCompatibility|TestSnapshotResultReferences|TestSnapshotInventory)' -count=3 -timeout=5m
   ```

   session 44978，terminal exit 0，22.423s；包含本单元、原三来源引用全组、合法 Unicode 模型历史边界、全部修订结果引用，以及不需 PG 的外层错误映射。专属 PostgreSQL 外层测试因 DSN 缺省没有执行，不能据此声称双库/外层 PG 已通过。
6. 测试覆盖真实两种 BPE 与 heuristic 的 legacy/derived compiler 路径、真实 SaveRunEstimate/CreateRun、所有四状态 Baseline scope 结构记录、未知 Unicode 身份及 128/132 字节界限、每字段 NULL/类型/大小写/超长/换行/NUL、配置 hash/版本冲突、known-pair 冲突、缺失历史、取消、distinct 精确上限及超限、隐式序列化/日志封闭。case-only `Input_Estimate` 反例重新计算 fixture manifest SHA，排除只因陈旧 hash 失败的假证据。
7. `TestSnapshotArtifactReferencesInputStoredHistorySameViewAndFaults` 使用原 RO 事务与另一实际连接：后者提交 Estimate input 变化后前者不漂移；fresh view 精确改变源摘要和 inputIncomplete 行数；未知 Unicode 编码原样保留；Estimate 末源已知冲突在合法 Run 已扫描之后仍零整体结果。测试用 RawMessage 保留真实 CSPRNG int64 身份，不经 float64。故障与兼容 wire 的重算 SHA 不代表重新签名或真实 compiler 授权。
8. 已有 101 组织/100 行分页、跨租户同版本不同原 hash、真实旧迁移、SQL 类型/长度预限、末页/末次查询 rollback 与取消继续纳入上述完整选择。实际 Baseline scope 夹具未冒充真实 analyzer/Baseline service/MAC 认证。
9. 两处 G101 是固定公开 tokenizer identifier 误报，仅在对应测试字面量行附说明，不全局关闭规则。修复后完整 repository lint `b24764`，exit 0，0 issues；最终增补后 input 无告警，完整 lint 当时仅报另一单元 `execution_reconciliation_atomic_updates_test.go:147` QF1003，已向 root 交接而未越权修改。随后 repository Windows vet 通过。组合命令最终 exit 0 来自后置 vet，不把前置 lint 告警算绿。全部本单元 Go 文件已 gofmt。

## 交接与未完成边界

实现范围：修改 `snapshot_artifact_references.go`、`_json.go`、`_baseline.go`、`_test.go`、`_actual_test.go`；新增 `snapshot_artifact_references_input.go`、`_input_test.go`、`_input_actual_test.go` 及本说明。没有改 result 引用、共享 PostgreSQL 外层、原 artifact 库存、安装载体、manifest 协议或他人维护代码，没有 Git 写入。

General 已明确交还 root/Windows，没有本单元后台测试。root 将在其独占时段运行相同完整选择的真实 PostgreSQL/双库及跨模块组合；本说明的 SQLite 证据不替代这些待运行验证。原 30 秒 RO fixture / 5 分钟命令期限没有放宽。

root 最终集成：全文核对新增/修改生产和测试、本文及原编译器对应身份，保留缺失 input 的独立分类，没有把旧 ordinal 语义改成新版。General 释放后实际完整双库组合 `go test ./internal/integrity/repository -run '^(TestSnapshotArtifactReferences|TestSnapshotReferenceModelCompatibility|TestSnapshotResultReferences|TestSnapshotInventory)' -count=3 -timeout=6m` **184.972s PASS**，62907 第二条命令已终态 exit0。没有 driver 子路径过滤；真实 PG 外层与原新引用/兼容/结果全子树均包含。6分钟仅本次完整组合命令上限，实际低于原5分钟，未修改任何 RO 或生产/CI期限。root 另已取得仓储 Windows vet/lint0 与 Linux amd64 交叉 vet0；不是 Linux 原生/race 或完整备份恢复验证。

本次只补 manifest 输入估算器原引用。尚需在完整协调器中把各种原资源引用映射到各组织/原版本/原参数 hash 对应的真实保留与 installed 载体，并处理其余 Findings、S1、原 rule/template 内容与残留兼容覆盖。不能以当前 builtin 或 carrier hash 替换历史配置/实现/评分参数，也不能把 `inputIncomplete` 丢掉后声称完整或恢复可启用。M6-05 与完整开发目标仍在进行。
