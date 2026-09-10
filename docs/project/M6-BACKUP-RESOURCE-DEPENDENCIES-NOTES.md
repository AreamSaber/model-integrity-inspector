# M6-05：原规则与模板资源依赖纯层

2026-09-10。按 `M6-SNAPSHOT-REMAINING-CLOSURE-DESIGN.md` 第 3.4、4、6 节实施。仅新增 `internal/integrity/bundle/backup_dependencies*.go` 及对应测试；未改变 repository、app、template/tokenizer/scoring 原 codec、manifest v1/v2/v3、迁移或 Git 状态。没有读取 DSN、启动/访问数据库或操作服务。

## 范围和事实源

本单元给后续同快照 collector 一个**已复制原 artifact → 有限依赖观察 → 精确载体字节身份匹配**的纯层，不重复查询 rule/template 表。输入必须来自既有同快照 artifact 库存和已完成的原字节 spool。组织、行 ID、版本、原内容 hash、字节数全部原样保留；接口没有 current、Run 引用、状态、敏感级别或组织启用过滤参数，因此 collector 必须对未使用、候选、退役等所有保留行调用它。

已完整对照：

- `bundle/builtin.go` 的 `mii.runtime-bundle.v1` 原 Manifest；`artifact.go` 的 `mii.rule-artifact.v1` 包装、真实候选 producer 与有限 compiler；`runtime.go` 当前 process-local version registry 的局限。
- `probe/templates/bundle.go` 的完整 canonical/Decode、成员、prompt/assertion/Render 规则；无 include、URL 或独立文件装载器。
- `analysis/scoring/types.go`、`runtime.go` 与 tokenrisk 对应文件中实际参数 JSON hash 语义；不是通过全包 SHA 代替参数 SHA。
- tokenizer 原配置与实际 installed rank/config/implementation/notices 载体；scoring installed 原参考 rule 载体及用途边界。
- `repository/bootstrap_bundles.go` 的真实初始写入口和现 artifact observer 的原行身份/总源预算约束。

RuleArtifact 有真实纯层 producer/compiler，但当前 bootstrap 持久入口仍是 root version/template/tokenizer/scoring 形状；不能把候选纯层测试说成数据库已有正式规则发布流程。历史 stored-shape 变体测试也不是当下 runtime admission。

## API 与原字节生命周期

`ObserveBackupDependencies(ctx, source, limits, read)` 的 `read(ctx, consume)` 适配既有受控 `BackupWorkspace.Read` / `privatefile.Read`，不得提供任意 SQL 或路径。read 应同步调用 consume **恰好一次**，完整传播其外层身份/EOF/最终关闭错误，并配合共同 context；禁止保留 callback 或脱离生命周期运行后台工作。

source 闭集类别只有 rule/template，携带 OrganizationID、RowID、原 Version/SHA256/Bytes。source version 当前最多 128 字节，沿用既有 artifact observer 可表达的输入范围，不改名、不 trim、不要求等于某个今日内置标签；不能据此声称已扩展 foundation 允许的所有历史超界标签。source SHA 是独立传入的库存预期值；匹配它仅证明本次读到的原字节一致，不认证提供该预期值的人或来源，也不是 MAC/审核批准。

每次读最多 64 KiB，并要求精确总长度、完整 EOF 和 SHA。已声明 source 超过本次 MaxBytes 时在读取前显式 limit 失败，不截断。MaxBytes 是单个来源预算（硬顶 1 TiB），**不是整个数据库或归档联合预算**；总体 entries/bytes、所有表与其他载体仍须 collector 累计扣除。

只在原 source 长度不超过现有 rule/template codec 的 1 MiB 上限时，保留一份有限解码副本。更大历史正文仍完整流式核对，但不整块积累、不只解析前缀、不以今日 codec 上限拒绝整份历史备份；结果为 `opaque_unverified / codec_byte_limit`。原正文保留责任始终属于调用者已拥有的 spool/数据库归档，返回观察没有复制或修改它。

未调用、重复/重入/并发调用 consume、短读、多尾、无进展、错误 n、取消、reader/外层错误或 panic 都无观察结果。外层 read 在 consume 已读完全部字节之后返回失败，仍丢弃整个候选。外层返回时若实际读操作活跃，取消并等待其结束，再处理结果；测试早退路径同样 cancel-and-join。任意不合作的底层 Read 无法被 Go 强制抢占，此合同没有虚构硬杀任意用户代码能力。

已退出的 consume 不再读取任何新对象或生成第二份结果。违约地在函数已经返回后调用旧 callback 只能获得 closed 错误；它不能倒撤已经返回的不可变原字节观察，因此上层必须遵守同步/禁止 detached work 的受信合同，并保留自己的整包发布栅栏。

## 已知格式、未知历史及冲突

分类至少明确区分：

- `explained_unverified`：已知完整有限数据形状及必要身份关系已解释；**未验证来源真实性、历史算法实际采用情况、当前执行支持、依赖取得或整个闭包**。
- `opaque_unverified`：未知 schema/shape、部分或非 canonical 旧表示、未知模板 codec、未知嵌套 manifest、超过有限 codec buffer。原 Source 和完整原 hash/bytes 保留，Dependencies/Members 为空；不能把它记作没有依赖、语义全覆盖或可恢复执行。

未知 schema 不递归寻找名字类似 version/hash 的字符串，不用这些未知字段制造冲突或猜出当前 tokenizer。对**完整确知 canonical codec**，原 manifest version 与行 version 不同、scoring 的 TokenVersion/TokenRulesHash 不对应原 TokenRisk、scoring BehaviorVersion 与外部原 BehaviorVersion 不同、已知必需身份为空/非法 hash 等都失败，不能将真实冲突降为 opaque。

原 `Manifest` 与 RuleArtifact 包装的完整 shape 通过当前有限结构和精确原 canonical 再编码核对；不调用 `defaultManifest`、`Parameters`、`Builtin`、`NewResolver` 或今日 `kernels` 准入来替换历史输入。历史 status、未知 implementation 标签、今日开发参数准入不接受的有限数值仍可作为原声明观察，既不提升信任，也不执行。

模板使用真实 `templates.Decode`。已知模板成员输出只包含 `(org, container version, container SHA, member ID, member version)`；prompt/assertions 始终在原模板载体里。未知模板只能说明原字节已观察，不能证明任何成员。

## 依赖身份、参数 hash 与实际载体

依赖带 Scope、OrganizationID、Category、Version、HashRole、SHA256、Basis，不存在跨组织仅按 version 索引的共享 Resolver。

| HashRole | 原来源/意义 | 不允许的替代 |
|---|---|---|
| `template_container_content` | 原 Manifest.Template version/content SHA；组织资源 | 其他组织同 version、另一个同名容器 hash 或 member version |
| `tokenizer_configuration` | 原 Manifest.Tokenizer version/config SHA；安装资源要求 | rank 文件 SHA、整份 installed carrier SHA 或今日 builtin |
| `scoring_parameters` | 原完整 Scoring 有限结构的 JSON 语义 SHA | 原整包 rule SHA、installed 参考 carrier SHA |
| `tokenrisk_parameters` | 原完整 TokenRisk 的 JSON 语义 SHA，与原 Scoring.TokenRulesHash 对照 | 词表/config SHA、今日 tokenrisk 默认参数 |
| `implementation_version` | 原 generator/features/structure/behavior；包装存在时还有原 analyzer implementation | 声称载体含实现二进制、用 SourceCommit 字符串证明已取得旧发行物 |

参数摘要使用**现已冻结的实际 scoring/tokenrisk Rules 结构及其 JSON 编码公式**，与真实 RulesHash/hashRules/Engine 构造相同；输入是原参数，不调用今日默认构造。Basis 固定为 `derived_known_json_codec`，区别于直接保存的 `declared_original` 引用。它证明这些原有限字段在该已知 JSON codec 下的摘要，**不是历史 writer 曾计算/采用了该摘要或某个未知历史实现使用同样 hash 算法的证明**。无法解释的旧形状不产生参数摘要；执行真实性和历史实现支持仍是未知/未验证的独立阶段。

提供四个精确纯匹配函数：

- 模板依赖：必须提供另一个真实观察结果，核对同组织、原版本、原内容 hash，返回该原对象的 carrier 身份。opaque 容器可匹配字节，但分类不会改变。
- 模板成员：必须已成功解释模板，完整五元身份精确相等；仅载体 hash 相同仍不能替代成员存在验证。
- tokenizer：必须提供真实 opaque `InstalledArtifact` 能力，匹配其 Ref 的原 Version/ConfigurationSHA256，再返回不同角色的实际载体 SHA/Bytes。nil/zero 对象、旧缺失版本、正确版本错 config hash、把 carrier hash 冒充 config 均显式 unavailable。
- installed scoring 参考：只可选地匹配真实 `InstalledScoringArtifact` 所带**原参考 rule**、参数 version/scoring/tokenrisk 摘要；不能满足不同租户的历史候选参数。租户参数本就在它自己的原 rule 中保留，参考匹配失败不应删除、覆盖或替换它们。

匹配函数没有搜索/下载/default fallback；签名不接受调用者凭空创建的 installed Ref 字符串。返回 binding 仍只是已观察字节身份映射，collector 必须真正把该原载体归档；它不包含依赖闭包 Complete、真实性 Verified、执行或授权方法，也不承诺 generator/features/behavior/structure/analyzer 的历史代码已经存在于数据载体中。

## 实际验证（纯层、未使用数据库）

真实正向包括 Builtin 原 bytes、templates Canonical/Registry/Decode/Find/Render、DevelopmentArtifact 修改准入参数后 Canonical/Decode/实际 compiler Engine.Hash，tokenizer 实际 rank/config 载体，以及实际 installed scoring 原参考载体。各自原 version/hash 与观察、绑定一致，hash 角色不同；不是只用任意字符串或伪造 carrier struct 作正例。

历史反例包括两个组织同名不同模板/参数、同 org/version 不同原 hash 的独立观察不被 process version map 合并、未被任何 Run 使用的旧/retired 原 shape、未知实现、今日不接受参数、部分/非 JSON/空原 bytes、未知嵌套语义。该纯层不判断这些独立原观察能否同时满足数据库 UNIQUE 约束；同快照 SQL 库存的唯一性规则仍由原 observer 保持，未新增或规避 SQL 规则。

24 MiB 原 opaque 流实际完整消费，reader 最大请求 64 KiB，测得调用期间 TotalAlloc 小于 2 MiB；不是把源读进内存后再拒绝。少 1 byte 总源预算在读取前失败。晚读错、读完后外层错/取消/panic、nil/typed-nil、panic(nil)、非法 n、重复/重入/真活跃读取的取消等待均实际封闭。source/ref/member/binding/observation 的值和指针格式化与 JSON/YAML 序列化封闭；输出 slice 是独立副本。

- 首次完整实现 compile-only：5d862d，terminal 0，bundle 0.125s；匹配接口完整后 ea884a terminal 0，0.123s。
- 第一轮真实 producer/载体/历史内容专项：99dc19，terminal 0，0.393s。
- 补生命周期和大流后专项三轮：c1fe9f，terminal 0，0.730s；全部匹配补充后专项三轮：1007fe，terminal 0，0.740s。
- Windows vet/lint 首次真实红：892182，固定 `tokenizer_configuration` 角色被 G101 误认为硬编码凭据，及 QF1001 等价逻辑风格建议。仅对该常量加精确无密钥说明、等价改写 hex 检查，未关闭全包规则或改变验证语义。
- Windows bundle vet/lint 复验：799136，terminal 0，0 issues。
- **完整 bundle 包三轮：648ec8，terminal 0，0.922s。**
- **`GODEBUG=panicnil=1` reader/outer panic(nil) 专项三轮：ae13b4，terminal 0，0.140s。**
- **Linux amd64 bundle 测试交叉编译与 vet：5a66af，terminal 0。** 仅交叉编译/静态，不是 Linux 原生或 race。
- 最终补非 canonical、重复/大小写 alias、未知嵌套 runtime，以及已知模板与原行 version 冲突后：**完整 bundle 三轮 + Windows vet/lint：b9f017，terminal 0，0.751s，0 issues。** 生产四文件未因该补测改变。
- 最终相同源码的 `panicnil=1` 两类专项三轮（0.120s）及 Linux amd64 交叉编译/vet：**0e1c38，terminal 0**。未执行 Linux 二进制。

这些是本单元实际纯层证据，不是双库/完整同快照 collector、完整备份/隔离恢复、Linux 原生、远端 CI 或 M6/M7 验收。既有 manifest v1/v2/v3 没有被扩展为通用闭包协议；未知历史来源/实现及联合预算如何写入后续受认证闭包记录，仍由最终协调器协议明确处理。

root 集成复核：全文读取四个生产文件、三个测试文件、本文及实际 Manifest/载体身份定义，未发现阻断问题；统一 gofmt。组合三轮 `go test ./internal/integrity/bundle ./internal/integrity/backupmanifest ./tests/contracts -count=3 -timeout=3m` 实际通过，分别 1.197s、3.367s、1.480s。bundle/repository vet 通过；同次联合 lint 被另一个未提交 input 引用测试的两条 G101 阻断，不记为全仓 lint 通过。

四个新增 production 文件、三个新增测试文件和本文档现已停止编辑，供根任务完整复核；无后台测试或数据库命令继续运行。
