# M6-05：Run / Estimate / Baseline 原始制品引用观察

2026-09-10。第一阶段私有观察单元，**不是完整 artifact 闭包、完整备份、恢复或正式审核批准**。本单元没有数据库写入、归档发布、资源下载、业务入口、规则发布或恢复启用接口。

## 原要求与已经核对的实际来源

PRD SYS-008 要求系统内配置/数据备份及恢复校验，RUN-004/15.1 要求冻结版本和历史可复现；TECH SPEC 19.5 要求数据库、报告、规则版本、配置模板一起备份并完成干净环境恢复；开发计划 M6-05 的交付仍是完整双库备份与恢复，不是只记录当前 builtin 版本。

本轮逐项检查 `domain/execution.go`、`repository/execution.go`、`run_estimate.go`、`baseline_models.go`、`baseline_repository.go`、`baseline/service.go`、generator manifest/replay、foundation/7/9/12/18 migrations，以及现有原字节 artifact inventory、installed tokenizer/scoring 载体和 manifest v2/v3。未改变这些实现。

- Run 保存四个 SQL 版本、`config_snapshot.plan.versions`、原 manifest 字节及 hash；实际 generator 的 manifest 保存 rule/scoring **版本**，template/tokenizer **版本与原 hash**。没有 rule 内容 hash 或 scoring 参数 hash 的字段，不能从空缺创造历史证明。
- Estimate 从 migration9 引入；其原 writer `estimateSnapshot` 要求非空 manifest，并在保存前验证预算已经冻结。之前 key 单元已核对引入提交 `5b84e45` 的 writer/decoder，从引入起都要求 manifest；没有补写历史 manifest 的 migration。本单元不把 estimate 缺失 manifest 降级为合法旧 Run。
- Run 低层 `validateExecutionPlan` 明确保留无 manifest 的 legacy plan；migration18 原样将老行标为 `legacy_response_v1`。实际 migration fixture 的 `{"legacy_fixture":true}`、四版本 `1` 不包含当前 plan，不能重建/重签。
- 原低层 writer 的 sample ordinal 只要求在每个 probe 内唯一，另行分配 execution ordinal。旧数据可能存在跨 probe 相同 ordinal 或不从零连续的 ordinal。新编译器的 manifest 才具有全局有序 ordinal；两种观察路径分开。
- Baseline scope 使用原 Go 字段名，例如 `SchemaVersion`、`Versions`、`TemplateHash`，嵌套四版本为小写键。`ParametersHash` 是探测条件/分布摘要，**不是 scoring 参数摘要**。
- migration12 对旧 baseline 明确加入 `snapshot_json='{}'`、四个空来源/快照/参数 hash 及双 NULL approval 字段。原 approved 状态不能继承信任；合法默认组合保留为 `legacy_incomplete`。部分默认组合、单 NULL approval、signed 空 scope 不得使用该例外。完整 scope 双 NULL 时仍完整观察引用，但继续标未验证。

## 私有接口与同快照边界

只新增 `snapshot_artifact_references*.go` 及本说明。入口：

- `Store.snapshotArtifactReferences(ctx, tx)`；
- `snapshotArtifactReferencesLimited` 只允许收紧 distinct-reference 预算，供组合层/测试使用。

必须是真实 `*sql.Tx`、deadline、匹配方言及现有 RO 隔离检查；SQLite native 物理只读仍由调用者在 BeginTx 前核验。使用 `NewDB` 清除外部查询条件；不访问 Store pool、不创建/结束事务、不带 status/TTL/组织启用筛选。

全部 Run、Estimate、Baseline 按 `(organization_id,id)` 分页，每页 100 行。每源先统计全部行并显式检测重复全局 ID，结束再与实际观察行数比对；NULL/非正 ID、跨页重复/缺行不能被 keyset 隐藏。没有任意总历史行数上限。

结果仅包含去重引用、三源精确行数/legacy 计数、分类与逐源观察 SHA-256，不保留 source 正文、Endpoint、请求、响应或 MAC。正文只在一行验证期间有界读取，之后清除借用 byte slice；这不是 Go 堆上所有 JSON 临时字符串的强制清零保证。

distinct 上限沿用 `backupmanifest.MaxEntries-3` 的有限预算，**仅是本单元内存/结果预算，不表示已经通过最终 manifest 的共享条目、总字节与 framing 预算**。同组织相同版本但不同原 template hash 不归并；不同组织同版本更不归并。引用包含 rule/template/scoring/tokenizer 和带原 bundle 容器版本/hash 的 template member，不把模板成员版本误当 bundle 版本。

各来源摘要使用固定域 `mii.snapshot.artifact-root-observations.v1`，固定类型/字段顺序的 JSON 记录，再以 8 字节大端长度 framing 写入 SHA-256。包括原 SQL 身份/版本/hash、原 body SHA-256、legacy 分类及收尾计数。不同原 body 的空白等字节差异不被 canonicalize 消除；相同原逻辑来源在 SQLite/PG 上摘要一致。该 SHA 是观察摘要，**不是参数 hash、MAC 或真实性证明**。

## 本阶段校验内容

1. SQL 先检查实际类型、ID、组织/目标/来源 Run/result 关系及文本字节上限；不先将超长 body/version/hash 传到 Go。Run/Estimate body <=8 MiB、manifest <=2 MiB、Baseline scope <=200 KiB、仅为 baseline 原来源摘要读取的 result <=4 MiB。坏长度、NULL 和动态类型不会返回成功前缀。
2. 复用 `snapshotKeyStrictJSON` 的 UTF-8、深度、键预算、完整 duplicate/Unicode SimpleFold alias 校验，以及既有 narrow manifest 元数据检查；不导入 secret/generator/bundle 实现，不复制 MAC/AES/HKDF 或算法逻辑。
3. 当前 Run 的 SQL 四版本、plan 四版本、manifest 对应字段相同；plan/manifest target ID、组织、analysis source、目标 model/protocol/parameter 不矛盾；原 manifest byte hash 同时匹配 SQL/plan 声明。当前 plan sample ordinal/member 与原 manifest 逐项匹配，而不是只做 DISTINCT 成员集合比较。
4. Baseline 原 scope 字节 hash 与 SQL snapshot hash 一致，原 schema 的精确 canonical 字段不接受大小写替代；scope 与 SQL org/run/revision/model/protocol/来源 hash 相同。再同快照读取原 Run，核对四版本、template/tokenizer hash、target 及冻结目标 metadata，比较完整 template member 多重集合，并将所保留 result 原字节 hash 与 scope/列声明核对。不要求当前评分版本，不按有效/过期/退役状态筛掉记录。
5. 任意查询、hash/身份/类型/分页/预算/取消/迟发错误返回零值结果。私有结果和引用 fmt/slog 固定摘要，禁止隐式 JSON/YAML；不会把 SQL/正文错误携带到结果。

## 明确未完成的后续闭包

- 没有核对 rule/template 库存里的实际原正文是否满足这些引用；没有解析原 rule 的完整模板/tokenizer/评分实现依赖。
- 没有遍历所有 result revision、持久 S1 derived、Probe/Finding/Report 投影的依赖；本阶段读 result 仅为 Baseline 原来源 byte hash，不是结果 schema/算法认证。
- 没有连接 installed tokenizer/scoring carrier。历史 tokenizer 配置 hash、评分参数 hash 与安装 carrier 文件 hash 必须分别映射；不能用当前 builtin 或一个全局 version-only resolver 替换各组织原参数。
- 当前 generator/scope 未知 codec 返回显式 Unsupported；超过所支持结构预算或不符合已知当前格式也不构成历史迁移/修复授权。合法 opaque 旧资源与缺失依赖仍需兼容清单和隔离恢复策略；manifest v3 只新增 legacy reports，并不解决全部历史 artifacts。
- 不验证 manifest/Baseline MAC、密钥真实性、资源可用性、正式发布/校准、归档成功或恢复安全。`snapshotReferenceObserved` 仅表示本单元观察完成；`snapshotReferenceLegacyIncomplete` 保留缺少当前证据的合法旧根，不把它升级为恢复可启用。

## 实际验证与失败记录

固定 Go 1.26.7；按 root 授权独占 General PostgreSQL 时段，仅从 ignored `.tools/test-postgres/dsn.txt` 读取现有 DSN，不输出 DSN，不启动/重置数据库，不操作 Backup。各 DB 测试使用现有真实 SQLite 文件和隔离 PG schema；原 30 秒 RO fixture / 5 分钟命令期限未放宽。

- 第一版生产编译通过；新 external fixture 曾把实际 `SecretMetadata` 写成 `SecretRecord` 而编译失败，随后按原类型改正。初始纯测试通过 0.270s。
- 对照原 writer 发现旧 probe-local ordinal 会被初版误拒，最小纯红 **0.096s**；分离 legacy/current ordinal 后全部纯三轮 **0.298s PASS**。
- 首次真实双库命令失败 **3.066s**：新 fixture 未在生成 manifest 前冻结 policy（实际估算 writer 正确拒绝 stale），历史 SQL 目标漏填 NOT NULL secret_id。修夹具未改生产 policy；不是产品缺陷的红绿证据。
- 第二次真实双库失败 **3.736s**：新历史 SQL 行漏填原 request/token budget，且迟发故障 callback 匹配了错误 GORM table alias；按真实列/查询修正。一次错误 callback 流程伴随 PG rollback 清理报错，未记为通过。
- 修正夹具后全部初始双库 **4.842s PASS**。扩展全部 offline NULL/类型/长度/重复/跨租户及 source 故障后单轮 session44427 **15.454s PASS**。
- 自复核发现 Baseline 的 scope/列 model 一起变化并重算 snapshot hash，会绕过初版与原 Run 目标 metadata 的核对。真实双库红 **1.021s**；补 plan↔manifest 和 Baseline↔Run 原 metadata 校验，并检查旧 baseline 的实际来源 result 存在性。
- 最终 `go test ./internal/integrity/repository -run '^TestSnapshotArtifactReferences' -count=3 -timeout=5m`：真实 SQLite/PG **49.777s PASS**，session15296 terminal exit 0。包括真实签名 compiler 的 legacy/derived 纯路径及 derived Run/Estimate 实际保存、四状态 Baseline scope 原字节、101 组织/分页/disabled、各状态旧 Run、过期 estimate、exact distinct / +1 超限、独立连接提交同视图不漂移、原 body 字节变化摘要不同、migration11→21 原 baseline 默认组合、跨双库稳定摘要、全部来源约束移除副本上的 NULL/重复/动态类型/超长值、原 source result 改写/重复、Unicode aliases、迟发漏行/取消/实际 rollback。
- Baseline/result 的 SQL 测试夹具是符合原 schema、使用现有 `baselineJSON` 的结构性记录，不冒称已通过真实 Baseline service、真实 analyzer 或 MAC 认证。当前单元只观察这些原引用/摘要。
- 同期完整 repository lint session83757 terminal exit 0：`0 issues.`。此后 DB 时段明确交回 root，无本单元后台测试。完整包/跨模块、外层 PG 接线和远端 CI 由 root 独立验证，不以本单元专项代替。
- DB 释放后仅补本说明；完整 repository Windows vet、Linux/amd64/CGO=0 cross-vet 均 exit 0；Linux cross-lint `0 issues.` / exit 0，全部新 Go 文件 gofmt 检查无输出。交叉静态检查不是 Linux 原生测试，也没有运行 race detector。

M6-05 / SYS-008 与完整开发 Goal 继续进行中，正式审核仍待完整开发后统一进行。

## 独立复核修正：模型名的字符／字节兼容边界

2026-09-10 后续限定修复，不以前面的通过记录替代本次验证。

独立复核发现确认 P2：plan/manifest 对照和 Baseline SQL 投影把 model 限为 128 **字节**，
会拒绝真实 writer 已允许的值。`target/service.go` 的 `safeText` 按 128 个 Unicode 字符；
`generator/generator.go` 的 `validateOptions` 按 256 字节；
`repository/target.go` 的 `validTargetRecord` 按 512 字节。
例如 43 个“模”是 43 字符、129 字节，公共目标输入及真实 compiler 都允许，原库存却拒绝。
这些不同边界不能用当前生成器的较窄限制覆盖低层仓储已保留的历史。

修复仅给 model 引入与实际仓储 writer 一致的 512 字节常量，并同时用于双侧 model
对照和 Baseline SQL CASE/类型/长度预检查。保持原值精确匹配，不截断、不重新编码或补写
原行。protocol/max_output_parameter 保留既有 128 字节双侧一致性边界，Baseline protocol
SQL 仍为既有 32 字节；本次不顺带收紧其它历史字段。root 的最后查询收尾及 legacy ordinal
修复由 root 独立负责，本修复没有覆盖这些行。

新增专属 `snapshot_reference_model_compatibility_test.go` 和
`snapshot_reference_model_compatibility_actual_test.go`：

- 真实 `Generate` → MAC 验证的 `ExecutionPlan` → 实际仓储 validator → Run/Estimate
  纯观察，覆盖 ASCII/Unicode 的 129/256 字节及 legacy/derived analysis source。
- 真实授权 `UpdateTarget` → `SaveRunEstimate` → `CreateRun`，双库覆盖正常 compiler
  的 129/256 字节 Unicode，以及低层仓储 512 字节 ASCII/128 个四字节 Unicode 字符。
  超出 256 字节的 manifest 是明确标注的低层结构性历史 fixture，不声称由当前 compiler
  生成、通过 MAC 或能够立即执行。
- Baseline 使用真实 `baselineJSON` 编码及数据库原列，是双 NULL approval 的未签名
  结构性 fixture，不冒充真实 analyzer/Baseline service。范围完整且引用可观察时仍标
  `legacy_incomplete`；直接检查 SQL 投影与 scope 的 model 原字节不变。
- 513 字节 model 在 SQL 中变为拒绝标记/空投影，不传入 Go 候选；全观察失败零结果。
  纯层也拒绝 513 字节和两侧不同的 256 字节 model，不以放宽长度削弱身份绑定。
- 再读原 Run/Estimate/Baseline 行，确认整个观察没有改写源 JSON 或 model。

实际证据（固定 Go 1.26.7，Windows 原生双库）：

1. 先仅新增真实 compiler 红测：`^TestSnapshotReferenceModelCompatibilityPureActualCompiler$`
   **FAIL 0.285s**，exit 1；四组合法 129/256 字节输入均在库存返回 Invalid。
2. 两处 model 修正后全部模型纯测试三轮 **PASS 0.459s**，exit 0。
3. 首次尝试 DB 命令被其它在建 result-reference 文件的缺失函数阻挡，编译 exit 1，
   未运行任何 DB 用例；等待该单元恢复可编译后继续，没有修改或绕过其代码。
4. `go test ./internal/integrity/repository -run '^TestSnapshotReferenceModelCompatibility' -count=1 -timeout=5m`：
   双库 **PASS 4.594s**，exit 0；最终相同范围三轮 **PASS 11.804s**，session84640 terminal
   exit 0。随后明确释放 General，没有后台测试、服务或 Backup cluster 操作。
5. 释放后仅运行既有 artifact 纯测试与模型纯测试组合三轮，**PASS 0.459s**；
   Windows `go vet ./internal/integrity/repository` exit 0。全仓储 lint 本次 exit 1：
   35 项均来自同期未接测试的 `snapshot_result_references*.go`（34 unused、1 QF1001），
   本修复文件无诊断；不能把这一轮整体 lint 记为通过。由集成方在其它单元完成后复验。

除本次 model 及另交 root 处理的 legacy ordinal/最后查询边界，未另确认新的 P1/P2。
模板 member/ordinal 和 Baseline 多重集合只验证本单元
声明的根引用关系，不是 Variables/ParametersHash/MAC 或物理 Probe/全部 result 的完整闭包。
合法 opaque 旧根、资源实体解析、隔离恢复与整个 SYS-008 仍须继续完成。
