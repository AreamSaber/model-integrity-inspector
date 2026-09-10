# M6-05：剩余快照资源闭包设计

2026-09-10。基于当前工作区及已提交的备份操作读取 `5c89286` 之后的只读源码核验。本文只设计剩余资源闭包，不实现生产或测试，不改变任何已冻结 observer、迁移、全局计划或审核状态。本轮没有读取 DSN、运行数据库、调用网络或进行 Git 操作；下述测试是实施要求，不是已经取得的测试证据。

## 1. 结论与范围

还不能把现有 inventory 的组合称为完整资源闭包，但也不需要为每张业务表再造一个相同 observer。最小增量是：

1. **解析已经复制的原 rule/template 内容并建立真实依赖映射**，包括未被任何 Run 引用的保留版本；不重新做全表 artifact 字节库存。
2. **补两类独立历史根**：全部 Findings 的原规则成员身份；全部 S1 derived 尝试的原提取器/模板/tokenizer 身份。
3. **补现有 Run/Estimate 的小型嵌套边**：manifest 的每个 `input_estimate` 身份，而不是再扫一遍 Run 表建立同样库存。
4. **一个固定来源的残留投影/历史覆盖阶段**：物理 probe/attempt 镜像、非 ready 的 report source、旧 projection/baseline scope/replay 字段。已知镜像只验证与已观察根的关系；无已知 codec 的非空原值保留为 opaque/unverified，不能以“当前 writer 不写”认定数据库一定为空。
5. 在单一快照协调器中连接以上结果、现有 installed 载体和共享 manifest 预算；把“原字节保留”“依赖已解释”“真实性已验证”“允许恢复运行”分开。

PRD SYS-008（PRD:263）、备份恢复验收（PRD:644）、TECH 19.5（TECH:1595）、AC-23（TECH:1763）和开发计划 M6-05（计划:197）要求数据库、报告、规则与配置恢复一致、密钥单独提供，不能只备份今日 builtin，也不能因遇到合法旧格式而永久拒绝历史备份。本文的“已覆盖”仅指明确的当前观察合同，不代表所有历史 codec 或全部业务图真实性已经验证。

## 2. 当前已经具备什么

| 当前单元 | 已经覆盖 | 不能据此推导 |
|---|---|---|
| `snapshot_artifact_inventory.go` / `snapshot_artifact_stream.go` | 全组织 rule/template 原行、原版本/内容 SHA、实际正文流；不筛状态、敏感级别或组织启用状态 | 正文中的依赖已解析、每个参数引用已满足、opaque 内容可执行 |
| `snapshot_artifact_references*.go` | 所有 Run/Estimate/Baseline 的四版本、已知 manifest 的 template/tokenizer 原 hash、模板成员及来源绑定；合法旧 Run/基线分类和原字节摘要 | rule 版本含原 rule 内容 hash；scoring 版本含参数 hash；每个 manifest 输入估算器身份已观察；所有物理 probe 都已被结果访问 |
| `snapshot_result_references*.go` | 所有结果修订及 published/unpublished；原 scoring/tokenrisk 参数 hash、features/behavior/structure 实现版本、结果样本模板和 tokenizer 身份及已提供样本的物理关系 | 全部 Findings、全部重试 S1、没有结果的样本已扫描；发布 writer 对参数使用提供了 MAC 证明 |
| `snapshot_complete_report_inventory.go` | 全部 ready 行；现代 source/hash/render 检查；历史 ready 行完整原列摘要和明确未验证分类 | 所有非 ready `source_json` 已解析；旧文件 locator 已映射；全部报告历史自动可重渲染 |
| `snapshot_key_inventory*.go` | 当前支持源的 required root-key version union，包括全部 S1 的 `key_version`；Run/Estimate manifest 原 hash/key 关系 | S1 payload 内资源身份已解释或 MAC 已验证；未知封装/段格式支持已完成 |
| tokenizer/scoring installed artifact | 实际已安装 tokenizer 词表及配置/实现元数据、实际 installed scoring 原参考规则载体，独立 expected ref 与从归档重建路径 | 任意历史版本 registry；同版本不同组织的原参数被一个 installed reference 替代；历史实现代码已经装入载体 |

这些单元的现有 byte hash、计数和分类应直接作为后续输入。相同源不要在另一实时连接重新读取，也不要给已有成功结果附加“全闭包通过”的新解释。

## 3. 逐来源判定

### 3.1 Findings：确有独立根，不能从结果反向假定

来源：foundation `integrity_findings`（`migrations/common/000001_foundation.up.sql:328`）；`repository/analysis_result.go:30,76,110`；真实 producer `worker/analysis.go:195`。

- 原列是 `rule_id`、`rule_version`，以及 org/run/revision、`statistics_json`、`sample_refs`、可空 `gateway_evidence_id`。当前 worker 写 `development.aggregate.<dimension>` 和 `document.Scores.Version`，statistics 是真实 `scoring.Dimension`；该结构没有单独参数 hash 或资源 locator（`analysis/scoring/types.go` 的 Dimension）。
- 但 `validPublication` 只要求规则 ID/version 满足原 execution label，statistics 是有界 JSON object；`PublishRunAnalysis` 不把 Finding.RuleVersion 绑定为 Run.ScoringVersion，也不把 statistics 与 document dimension 完整绑定。正常 worker 的映射不能被误写成低层存储协议已经禁止其他保留值。
- 因而必须观察 **全部 finding 行**，包括其他 result revision、未发布结果、disabled 组织。原 `(organization, run, analysis_revision)` 必须真实存在；提供的 sample refs 绑定同 Run 的真实 sample，不能因别的结果出现同 ID 而通过。当前 `sample_refs` 是 decimal-string 数组，不能猜成数值数组；原当前 writer 最大 256 findings/次发布、statistics 64 KiB，但这不是整库全部历史行数的限制。
- 私有 root role 应为 `finding_rule_member`，键至少带 org、原 Run 四版本、原 rule ID/version、源 result revision；**不要直接把 RuleVersion 当成 rule bundle version**。已知 `development.aggregate.*` 且原评分身份相容时可以连向该结果/原规则的 scoring 实现；未知成员或与当前 producer 不同的合法历史声明不能强行绑今日 aggregate。
- 未知统计对象只能保留原字段摘要并分类，不递归抓所有名叫 version/hash 的字符串当依赖。rule_id/version 列本身仍要完整观察。未知 statistics 不抹掉已提供的身份，也不提升到 current verified。
- `gateway_evidence_id` 是证据记录关系，不是评分参数文件；原 gateway 的签名/codec 未支持由现 key/恢复边界独立处理，不能凭该 ID 提升 A/B 证据等级。

推荐一个 bounded Findings 根 observer；不重跑 analyzer、不通过 `ListAnalysisFindings` 的 published/current 读政策扫描历史。

### 3.2 S1 derived：确有独立根，必须包括非最终尝试

来源：migration18 全文；`repository/execution_derived.go:28,52,95,144`；`analysis/features/derived.go:17,31,42,56,144,318`；`analysis/features/derived_auth.go`；`analysis/behavior/derived.go`；`worker/analysis.go` 的全部 derived row 绑定。

原表 `integrity_attempt_derived` 为 `(organization_id, attempt_id)` 主键，payload 1..32768 bytes，MAC 32 bytes。它是所有尝试的 S1，**没有 TTL/清理字段**。正文删除仅影响 S2；`response_retention_cleanup.go:271` 删除 response/display evidence，不删除 S1 或结果。取消、UNCERTAIN、recovered_unavailable、非最终重试、尚无结果的 Run 都可能保留该根。

原 payload JSON 路径如下；按真实小写 tags，不能借结果 PascalCase 模式猜测：

| 路径 | 含义/要连接的对象 |
|---|---|
| `version` / SQL `version` | `mii.derived-s1.v1` codec，不是 root-key 版本 |
| `scope.organization_id/run_id/sample_id/probe_id/attempt_id/job_id/number/ordinal/manifest_hash/request_hash/outcome_hash` | 绑定原真实 Run/sample/probe/Attempt/Job 和结果状态；历史 Attempt.JobID 是原 Job，不能要求等于重试之后 sample.job_id |
| `extractor.features/behavior/structure` | 各实现版本；目前原生代码仍属相应发布构建 |
| `extractor.tokenizer/tokenizer_hash/tokenizer_implementation` | 配置版本/hash 与实现标识，分别连接 tokenizer installed 内容和实现支持 |
| `extractor.template/template_hash` | 原模板容器身份；不能只看 feature 内单个 member |
| `feature.template_id/template_version` | 模板成员，连接原 manifest/physical probe 与模板内容 |
| `feature.local.bundle_version/bundle_hash/tokenizer_version/tokenizer_id` | 局部估算观测；启发式 `unicode-byte-v1` 与 extractor 的安装 BPE implementation 不是同一命名空间，不要求字符串相等 |
| `feature.structure.version`、`feature.behavior.version` | 已提供嵌套观测的实现版本，与外部 extractor 保持原 codec 关系 |
| `behavior_observation` | `[]byte` 的 JSON base64；存在时内部为 `mii.behavior-derived.v1`，含 `features.version` 和原 binding hash；不能当普通 JSON object 或跳过内部 codec |
| `source_hash` / `usage_comparison` | 来源字节/计数证据，不是安装资源 hash，不创建虚假的外部 artifact |

现结果只选权威 final attempt 的 feature；`BuildDerived` 却验证全部 attempts，再选 final，所以扫描结果不能替代此来源。现 key observer 只覆盖 SQL key_version，不能证明 payload 的这些引用已经观察。

存储层 `validDerivedRecord` 只约束 outer version/key/payload长度/MAC长度，不验证内部 canonical JSON；只有真实 features verifier 验 MAC 后解析并比对原 canonical。备份观察不得调用 `BuildDerived` 并强制所有旧 extractor 等于今天 `b.extractor()`。建议分离：

1. 同快照 bounded 原行/scope 观察和已知 codec 元数据解释；结果是未授权的资源根证据。
2. 由实际 purpose verifier 作原 MAC 验证（独立阶段，可由受限 capability 提供），不在 repository 复制 MAC 模板或导入上层导致循环。
3. 未知/历史未解释 payload 原样在数据库保留并分类。不能仅凭 migration18 的外层固定 version 推断每个内部 payload 必定由现 producer 生成。已解释字段冲突与未知 codec 分开处理。

对于 known current 结构要求原 scope/行/manifest 完整一致。缺少旧字段、未知 codec 的容纳政策必须依据实际旧 codec，不能自动补当前 extractor，也不能把 outer 长度检查当真实性证明。

### 3.3 Run/Estimate 输入估算器：补已有遍历的边，不建重复表 observer

`generator/manifest.go:86` 的 `Samples[].InputEstimate` 是实际 `tokenizer.Estimate`；`generator/generator.go:399` 调用真实 `EstimateInputFor`。其原 JSON 有 `bundle_version/bundle_hash/tokenizer_version/tokenizer_id/quality`（`tokenizer/estimate.go:37`）。

目前 `snapshotReferenceManifestMembers`（`snapshot_artifact_references_json.go:276`）只读取 ordinal/template member；上层只观察 manifest 顶层 tokenizer version/hash。输入估算的实现/encoding 身份尚未成为 observed refs。即使 Run 没有结果，或 Estimate 已过期未删，这些原元数据仍然存在。

最小补法是在已有 manifest 样本循环观察这些可用字段：已提供 bundle version/hash 与该原 manifest 相同；实现/encoding 用真实 tokenizer metadata 命名空间，区分 BPE 与 heuristic。不要把顶层 BPE implementation 强塞给 heuristic。未知缺失按存储/历史 codec 分类，而非重新调用今日 tokenizer 生成替代值。`generator.Projection` 只有数量/成本/时间/重试预算，没有独立资源身份；不为它建立资源 observer。

### 3.4 原 rule/template 内容：当前最大的闭包接线缺口

`bundle/builtin.go` 的 `Manifest` 明确包含：原 Template/Tokenizer version+SHA、Generator/Feature/Structure/Behavior 版本、完整 `Scoring` 和 `TokenRisk` 参数、行为最低条件、配对指标/alpha、limitations。`Scoring` 自身又有 `BehaviorVersion/TokenVersion/TokenRulesHash`；这些 hash 是参数语义，绝不是整包文件 SHA。

`bundle/artifact.go` 另外定义 `mii.rule-artifact.v1` 包装及 `implementation/manifest`。它是有真实 decoder 和纯层候选支持的数据格式；本次没有找到其生产 repository 持久写入口。现持久 seed 的 `validatedBootstrap` 要求根 `version/template/tokenizer/scoring`，`seedBootstrapBundles` 只写 development，不覆盖旧行。不能把纯层 DevelopmentArtifact/Resolver 测试说成当前数据库已经具有正式规则发布生命周期。

最小实施：

- 复用已通过 hash 的 artifact sink 原字节/私有 staging 文件，在有限 codec worker 中解释；不要重新在 live Store 查“相同版本”。原 opaque 大正文继续流式保留，不能先读入 Go 再用 1 MiB 当前 decoder 拒绝全部历史。
- 识别原 schema/shape 后提取 template/tokenizer、各实现、scoring/tokenrisk 参数关系；原 hash 与行 hash 不一致是数据问题，未知 schema/实现是兼容问题，不能退回 builtin。
- 把原模板内容与 `(organization, container version, container hash, member ID, member version)` 核对。`templates.Bundle` 已内含 prompt/assertions/member version，无独立文件 include/URL/表达式加载路径（`probe/templates/bundle.go`）。无需为每个 member 复制整个模板文件。
- 所有 rule 状态、未引用候选、退役版本仍需解释其自身依赖；不能只按 Run 所需版本提取而遗漏尚未使用的规则根。
- 以 **org+原版本+原内容hash+hash role** 为键计算依赖。当前 `bundle.Resolver` 的进程 map 按 version，并会拒绝同 version 不同 hash；不能把一个跨组织共享 Resolver 用作备份闭包索引。需要每组织隔离 resolver 或原内容身份索引，保留同名不同租户参数，不改写原版本来绕过冲突。

若原 Run 只有 rule/scoring 版本、没有内容/参数 hash，可证明同组织保留目录有该版本，并保留版本级关系；不能从今天该行推导历史上一定用了同一参数。结果提供的原参数 hash可加交叉证据，但发布 writer 没有给它独立真实性签名，此处不升级信任。

### 3.5 Projection/镜像/生命周期：统一残留覆盖，不机械新增 root

| 原保留来源 | 实际 writer 与现有覆盖 | 最小处理 |
|---|---|---|
| `integrity_probe_instances.template_id/template_version` | `execution.go:292` 从 plan 建原 probe；结果 observer 只核对结果引用到的样本/probe | 对全部 probe（含没有结果）作原 Run/manifest 成员镜像关系检查；已知现代一致时不生成独立容器/重复原文件。旧 Run 无 manifest/成员证据时仍保留原列声明的 member 根及不完整分类，不能只存 opaque 摘要而漏掉已知身份，更不能猜 container hash |
| `probe.parameters_json` | 当前 CreateRun 固定写 `{}`；ProbeRecord 不映射 result_json | 精确已知空对象无资源根；历史不同原值保留原字节/类型/null摘要，未知，不递归猜 codec |
| `probe.result_json`、`logical_samples.feature_json/rule_result_json` | foundation 可保留；全生产源码搜索未找到当前 writer/codec，当前 SampleRecord 也不映射这两列 | SQL NULL 是合法未写；非 NULL 不表示可按结果 schema 解码。纳入固定 opaque 原字段覆盖，不能静默跳过或直接永久拒备份 |
| `logical_samples.request_plan`、Attempt `request_snapshot` | 当前为 domain.SamplePlan/RequestSnapshot；请求正文与原 hash，没有新增 bundle/algorithm version；Job/结果/S1 只验证各自合同所需绑定 | 原 SQL dump 完整保存；按全物理图绑定需要核对原 plan/request关系，不为请求字符串里类似 version 的字样生成资源根 |
| Attempt `tokenizer_id/tokenizer_quality/local_completion_tokens` | `worker/execution_http.go:119` 保存实际 CountOutput 的 ID/quality/count；`execution_attempt.go` 当前 writer 不保存实现版本/config hash | 全部 attempts 的 encoding声明应在残留镜像阶段观察；有 S1 时与原 S1 对照。legacy-only 没有精确实现/version证据就保留不完整，不能从 ID 推出某个今日词表 hash |
| `integrity_reports.source_json`（现代 ready） | snapshotReportVerifyRow 已按原 source hash、四版本/原 Run、真实 report.NewDevelopmentSnapshot/render 验证；report validator 将 finding规则/版本绑定 scoring，并限制 encoding IDs | 复用已有检查和源摘要；不存在独立新 scoring 参数 hash。无需第二次重渲染或完整再扫 ready 行 |
| report 非 ready `source_json` | FreezeReportSource 可能在文件发布前保存，随后 failed/expired；低层 `report_source.go:203` 只检查私有lease与长度/hash，没有亲自解码完整 source | 在残留覆盖阶段处理；NULL 与成组合法未冻结字段不是错误；原 source hash、状态/行关系有可检查证据。已知 frozenReport 可以复用纯元数据 codec，未知原字节分类保留，不通过今日 renderer 强制判全部历史可用 |
| 历史 ready report 原 source/schema | 当前 complete report 单元已有20列原行摘要、明确 unverified；不能推定曾经由今日 renderer 产生 | 复用该原行证据；未知 source 保持兼容缺口，不另猜依赖；旧文件映射归报告文件单元，不在此重复 |
| 现代 Baseline `snapshot_json` | 第一引用单元已扫描全部状态及来源 result 原字节；ParametersHash 是条件摘要，不是评分参数摘要 | 不再建 Baseline 资源 observer；审批/MAC/真实使用门禁独立，不能从 approved/expired/retired 状态增减资源 |
| Baseline `applicable_scope_json` | foundation 原字段；现代 Create 固定写 `{"schema_version":"baseline.scope.v1"}`（baseline_repository.go:314）；migration12 没有改写旧 applicable_scope_json | 已知现代哨兵没有新增根；历史非哨兵可能有旧范围定义，原值未被现 snapshot_json observer 解释，应在统一 opaque 覆盖阶段分类 |
| `integrity_reviews` / `integrity_review_receipts` | 原 org/run/revision/reviewer、结论文字及幂等 hash；AppendReview 只追加，不改算法结果 | 数据库与审计完整保留；完整恢复需 FK/审计关系检查，但没有独立算法/规则资源根，不为解释文字中的版本词建立 observer |
| rule `status/published_at/replay_metrics_json` | bootstrap只写 development，不覆盖/发布/退役；未找到 replay_metrics 非测试生产 writer/codec；原表无状态枚举 CHECK | 全部原行留存；NULL replay 无新增根，非空 opaque replay 明确未解释，状态不授予校准/发布信任；真正规则发布/回放生命周期仍是开发计划的独立工作，不通过备份 observer 伪实现 |
| `model_profiles.tokenizer_json` | CatalogTokenizer 仅 ID/quality 声明；run/service.go:185 显式忽略该返回项，只取能力和限制；runtime选择实际安装映射 | 保留配置声明，不把此 ID/quality 当已验证 installed root，也不自动加载命名插件；未知旧 JSON按配置兼容处理 |

“无需独立资源根”不等于无需备份或不必做恢复图一致性检查。全部表和未映射列必须仍在真实数据库备份中。建议一个固定表/列清单的 residual coverage 结果，含每源总行、NULL/已知哨兵/已知镜像/opaque 分类、原类型与长度/原字节摘要；不是通用接受 SQL/路径/用户字段名的扫描器。

不能对 schema 无上限的 opaque 旧 TEXT 套用当前 64 KiB/4 MiB writer 限制。应优先 SQL 长度观察、流式原字节摘要，最大资源/归档预算由协调器控制；超出当次预算是显式 limit，不截断后记完成。

## 4. 必须保留的安装资源与历史支持边界

| 资源 | 当前真实可归档载体 | 历史和实施限制 |
|---|---|---|
| 每组织 rule 参数/manifest | 原 content_json + 原行 identity/hash；已有 artifact stream | 全状态、全部原版本；不能用 installed reference 替代租户参数 |
| 每组织模板 prompt/assertions/成员 | 原 template content_json；已有 artifact stream | container版本/hash和member版本分开；同版本不同组织不同字节都留存 |
| tokenizer 配置、实际 rank 表、regex/heuristic/framing语义和 notices | `tokenizer.InstalledArtifact`：实际 boundedBPE.ranks、cl100k/o200k、原配置/实现元数据/notices，外部 expected InstalledRef | 当前 verifier只支持当前冻结配置与实现，不是所有历史codec仓库。原 config hash≠carrier hash，encoding ID≠实现版本 |
| installed评分参考参数和限制 | `bundle.InstalledScoringArtifact`：实际 a.rule 原参考字节、scoring/tokenrisk参数hash、工作限制、外部 expected Ref | `scoringRuntimeFromOriginal` 固定当前 BuiltinHash；NewReferenceRuntime 不是历史租户 resolver。原rule hash、scoring hash、tokenrisk hash、carrier hash各自不同 |
| features/behavior/structure/generator、report canonical/CSV/render 实现 | 匹配应用发布构建/源码身份；现数据载体保存部分原版本与参数引用 | 当前 behavior 英/中文 refusal/identity 模式直接在 `analysis/behavior/analyze.go:8` 编译为正则；没有独立词表文件/数据库字典。不能写“scoring载体已打包这些实现代码”。需要匹配的发布实现才能执行；只有 SourceCommit/ApplicationVersion 字符串也不等于已经保有可安装历史发行物 |

行为规则中部分有限数据是代码内正则/契约策略，模板 Bundle 不是额外词典包；不要凭 spec 的“词表”概念发明现仓库没有的文件。最低实现兼容方案是保留对应发布构建及既有许可证/组件清单、恢复时精确确认支持的 implementation。若后续要把这些代码内有限数据外置，须另立版本化 installed semantics 载体并验证真实运行消耗其原数据；不能在本闭包里临时复制常量后声称已经归档实现。

对于未来真实已安装多个版本，应由启动时受控安装资源 registry 给出原 owned bytes+expected ref；缺版本就明确 missing/unavailable，不调用 NewBuiltin 或下载未知代码补齐。未知历史数据仍可在隔离恢复中原样保留，运行/重算另受支持矩阵控制。其缺失不得伪装为参数校验通过。这里的匹配发行物是实现兼容前提，不擅自扩大当前数据备份格式为任意二进制/代码上传入口。

## 5. 协调器的最小私有协议

建议保持三种身份而非一个 version map：

- 原来源身份：source kind、org、row/复合键、result revision/attempt identity、原字段字节摘要和分类。
- 资源身份：scope、org（租户资源时）、category、原版本、原内容hash/参数hash **role**、container/member 或 implementation qualifier。
- 实际载体：受控 EntryID、实际 bytes/SHA、已观察资源身份到具体 carrier 的映射；不存在任意文件路径或用户自填当前版本的“resolver”。

推荐私有 source kinds/roles，具体命名待实施冻结：`finding_rule_member`、`derived_extractor`、`input_tokenizer_observation`、`stored_projection_coverage`；已有 `scoring_parameters/tokenrisk_parameters/tokenizer_configuration` 等角色复用，不能以 bodySHA 代参数hash。每个来源完整扫描只一次，重复资源在有界 union 中去重；不能任意限制全部历史行数代替分页。

实现归属：repository 负责同一个实际只读 `*sql.Tx`、SQL 预界、计数/keyset/关系和原字节借用；bundle/features 等已知 codec 的原资源解释由对应包的最小有限数据接口或上层受控 collector 完成。避免 repository import generator/secret/features/bundle 形成循环；不把缺失循环依赖问题“解决”为在 repository 复制 MAC 或评分算法。借用 callbacks/文件必须承接已有 sticky failure、单次消费、取消/EOF/hash/终结后的封闭保证。

所有 observer 使用同 snapshot、deadline、NewDB/no Store pool、每页100、重复键/孤儿/NULL/实际类型/原 native integer 范围验证、末尾真实查询与精确计数。source摘要采用固定域+类型+长度 framing；所有子单元失败使协调器无 candidate，不返回成功前缀，不发布 staging。

分类至少区分：已观察已解释、合法旧证据不足、未知codec原字节保留、真实依赖未取得；资源真实性/MAC验证结果和恢复执行许可另列。跨字段提供的真实冲突不因 legacy 而被忽略。尚未解析 opaque 数据时不可写“完整语义闭包”；但可以表达“原数据库字节完整保留、这些旧源明确未验证”，供隔离恢复使用。

### manifest 需要的表达能力，不假装 v3 已具备

现 `backupmanifest.Manifest` 没有通用 resource-closure/opaque-source 分类；v3 只新增 legacy reports。`Artifact` 只允许四类别，并且 `scoped_artifacts.go` 对 installed 使用 category+version 唯一，没有 implementation/hash role identity。当前一个 tokenizer/scoring frozen版本可以映射；未来同版本标签不同安装配置不能通过改版本名绕过限制。

最小原则是先形成私有闭包候选，然后为**确有必要的历史分类/身份**设计明确向后兼容的新 manifest 格式或受认证的固定闭包记录，保持既有 v1/v2/v3 canonical 字节不变。原 DB 文件 SHA 能认证其全部字节，但并不自行解释缺失资源、opaque来源或历史执行支持。是否把完整边列表、逐源摘要/计数/分类与具体文件ref怎样编码，应在最终协调器协议确定时一起冻结，不能先往现 v3 任意塞自由 JSON。

共享上限统一扣除 database、reports/legacy report frames、tenant artifacts、installed artifacts、configuration、closure记录、manifest以及archive framing；不能把每个 observer 的 MaxEntries-3 分别用满后仍称全局有界。已有 key union再由协调器加入最终归档sealer active版本，沿用 max64；不在 SQL 猜 active，不把 immutable AAD 的 payload_key_version误加入 required。

## 6. 最小实施顺序与真实验收设计

1. **先完成原 artifact→dependency→installed 映射纯层**。复用现 artifact stream 和 installed载体，只给已知codec增加有限的原资源身份提取/关系结果。两个组织同version不同模板/评分参数必须分别满足各自引用；缺少旧tokenizer、正确version错误hash、把carrierhash当config/parameterhash、未引用退役规则自身依赖缺失均失败或显式未完成。未知opaque原字节不被今日decoder改写。
2. **补最小 source 根**：manifest input_estimate 小补边，及一个 Findings observer；然后一个全 Attempt S1 observer。共享有限身份/摘要工具，不复刻原已完 Run/result读策略。真实 producer→writer→同快照观察为正向；storage-only允许的历史变体须独立标注，不冒充真实算法结果。
3. **做一个残留投影覆盖阶段**，限定前述固定表/列；与现 ready报告/基线证据拼接，现代镜像不新增同样资源副本。未知旧列先保留原摘要/NULL/类型分类，并明确恢复不启用，不展开通用 JSON 猜测器。
4. **将闭包候选接最终统一清单/归档预算与验证**；最后才认定本快照的资源保留覆盖，随后仍须真实原始 Secret/MAC/审计、报告文件、完整数据库导出、归档读回、授权完成和隔离恢复验证。

必要真实双库测试（本轮未执行）：

- Findings：真实 analyzer publication；全部修订、未发布、无当前version假设；独立 old RuleVersion；同名rule不同org；sample_refs原字符串ID、跨租户/孤儿/重复；未知stats保留；101行/末行坏数据/取消/rollback全零。
- S1：真实 DeriveAttempt→Seal→FinishAttemptWithDerived，全attempt含非final retry、UNCERTAIN recovery、业务取消、无结果Run；删除全部S2后仍观察全S1；未知extractor/codec、原MAC与scope/请求/Outcome绑定阶段明确；原Attempt.Job与sample当前Job不同的合法重试保留；base64内部behavior版本、heuristic与BPE身份分别验证。
- 输入估算：真实 Generate→SaveRunEstimate/CreateRun，无结果及过期Estimate；当前BPE/heuristic真实输出，改nested config/hash/implementation，当前outer hash匹配但nested声明冲突，已提供字段NULL/case alias，结果全零或正确历史分类。
- 残留列：从foundation/m12/m14/m18实际迁移得到的NULL/哨兵/非空旧值；现代/旧Baseline scope、non-ready frozen report、无result probe；原bytes和类型不变。不得为未知旧TEXT随意套当前writer上限并声称完整兼容。
- 所有新根：完整分页、跨页重复、不活跃组织、全源union精确边界/+1、同物理事务另一连接提交不漂移、SQL长度预界、取消和最后读取后真实rollback、吞错/迟发错误零候选；SQLite原生整数能力不被无证据地收紧为PG int32。

现 Baseline observer 对 revision 仍有 int32 范围（snapshot_artifact_references.go 的 SQL投影），foundation SQLite 原 INTEGER 只有正值语义；这是本轮静态看到的既有历史兼容边界，未以新数据库反例确认/修改。后续明确支持历史native revision时须验证该路径，不能因结果单元已支持native revision就推导基线也完全支持。

## 7. 完成条件与不属于本轮的事项

本设计完成的是精确来源划分，不是 M6-05/SYS-008 验收。不存在“有一个成功的 root inventory 就可忽略未知保留字段”的默认。完整协调器必须能说明每个固定来源为什么已解释、只是镜像、或明确未知，并真实保留相应原数据/载体。

规则发布与校准、人工审批的信任升级、未知历史实现的执行、已清除S2的重建、网关签名兼容、sealed audit segments、旧报告文件locator映射、完整恢复与原子启用、CLI/HTTP/UI和灾备演练仍各自需要真实交付；本文不发明权限、不补签、不从 current builtin 补历史，也不将残留兼容性问题藏在“完整备份成功”之后。
