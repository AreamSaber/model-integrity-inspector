# REP-003 / 005 Phase 2b：可信派生 S1

日期：2026-09-08。纯组件已实现并完成下述本地验证，等待主任务集成复核；不是 Worker、0 天留存、数据库或正式审核完成证明。

## 边界与形状

每次真实 Attempt 的响应仍在可信 Worker 内存时，使用签名 Manifest、冻结 SamplePlan、精确 wire Snapshot 和真实 NormalizedResponse 调用同一个 feature 提取器。它返回私有 Prepared，不能由调用者填充 SampleFeature。使用独立认证用途封装；生产注入仅有 `DerivedMAC(version, canonical)` 的用途限定能力，纯测试另有独立 32 字节用途密钥构造。生产 KeyRing 派生及结算装配由主任务独立完成，不能直接使用 master、display 或 response-evidence 密钥，也不能让 secret 反向导入 features 造成分层/测试循环。

认证内容为固定版本、完整 scope（org/run/sample/probe/attempt/job/number/ordinal）、Manifest / wire request hash、提取器/模板/tokenizer 版本和摘要，以及 outcome 绑定摘要。不绑定提交前尚未知的数据库 FinishedAt；读取阶段另检查完整持久关系及提交后的时序。

载荷仅为已存在的 SampleFeature S1 和 Token UsageComparison，加上 Behavior 的认证派生观察。后者的合同/变量/配对身份只保存域分隔摘要；记录不保存响应正文、原始响应头、ModelReported、ContentType、ProviderRequestID、原句片段、Nonce、Seed、PairID、合同原字符串或任意 Kernel Input。摘要是不可逆标识，不是加密或对短可猜内容的保密承诺。

每 Attempt 的 canonical payload 上限 32 KiB（外层 `DerivedRecord` 的 JSON/Base64 封装会另有固定有界膨胀），内嵌 Behavior canonical payload 上限 16 KiB。固定 typed schema，严格 canonical 编解码，未知字段/版本、认证失败、重复或缺失记录、scope/最终指针不符整批拒绝。原始路径的确实缺失观察可以记录显式状态；不能把一条必需但丢失的派生记录冒充正常缺失或零值。Run 保留既有 150 个样本/至多 2 次重试的限制，因此最多 450 个 Attempt；Manifest + 所有请求快照 + 派生 payload 仍受 8 MiB 总预算。

## 为什么足够，以及不能重算什么

| 使用处 | 保存的响应测量 | 从重新验证的冻结计划在内存恢复 |
|---|---|---|
| Token 阶梯与 bootstrap | tokenizer 质量/计数/选择类别、结构/终止分类、Usage 完整比较、协议与后缀观察 | cap、stream、repetition、实际 seed、condition、series、shared-nonce cluster；保持独立组及 seed 相等性 |
| Usage 与失败分母 | 缺失计数仍为 null；可用/方向/误差/带宽/上限/警告；最终有效性和网络失败 | 所有逻辑样本、真正最后 Attempt、期望数与 Auxiliary 排除；重试不增加样本 |
| Behavior 重复簇 | 原有 Features、证据区间数字/规范化 SHA256/候选与抑制分类 | 模板 registry、family/language、合同绑定及适用资格；与 raw 路径共用聚合实现 |
| Behavior 配对 | 四个假设的响应测量，非已聚合挑选的阳性结果 | PairID/arm/contrast、合同与变量相等性、ComparableSHA256；与 raw 路径共用同一配对实现 |
| 结构与协议 | 全部既有结构 Features、closed ProtocolObservations、延迟与计数；不保存 MIME/model 自由文本 | 原请求是否 stream、请求 cap、任务合同和版本身份 |
| 评分与报告 | 完整 Features/Token/Behavior/配对统计可恢复 | 同一个 analyzer 与评分器；不是重造“兼容”评分器 |

同一提取器/模板/tokenizer 版本下，依赖上述充分统计的聚合阈值、权重与描述性假设可以重新运行。更换 tokenizer、文本归一化/提示词分类、结构解析器、增加需要原句的新规则或重新提取任意片段，不能从旧派生记录重算；必须明确不可重分析，不能读取未留存正文或将全 Run 降为 insufficient 当作功能完成。

## 集成约束

1. Derive 在可信响应作用域执行，签名用途密钥不进入 HTTP。
2. 与真实 Attempt 结算、Job 和审计同事务保存记录。失租或审计失败不得产生孤立可用记录。
3. 0 天仍保存派生 S1，但禁止保存 raw analysis 和 display 两类正文密文；保留策略必须在结算线性化点重读。
4. 分析读取最终版本必须验证每个 Run→Sample→Attempt 持久关系、完整重试链、真正 FinalAttemptID、请求快照与计划，以及签名和精确提取器版本后才聚合。
5. 本纯组件不认证数据库身份，也不独自实现 0 天、单调 cutoff、正文清理、授权读取或报告发布。后续必须增加实际 Worker/TLS 双库 0/30 天等价和无正文落库测试。

## 验证计划

原响应路径和派生路径使用真实模板生成器、冻结请求构建器、tokenizer 和分析器。比较完整 JSON 字节，而非仅风险数字；覆盖正常、阶梯/流式、重复前后缀/配对、缺失 Usage、不同 model 映射、reasoning、拒绝、协议失败、结构限额、重试与 uncertain。额外验证未知版本、错误用途密钥、篡改、跨 scope、final pointer、漏记录、编码上限及 S2 canary 不在派生编码中。

## 实现 checkpoint 与恢复入口

专有实现文件：`internal/integrity/analysis/features/derived.go`、`derived_auth.go`、`derived_test.go`、`derived_analyzer_test.go`；Behavior 的 `derived.go`、`derived_test.go`。既有 `features/build.go` 只共用样本计数/限制汇总 helper，`features/types.go` 为私有 Batch 增加认证 Behavior 分派；既有 `behavior/batch.go` / `paired.go` 只将 items 后的聚合抽成共用函数。没有修改 Worker、repository、迁移、HTTP、阈值或既有 golden。

实际纯层接口：

- `Builder.DeriveAttempt(ctx, run, sample, attempt)`：精确重验已签入派生 source mode 的 Manifest 和 frozen wire 后，使用原 `Builder.sample` 提取当前 Attempt，返回不可手填的 `PreparedDerived`。不要求尚不存在的 Run 关闭或 Attempt 提交时间；已结算状态和网络错误分类进入 outcome 摘要。
- `NewDerivedCapabilitiesWithMAC(activeVersion, DerivedAuthenticator)`：只依赖 `DerivedMAC(version string, canonical []byte) ([]byte,error)`。KeyVersion 与现 KeyRing 的大小写字母、数字、点、下划线和连字符规则一致，历史版本能力由可信启动配置决定，没有另设 8 版本限制。
- `DerivedSealer.Seal(ctx, prepared)`：域为 `mii/derived-s1/auth/v1` + NUL + `mii.derived-s1.v1` + NUL + key version + NUL + canonical payload，MAC 必须 32 字节。底层能力错误折叠为闭合错误，最后一次 MAC 操作期间的取消仍在释放前检查。配置接口不接收 HTTP 参数或任意 JSON；只有纯测试的独立密钥构造接收 key bytes。
- `Builder.BuildDerived(ctx, input, records, verifier)`：先复用与原 Build 相同的私有核心做完整持久图/时序/最终指针/请求校验，且 Manifest 必须签入精确派生 source mode，输入必须不混有原始 Evidence。每个已存在 Attempt 必须有一条认证记录，包含真实缺失响应的显式派生观察；无 Attempt 的 NOT_APPLICABLE 样本不制造记录。恢复后仅统计真正最终 Attempt，重试不变成额外样本。
- `Builder.BuildResponseReference(ctx, input, records, verifier)`：显式 raw 对照 API，不是失败时的备用分析路径。先对独立 Samples/Attempts slice 的去 Evidence 副本执行完整 BuildDerived 认证/校验，再经同一私有核心提取真实 raw 特征，并在释放前将每个 Attempt（含非最终重试）的完整 NormalizedResponse sourceHash 与已认证 payload 核对。任一必需 S1 缺失、原始响应缺失或不一致均拒绝；真实采集时明确 no_response 的记录只能对应 nil Evidence。原输入及签名 Manifest 不会被改写。
- `behavior.DecodeAuthenticatedDerived` 仅是外层 MAC 已验证之后的严格 codec，不是独立认证。`VerifyDerivedBinding` 在 Batch 暴露前复验当前冻结合同/变量/Pair 摘要、registry 和 duplicated feature 一致性；恢复参数中的正文必须为空。它只能校验已有私有观测，不能由手填 Features 构造观测。聚合和配对继续使用 raw 路径的唯一函数。

提取器签名覆盖 features、behavior、structure、tokenizer bundle / implementation、template 的精确版本与 artifact hash。独立 `source_hash` 为 `digestJSON(["mii/derived-source/v1", wire_hash, SHA256(json.Marshal(NormalizedResponse))])`；无响应时末项为闭合 `no_response`。它不是 `ResponseHash`、分析密文 ContentHash 或 display SourceHash，不能混用。Token Seed、Nonce、合同原句等只来自再次核验的 S2 签名计划，在恢复内存里使用，绝不写入派生记录。

本地固定 Go 工具链实测：

- `go test ./internal/integrity/analysis/features ./internal/integrity/analysis/behavior ./internal/integrity/analysis/tokenrisk ./internal/integrity/analyzer -count=3 -cover`：通过，16.602s / 0.461s / 0.981s / 0.424s；包覆盖率 87.8% / 90.6% / 97.4% / 38.2%。完整 analyzer 被 features 外部包集成用例调用；单独 analyzer 包覆盖率不是该跨包用例的覆盖统计。
- 18 类完整 analyzer JSON 字节等价：normal、no-seed、affix、paired-cues、missing-usage、reasoning-unseparated、reasoning-separated、reported-model、partial-stream、protocol、refusal、structure-limit、behavior-limit、missing-response、uncertain、invalid、no-final、retry。normal 另外断言 Included / 有效样本 / 完整配对非零，避免两边同时降为无信息伪等价。
- 认证及持久 scope 反例覆盖外层/提取器/structure/behavior 版本、未知历史密钥/大小写错配、错误用途密钥、payload/MAC 篡改、org/run/sample/probe/job/outcome/wire/final-pointer、不完整提交时间、缺/重复/多记录、未知/重复 JSON 字段、非 canonical / 尾随数据、shadow raw Evidence、独立编码/条数上限；canary 同时检查外层 payload 与解码后的内嵌 Behavior，而非仅扫描 Base64。
- Behavior 专项使用真实样本提取重复模式及六个真实配对，raw / derived 聚合全 JSON 字节相同；冻结合同/变量/Pair/template/final attempt 变化、保留 shadow body、registry变化均拒绝。
- 相关 `golangci-lint run ./internal/integrity/analysis/features/... ./internal/integrity/analysis/behavior/...`：0 issues。没有抑制规则或调低阈值；通过显式受界消费观测 slice 消除了 G602 提示。

这些是纯层实测，不是 0 天已生效、实际数据库无正文、浏览器/完整报告发布或独立安全审核证据。下一集成单元必须由主任务把 purpose cap 与真实 Worker 结算、持久 S1、retention/cutoff 和分析读取装配起来，再跑真实 TLS + SQLite/PostgreSQL 的同 Run 0/30 天分析/报告等价以及无正文落库断言。当前对冻结原请求/Manifest 的 S2 保留不作缩减或“已匿名化”声明。

## CI 偶发完整 JSON 不等：确定性修复（2026-09-08）

远端提交 `e8a52a6` 的运行 `34179919964` 在 image job 的 `TestDerivedCompleteAnalyzerJSONEqualsRawResponsePath/refusal` 报完整 JSON 字节不等。此前本机三轮通过不足以排除数据相关偶发问题；也不能凭 Linux job 失败推断平台原因。

先只在测试添加闭合 DTO 字段路径诊断，不输出任何完整 JSON、正文、Manifest、nonce、seed、哈希或任意字符串值。诊断只披露已知字段的数值/布尔差异或长度/类型/存在性；未知字段名及值也被隐藏。专门反例包含任意字段名、原文字符串及未知数值 seed，防止调试输出成为 S2 日志。

保留原 `refusal` 模式和原生产实现，本地 100 轮通过后，1000 轮在 208.875s 中真实复现三次同一断言失败；首差均为 `$.scores.Confidence.RepeatabilityFactor`：`0.5999999999999999 != 0.6` 或 `0.5555555555555555 != 0.5555555555555556`。进一步从真实生成器/冻结计划/响应生成 `refusal-uneven` 场景，保留 format、neutral 的全部三个簇和 differential 的一个簇，其他真实响应标记 refusal；验证实际 Included 簇数和提取到的匹配合同，不手填分析特征。同一份 raw batch 重复 Analyze 在修复前即失败：`0.7777777777777778 != 0.7777777777777777`。这证实非派生 S1 测量丢失，而是评分器按无序 map 累加浮点数所致。

最小生产修复仅在 `analysis/scoring/analyze.go` 对 family 名排序后按固定顺序求和；不改变公式、浮点精度、阈值、参数 artifact、golden 或 JSON 精度。测试继续要求完整 JSON 字节等价，增加第 19 个真实 `refusal-uneven` 场景和同一 raw batch 重复 128 次的确定性回归。

修复后 features / behavior / tokenrisk / scoring / analyzer 三轮实际通过（30.408s / 0.480s / 1.702s / 0.834s / 0.587s）。原 refusal 模式 1000 轮通过（230.900s）；确定性与安全诊断三轮再通过（1.304s）；最终相关 features / behavior / scoring lint 为 0 issues，全仓 `go test ./... -run '^$' -count=1` 编译检查通过。没有实际在 Linux 运行这些本地复测；此处不是新远端 CI 已通过的声明。此修复单元仅修改评分器顺序、派生外部测试和本节记录，等待主任务提交复核。

## 签名来源模式与防静默降级（2026-09-08）

`domain.AnalysisSourceDerivedV1` 固定为 `mii.derived-s1.v1`，`features.DerivedVersion` 保留为同值 alias。`generator.Options.AnalysisSourceVersion` 使用 `json:"analysis_source_version,omitempty"`，随 Manifest.Options 全体进入既有 HMAC；`domain.ExecutionPlan.AnalysisSourceVersion` 为已验签 Options 的同名投影，并参与现有完整 Plan 等价校验。Generate / Verify 的闭集只有空值（legacy）和该精确版本，未知或未来版本不会自动按 v1 解释。GeneratorVersion、模板、tokenizer、规则/评分 artifact hash 和旧 golden 均未改变。

空字段省略后旧 Options / Manifest / ExecutionPlan 的 canonical 字节不变；测试使用去除此新字段的旧结构形状，独立编码完整 legacy canonical 并计算原 manifest-v1 MAC，确认旧字节、hash、签名与新版一致且可验证。新非空标记改变该 Run 的 ManifestHash 和 MAC，但不改变冻结请求、样本、参数或估算。显式空字符串/null 的非 canonical 注入也拒绝。旧程序不能识别新字段时将关闭失败，未声明混合新旧 Worker 可安全处理新模式。

公开 `Build` 仅接受空模式，`DeriveAttempt` / `BuildDerived` / `BuildResponseReference` 仅接受精确派生模式；三个调用路径共用私有图/请求校验和原始测量核心，没有可由调用者开启的 allowDerivedRaw 开关。删除 S1、仅改 Plan/数据库投影模式、直接删除签名字段并重算数据库 plain hash，均不能使派生 Run 降为 legacy。历史目的密钥、全部重试链、缺失观察、scope 和提取器版本的既有校验均保留。19 类完整 analyzer JSON 等价用例现均从真实生成器签入新模式，再通过显式响应对照 API 得到 raw oracle；不去掉或重签模式以走旧路径。

对照额外反例覆盖正文、provider request ID、MIME、model、usage、raw 缺失、AAD scope、S1 缺失/重复/篡改、final pointer、非最终真实重试源差异，以及通过测试用途能力认证但与实际响应不同的 sourceHash。记录/样本/Attempt 个数和原始/S1 字节预算继续受界；完整 BuildDerived 成功后的后续 MAC 取消同样拒绝释放对照。对照要求全部真实响应源在场，不支持从 0 天未留存的原始响应生成 reference。

服务和 app 接线由主任务实现：实际新 Estimate 明确签入派生版本，未确认的旧模式 draft 在切换后返回 EstimateStale；已确认的 legacy Run 保持原签名和模式，先恢复其既有 receipt，不重新签署历史计划。本单元不改数据库、Worker、run.Service、app 或 replay，亦不把派生纯层通过声称为已启用留存策略。后续真实 Worker / replay 受控验证须提供完整可信 S1 给 BuildResponseReference，不可先删 marker 再调用 Build。

防护边界：现签名绑定组织及 RunNonce，未绑定随后生成的数据库 RunID。本改动阻止直接删 S1 / 改模式降级，不宣称抵抗攻击者用同组织另一份有效 legacy Manifest 替换整套 Run 持久数据。可删除的独立 activation 行不构成额外防降级依据。新模式无需修改迁移 17 或回填旧 Manifest；S1 持久结算由后续独立迁移处理。

本地验证：最终补强后的 generator / features / behavior / tokenrisk / scoring / analyzer 三轮通过（1.086s / 20.886s / 0.656s / 1.488s / 0.695s / 0.528s），原有 golden 未修改；新增来源与 reference 反例独立三轮通过（1.579s）；最终 domain / generator / features lint 为 0 issues；全仓 compile-only 通过。这些不是新远端 CI 或 Linux 实跑证据。

本单元冻结文件：domain/execution.go；generator/manifest.go、generator.go、replay.go、新 analysis_source_test.go；features/build.go、derived.go、derived_auth.go、derived_test.go、derived_analyzer_test.go、新 derived_source_test.go；以及本 notes。未执行 Git，待主任务复核整合。恢复入口为 BuildResponseReference 及上述来源模式负例；不再通过去掉签名标记来适配未来 Worker/replay 测试。
