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

- `Builder.DeriveAttempt(ctx, run, sample, attempt)`：精确重验 Manifest 和 frozen wire 后，使用原 `Builder.sample` 提取当前 Attempt，返回不可手填的 `PreparedDerived`。不要求尚不存在的 Run 关闭或 Attempt 提交时间；已结算状态和网络错误分类进入 outcome 摘要。
- `NewDerivedCapabilitiesWithMAC(activeVersion, DerivedAuthenticator)`：只依赖 `DerivedMAC(version string, canonical []byte) ([]byte,error)`。KeyVersion 与现 KeyRing 的大小写字母、数字、点、下划线和连字符规则一致，历史版本能力由可信启动配置决定，没有另设 8 版本限制。
- `DerivedSealer.Seal(ctx, prepared)`：域为 `mii/derived-s1/auth/v1` + NUL + `mii.derived-s1.v1` + NUL + key version + NUL + canonical payload，MAC 必须 32 字节。底层能力错误折叠为闭合错误，最后一次 MAC 操作期间的取消仍在释放前检查。配置接口不接收 HTTP 参数或任意 JSON；只有纯测试的独立密钥构造接收 key bytes。
- `Builder.BuildDerived(ctx, input, records, verifier)`：先复用原 Build 的完整持久图/时序/最终指针/请求校验，输入必须不混有原始 Evidence。每个已存在 Attempt 必须有一条认证记录，包含真实缺失响应的显式派生观察；无 Attempt 的 NOT_APPLICABLE 样本不制造记录。恢复后仅统计真正最终 Attempt，重试不变成额外样本。
- `behavior.DecodeAuthenticatedDerived` 仅是外层 MAC 已验证之后的严格 codec，不是独立认证。`VerifyDerivedBinding` 在 Batch 暴露前复验当前冻结合同/变量/Pair 摘要、registry 和 duplicated feature 一致性；恢复参数中的正文必须为空。它只能校验已有私有观测，不能由手填 Features 构造观测。聚合和配对继续使用 raw 路径的唯一函数。

提取器签名覆盖 features、behavior、structure、tokenizer bundle / implementation、template 的精确版本与 artifact hash。独立 `source_hash` 为 `digestJSON(["mii/derived-source/v1", wire_hash, SHA256(json.Marshal(NormalizedResponse))])`；无响应时末项为闭合 `no_response`。它不是 `ResponseHash`、分析密文 ContentHash 或 display SourceHash，不能混用。Token Seed、Nonce、合同原句等只来自再次核验的 S2 签名计划，在恢复内存里使用，绝不写入派生记录。

本地固定 Go 工具链实测：

- `go test ./internal/integrity/analysis/features ./internal/integrity/analysis/behavior ./internal/integrity/analysis/tokenrisk ./internal/integrity/analyzer -count=3 -cover`：通过，16.602s / 0.461s / 0.981s / 0.424s；包覆盖率 87.8% / 90.6% / 97.4% / 38.2%。完整 analyzer 被 features 外部包集成用例调用；单独 analyzer 包覆盖率不是该跨包用例的覆盖统计。
- 18 类完整 analyzer JSON 字节等价：normal、no-seed、affix、paired-cues、missing-usage、reasoning-unseparated、reasoning-separated、reported-model、partial-stream、protocol、refusal、structure-limit、behavior-limit、missing-response、uncertain、invalid、no-final、retry。normal 另外断言 Included / 有效样本 / 完整配对非零，避免两边同时降为无信息伪等价。
- 认证及持久 scope 反例覆盖外层/提取器/structure/behavior 版本、未知历史密钥/大小写错配、错误用途密钥、payload/MAC 篡改、org/run/sample/probe/job/outcome/wire/final-pointer、不完整提交时间、缺/重复/多记录、未知/重复 JSON 字段、非 canonical / 尾随数据、shadow raw Evidence、独立编码/条数上限；canary 同时检查外层 payload 与解码后的内嵌 Behavior，而非仅扫描 Base64。
- Behavior 专项使用真实样本提取重复模式及六个真实配对，raw / derived 聚合全 JSON 字节相同；冻结合同/变量/Pair/template/final attempt 变化、保留 shadow body、registry变化均拒绝。
- 相关 `golangci-lint run ./internal/integrity/analysis/features/... ./internal/integrity/analysis/behavior/...`：0 issues。没有抑制规则或调低阈值；通过显式受界消费观测 slice 消除了 G602 提示。

这些是纯层实测，不是 0 天已生效、实际数据库无正文、浏览器/完整报告发布或独立安全审核证据。下一集成单元必须由主任务把 purpose cap 与真实 Worker 结算、持久 S1、retention/cutoff 和分析读取装配起来，再跑真实 TLS + SQLite/PostgreSQL 的同 Run 0/30 天分析/报告等价以及无正文落库断言。当前对冻结原请求/Manifest 的 S2 保留不作缩减或“已匿名化”声明。
