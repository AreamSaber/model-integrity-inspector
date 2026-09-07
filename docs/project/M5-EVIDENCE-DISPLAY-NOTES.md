# REP-003 / REP-005：授权证据展示与复现模板设计

日期：2026-09-07。状态：Phase 1 纯组件已实现并经主任务集成验证；Phase 2/3 仍为待分配实施的后续设计。不是正式安全审核或发布批准。

最初只读设计核对基点为 `c560963`，另只读核对主任务新增的 AC-17 回归；随后主任务仅批准 Phase 1。此次实现仅新增纯脱敏/展示加密组件，并为 KeyRing 增加独立 purpose 派生；没有修改 Worker、repository、迁移、API、权限、组织设置或前端。第 10 节记录实际内部 API 和测证；其余后续路径、状态名和 HTTP 契约仍是建议，不能当作已经交付。

## 1. 最小路线与本轮可批准范围

1. **Phase 1：纯脱敏与独立加密用途。** 实现有界纯脱敏器、不可任意序列化的展示载荷、仅用于展示的 seal/open 能力和单元反例。不接 HTTP，不开放设置，不让 API 得到分析解密器或凭证能力。
2. **Phase 2：Worker 采集、可信持久化与保留语义。** Worker 在 `Credentials.Use` 内用实际 Key 和全部自定义 Header 值构造脱敏副本；按真实 Attempt scope 加密，与 Attempt/Job 结算同事务落库。实现 0 天仍能正常分析的可信派生 S1 路径、单调保留截止线、到期/删除状态，之后才具备完整读取基础。
3. **Phase 3：授权读取与复现。** 单 Attempt、同组织及固定修订；最终权限复验、保留检查和读取审计同事务，成功提交后才释放正文。加入严格 HTTP DTO、纯文本前端、显式复制/下载和不可用原因。

Phase 1 可独立实施，不必等待全部 Phase 2；但只完成纯组件不能关闭 REP-003/005，也不能宣称 0 天留存已经生效。阶段性拒绝读取是安全退化，不等于产品需求完成。

## 2. 已核对事实：不要混同四种材料

| 材料 | 当前事实与边界 |
|---|---|
| 上游错误正文 | TECH AC-17 的准确对象是“Key 出现在上游错误体”。`openaichat.httpError` 有界读取并只返回闭合分类；200 的 error object 在赋值 Content 前失败；SSE `event:error` 不拼接错误载荷，保留此前合法内容。不能据此宣称成功正文、响应头同样安全。 |
| 原始分析证据 v1 | `secret/evidence.go` 保存整个版本化 NormalizedResponse 的密文，含 Content、HeaderSummary、ProviderRequestID 等；AAD 绑定 org/run/sample/attempt/request hash/key version，但没有脱敏策略证明。仅 Worker/analysis 可调用 `WithResponseEvidence`。它并不是原始 HTTP/SSE 全字节档案。 |
| 脱敏展示副本 | Phase 1 已有纯组件和独立用途的加密能力，但真实 Worker 尚未采集/落库，也没有 HTTP 读取。不能把旧分析密文解密后直接当 HTTP DTO，也不能由浏览器做脱敏。副本仍是 S2，不因脱敏降为普通列表字段。 |
| 冻结请求/复现材料 | `ReserveAttempt` 保存发送前、未附认证的 RequestSnapshot；RequestHash 覆盖 wire JSON，且与冻结 SamplePlan 核对。它没有真实 Authorization，但消息、model、stop 等文本不能仅凭“pre-auth”标签获得无 Key 证明；新采集仍须通过实际凭证字典检查。 |

主要代码证据：

- [Worker 作用域与后续加密](../../internal/integrity/worker/run.go)、[实际调用与 Token 计数](../../internal/integrity/worker/execution_http.go)。目前离开 `Credentials.Use` 后才加密分析响应。
- [错误分类](../../internal/integrity/adapter/openaichat/errors.go)、[非流式解析和 metadata](../../internal/integrity/adapter/openaichat/parser.go)、[SSE 解析](../../internal/integrity/adapter/openaichat/stream.go)。
- [证据密文/AAD](../../internal/integrity/secret/evidence.go)、[同事务结算与当前固定 30 天](../../internal/integrity/repository/execution_evidence.go)、[实际请求预留](../../internal/integrity/repository/execution_attempt.go)。
- [S1 特征边界](../../internal/integrity/analysis/features/README.md)、[协议观测](../../internal/integrity/analysis/features/protocol.go)、[ModelReported 与 tokenizer 选择](../../internal/integrity/analysis/features/mapping.go)。
- [PRD 9.8 / 10.3 / 11](../../模型真实性检测系统-PRD-V1.0.md)、[TECH 10.10 / 13 / AC-17](../../模型真实性检测系统-TECH-SPEC-V1.0.md)、[ADR-0004](../adr/ADR-0004-secret-envelope-encryption.md)、[ADR-0006](../adr/ADR-0006-audit-log-integrity.md)。

主任务已新增 [真实上游错误 canary 回归](../../internal/integrity/worker/upstream_error_evidence_test.go)：400、401、200 error object、非法 JSON、SSE error、合法前缀后 error；经真实 TLS/Worker/精确 AAD 解密检查错误体未进入证据及日志。主任务报告双库三轮 14.836 秒、lint 0。本设计没有重复运行或修改该测试；该证据不覆盖恶意响应头或成功正文。

## 3. AC-17 与 metadata：先保留分析语义

当前 `metadata()` 对五个头只检查单值、长度和 CR/LF/NUL；请求 ID 只检查可打印 ASCII。`X-Request-Id: <真实Key>` 因而可能被接受，错误路径在丢弃正文前已经生成这些 metadata。白名单控制的是字段名，不证明字段值无秘密。

建议先做独立 checkpoint：

- 错误路径不保留任意原始 HeaderSummary/ProviderRequestID。Content-Type 如需保留，只保留受支持的规范化 MIME 类别；Retry-After 保留已解析的有界数值/分类，不复制原字符串；失败类型、Usage 的缺失性、HTTP 状态与实际延迟不改变。
- 成功响应展示副本同样净化所有自由文本 metadata；最小版本可不展示请求 ID/原响应头，仅展示已校验的结构化状态、计数和时间。
- **不直接重写成功分析响应的 Content、ModelReported 或 ContentType。** ModelReported 参与真实 model-echo 观测和 tokenizer 选择；ContentType 参与协议观测。为展示而改它们会改变重新分析语义。若需要改变分析 metadata，须先固定原观测的可信派生字段并验证前后语义，不用“脱敏”暗改风险或 tokenizer。
- 不修改旧 ResponseHash、分析载荷 ContentHash、Attempt 请求哈希、已发布 revision 1、报告哈希或历史 Token 数。新展示副本只记录自己的哈希和来源绑定。
- 不能通过检查随机密文是否含 canary 证明脱敏；必须在测试的可信层精确 AAD 解密后检查载荷，并覆盖日志/错误/DTO。

## 4. Phase 1：有界纯脱敏契约

### 4.1 来源与生命周期

输入由可信 Worker 在当前 `Credentials.Use` 回调中装配：冻结 pre-auth 请求、当前实际 NormalizedResponse、实际 Key 字节及全部自定义 Header 值。不只检查名称包含 key/token/auth 的 Header；认证值在 Key 字典中，自定义值全部进入字典，非空短值不准因“看似普通”跳过。

纯层无 repository、Secret service、网络或日志依赖；它不能证明调用者传来的身份是真实数据库身份，也不能仅凭一个 `redacted=true` 标志证明调用发生于凭证作用域。真实性依靠 Worker 唯一采集路径、租约/持久行绑定、封装的 private payload 和集成回归。API 不接收用户上传的“已脱敏证据”。

只输出私有字段的 `Prepared`。其 `fmt.Formatter`、`Stringer`、`slog.LogValuer` 固定脱敏；普通 JSON 拒绝序列化。仅显式可信 seal 边界可有界编码；只有后续授权展示服务最终投影为 HTTP DTO。字典不保存在输出、错误、密文、审计、配置或缓存中；归还时清除自有 byte buffers。Go 的复制字符串/运行时内存无法保证物理清零，文档不能承诺全部内存擦除。

### 4.2 精确替换与有限编码集合

建议策略 ID `display-redaction-v1` 固定以下集合，不能由请求方放宽：

1. 原始 UTF-8 字节；大小写敏感，原秘密不作 case fold。
2. JSON 字符串的标准转义形式，以及固定的 Unicode escape 形式；合法 surrogate pair 按规范处理。
3. URL query/form、path 转义；逐 UTF-8 字节 percent 编码的全大写和全小写十六进制形式。
4. 标准及 URL-safe Base64，各含有 padding/无 padding 形式。
5. 十六进制全大写/全小写形式。

每个值至多 16 个去重变体，凭证源至多 Key + 32 个 Header 值，字典总量至多 2 MiB。只生成上述一层编码，不递归解码、不枚举任意混合大小写或嵌套组合。Bearer 前缀后包含原 Key 的情况由原值替换覆盖；不必保存完整 Authorization。

替换按确定性的最长匹配优先进行，重复/重叠值去重；不将替换产生的掩码重新当新输入扫描。响应先按现有 parser 语义拼接合法流式 Content，再扫描，避免密钥跨 SSE chunk 边界逃逸。对冻结请求按严格类型的字符串字段处理，不能在序列化 JSON 上任意替换造成非法 JSON/改变数值类型。Header 名称不导出为任意对象键；最小模板统一用固定占位名。

空 Header 值无可替换内容，可省略；非空极短值与普通文本难以区分，不能忽略。对无法同时保证输出可用和完成检查的输入（例如短值使全文匹配或掩码本身产生歧义），返回 `unavailable_redaction_policy`，不回退原文、不拒绝已有真实 Attempt 的结算、不假称已完整展示。

附加有限“疑似秘密”规则只用于保守遮盖/拒绝展示：认证语法、私钥块、已版本化的常见 token 标记、敏感字段赋值。规则须限制输入长度、嵌套深度及执行时间；不可用任意回溯正则、外部 LLM 或在线服务扫描。未知编码、加密/拆字/图片、任意第三方秘密、未覆盖格式不能保证被识别；检测不到不等于不存在。界面说明“按已知凭证及固定规则脱敏”，不得宣称绝无任何秘密。

### 4.3 上限与损失声明

原请求至多 1 MiB，原响应 Content 至多 1 MiB，事件只取已有有界数值摘要，不保存原 SSE data。头尾采样/序号间隙须显式标注，不能把有界事件摘要称为完整上游时间线或用于还原所有 chunk。展示载荷建议严格编码后总上限 4 MiB；字典 2 MiB、事件至多 256、固定字段名、UTF-8 严格有效。应在扩展/编码分配前计算或通过 bounded writer 限制，不能先分配任意体积再判断。统一 HTTP 8 MiB cap 不允许由调用者提高。

若替换扩张、格式、时限或资源限制失败，整份对应正文标记不可用；不把截断文本标记为完整。不改变分析有效性来掩饰“仅展示副本生成失败”；保持真实 Attempt/已完成分析事实，额外记录闭合 display 状态。原采集本身超限则保留既有 INVALID_SAFETY_LIMIT 语义，不能用展示成功替它恢复有效样本。

## 5. 独立 purpose 与精确历史绑定

建议新 HKDF purpose 为 `evidence-display`，与既有 `response-evidence`、Secret wrap、audit、probe、baseline 不同。仍用随机 96-bit nonce 的 AES-256-GCM，不复用原 nonce/key；所有版本化键必须有明确旧版本解密窗口。

窄能力建议：Worker 仅持 DisplaySealer；授权展示 service 仅持 DisplayOpener。两者内部只含 display purpose 派生键，不嵌入原 KeyRing 指针，不暴露 raw key getter，不提供 Secret/分析解密方法。HTTP control 只得到 service 的 typed 方法；不能把 `KeyRing.WithResponseEvidence` 或 `WithCredentialsForWorker` 注入 API。

新封装的 AAD 至少绑定：envelope/payload/policy 版本、purpose、org/run/sample/attempt、实际 request hash、来源分析载荷 hash（存在时）、展示 payload hash、key version、plaintext bytes、采集时间、不可延长的 sealed expiry。来源若无分析密文（0 天）使用明确的 source kind 和可信派生来源摘要，不把缺失值当零哈希或编造分析密文。

Scope 必须来自同组织的持久 Run→Sample→Attempt 关系。默认样本结果绑定固定 revision 1 与其 FinalAttemptID；用户查看重试链某个已结算 Attempt 时必须显式选择其 ID，标注它不是最终统计样本，不能静默挑最佳重试。DISPATCHED/UNCERTAIN 无确定响应不提供伪造正文。

建议新增独立展示表，而不是复用未带脱敏证明的 `response_content_redacted` 字段。唯一绑定至少为 org+attempt+policy version；记录只含上述 S1 scope、闭合状态、密文 envelope、创建/失效时间，禁止明文列。记录与 FinishAttempt/CompleteWith、Job 和强制审计同事务提交；失租、审计/数据库失败不产生可读取的孤立副本。policy 升级只新增副本版本，不覆盖旧报告或分析版本。

旧 v1 证据一律 `unavailable_legacy_unverified`：不能由 HTTP 解密后补 regex，不能读取当前 Key 来“认证”旧响应。Secret 轮换覆盖旧版本、删除目标销毁凭证后也不做旧 Key 恢复。未来独立展示副本可以在允许保留期内脱离当前目标/Secret 读取；目标删除不应破坏保留的 S1 报告。

## 6. Phase 2 必须完成的保留与 0 天链路

当前 [组织设置](../../internal/integrity/repository/identity_management_organizations.go) 接受 0～180 天，但 `FinishAttemptWithEvidence` 仍固定 30 天；[运行说明](../operations/DEV-RUNTIME-V1.md) 已将完整策略/清理标为未完成。不能只禁止 UI 显示而宣称 0 天“未落库”。

- 新 Attempt 在 0 天时不持久化完整响应的 raw analysis 密文或 display 密文；当前无证据标记不能冒充正常零分。
- **产品最终要求是 0 天仍能真实生成摘要/分析/报告。** 应在受租约、精确请求身份和版本约束的可信 Worker 内存作用域生成分析必需的派生 S1，再以 typed、版本化、组织/Run/最终 Attempt 绑定的记录原子落库。RunAnalysis 消费该可信来源，复验唯一最终 Attempt、完整性和未知状态，不接受任意 JSON/调用者自行填写的特征。
- S1 充分性必须逐项验证 Token/behavior 配对、相同 nonce cluster、结构/协议、缺失值和所有统计分母；不能把用于后续规则的原句、命中片段、nonce/seed 或任意 Kernel Input 当 S1 持久化。只保留必要的分类、计数、不可逆标识与固定版本。需要原文才能重分析的新规则须明确不可重分析，不偷偷缓存 raw body。
- 全 Run 变为 insufficient 可以是临时安全退化，但不是关闭正文留存功能完成；须保留未交付声明。至少测试同一受控上游 0/30 天生成相同应有 S1/分析/报告，且 0 天无正文持久化。不能为通过测试填入手写正常特征。

### 防止保留策略改变复活正文

仅使用 `created_at + current_days > now` 不足以保证不可复活：0→30 或缩短→延长可能把尚未物理清理的旧行重新开放。

建议组织设置事务维护单调 `response_evidence_not_before`。每次保留期变更，以同一数据库时间计算 `max(旧cutoff, now-旧days, now-新days)`；days=0 的相应值为 now。保留配置和 cutoff 必须与变更审计同事务；任何路径不能降低 cutoff。时间统一数据库 UTC 精度，边界 `created_at <= cutoff` 拒绝，避免同一微秒复活。

读取有效窗口为不可变 sealed expiry、当前天数、单调 cutoff 和显式删除状态的交集。增加天数不延长已封装副本的 expiry；已过期或关闭期间的历史正文永不重新出现。0 天期间不落副本，重新启用只影响新的可采集响应。

Worker 在提交正文前重新读取组织策略；与设置变更使用明确的同一锁顺序/线性化点。采集后、提交前改为 0 或落入 cutoff 时，跳过正文持久化，仍提交真实派生 S1；不得因为持有旧 policy receipt 而越过新禁令。策略时间/版本若不能与已封装 AAD 对齐，拒绝正文副本或重新封装已脱敏私有载荷，不能修改 AAD 时间假装一致。

清理按有界批次异步物理删除密文及 nonce，记录不含正文的删除凭证；到期访问拒绝不依赖清理及时执行。原结果/报告哈希不重写。保留策略仅针对响应正文，不借机任意删除冻结请求；请求和 Endpoint 私有参数同属 S2，其独立保留/加密边界仍需明确，不能因正文设置名不同而在默认页面回显。

## 7. Phase 3：最终授权与读取审计的事务边界

可参考现有 [ControlAuthority](../../internal/integrity/repository/controlauthority.go)、[事务鉴权](../../internal/integrity/repository/identity_management.go)、[报告下载最终审计](../../internal/integrity/repository/report_read.go) 和 [有界下载 service](../../internal/integrity/run/report_service.go)，但不直接给 HTTP 复用 raw 分析读取函数。

建议流程：

1. HTTP 只解析规范十进制 ID、revision、固定动作；cookie 会话和 X-Organization-ID 形成现有私有 capability。需要实时 `run.read + evidence.read + evidence.body`，不按角色名称硬编码。人工复核、报告导出或拥有目标都不自动授予正文权限。
2. 新 typed repository 在短授权快照内核对全部历史身份和发布修订，先查状态、版本、byte length 上限，再读取最多一个匹配 display 密文。复现所需 Manifest 另受现有 8 MiB 上限、单份 wire request 受 1 MiB 上限，不加载整 Run 的所有正文。未授权不得靠不同 legacy/expired 状态泄漏外组织对象是否存在。
3. service 在可取消并发槽内（建议每进程 4 个，满时闭合拒绝）使用 DisplayOpener 验证精确 AAD、UTF-8、严格 schema 和 policy。缓冲有界，解密/编码发生在数据库锁外；无网络、无凭证读取，不把正文交给任意回调。
4. **唯一最终释放点**是 `controlTenantTransaction("evidence.body", ...)`：同事务重新检查 session/user/member/grants、run.read/evidence.read、org 策略/cutoff、同一 published revision、sample/attempt/manifest/request hash、display 版本/哈希/expiry/删除状态；与第 2 步收据完全匹配，追加 `evidence.body.read` 或 `evidence.reproduction.export` 审计。未知/审计失败/事务提交失败都丢弃缓冲，不返回正文。
5. 成功提交后生成一次性、同 ctx/scope 的读取句柄，随后才写 HTTP headers/body。句柄不得跨用户/组织重用；超时、Abort、关闭清理缓冲并归还槽位。慢传输按固定小块复验授权与截止时间，撤权后停止未发送部分；不能撤回此前已经合法发送的字节，也不能承诺瞬时撤销用户已复制的内容。

第 2 步是减少未经授权解密成本的预检查，不能替代第 4 步；第 4 步把最终权限、对象绑定、保留策略及审计放在同一个事务，不依赖 HTTP 请求开始时的权限缓存。加密/文件/网络操作不放入管理全局锁。审计只记 actor、org/run/sample/attempt/revision、展示 policy/hash、动作和闭合结果/规模，不能记 Key、Header 值、请求/响应、Endpoint 私有参数或自由文本诊断。

建议 HTTP 路径（未注册）：

- `GET /api/v1/runs/{id}/samples/{sampleId}/attempts/{attemptId}/evidence?analysis_revision=1`
- `GET /api/v1/runs/{id}/samples/{sampleId}/attempts/{attemptId}/reproduction?analysis_revision=1`

前者为授权纯文本视图；后者显式 S2 模板导出，另复验 `report.export` 并说明范围。读取权不是 DRM，不能承诺用户无法自行复制已合法展示的文本。默认 result/findings/samples/SSE/JSON-HTML 报告仍为 S1，不自动内嵌全文。

授权对象上的正常不可用用 typed state（例如 `unavailable_legacy_unverified`、`unavailable_policy_zero`、`unavailable_expired`、`unavailable_deleted`、`unavailable_not_captured`、`unavailable_redaction_policy`、`unavailable_safety_limit`）；不可用正文为 null，不是空字符串。来源被篡改、未知 policy、解密/数据库/审计故障使用闭合错误，不能伪装普通“未留存”。状态优先级和 HTTP 错误码待契约单元冻结。

响应使用 `Cache-Control: no-store`、`nosniff`，不得进入 CDN/日志/浏览器长期存储。前端只在明确点击后加载，纯文本转义、不解释 HTML/Markdown、无原文搜索日志；账户/组织/run/attempt/revision 改变或 401/403 时 Abort 并清空已展示内容。复制/下载需明确范围提示，不自动请求上游。

## 8. REP-005：固定 pre-auth 请求，不是可执行插值脚本

- 从被授权历史 Attempt 的冻结 RequestSnapshot/RequestHash 和其冻结 SamplePlan/Manifest 验证构造，绝不读取“当前目标”的 model、Endpoint 或 Secret。当前 Adapter `BuildRequest` 是唯一 wire JSON 构建器；使用固定 `https://analysis.invalid/v1` 和禁止 Do 的实现，只复用序列化、绝不做 DNS/HTTP。重建 hash 必须与真实 Attempt 一致，不复制另一套协议构造算法。
- Worker 采集时先验证原快照，再在实际 Key/header 字典作用域内生成脱敏请求展示/复现副本。API 只导出经过认证的副本；旧无证明请求不因未附 Authorization 自动获得可导出资格。历史原快照可留给可信分析，不经 HTTP 补读旧/新 Key。
- 最小制品为规范 JSON request body 加固定格式说明：方法 POST，Endpoint 为 `${ENDPOINT}`，认证为 `${API_KEY}`；custom header 名为 `${AUTH_HEADER_NAME}`，其他 header 采用编号占位 `${CUSTOM_HEADER_1_NAME}` / `${CUSTOM_HEADER_1_VALUE}`。不输出真实 URL 的 host/path/query/fragment/userinfo，不输出原自定义 Header 名/值或 Key 掩码片段。
- 只保留来自冻结实际请求且通过脱敏策略的模型和参数；响应正文不混入请求模板。temperature/top_p/seed/stop/stream/max_output_parameter 等使用实际白名单字段，明确重试 Attempt 可能不同。公开探针正文虽不是客户数据，nonce/seed/完整请求仍按 S2 处理，不默认塞入 S1 页面或审计。
- 给出 `source_request_hash` 和独立 `template_hash`，并声明是否因脱敏修改 payload；不同哈希不能宣称逐字节复现。Endpoint/header 被占位意味着只复现请求结构/参数，不能证明相同网络路径、上游实现或输出。随机性、版本、模板及未校准限制必须保留。
- 不把模型输出、model、stop、Endpoint、Header 或模板正文拼进 shell；不提供 eval、动态 heredoc、命令替换或把用户字段嵌入引号的 curl 文本。Phase 1/最小 Phase 3 只提供数据制品。未来若加执行示例，命令必须完全静态，用独立 JSON 文件和受控环境输入；禁止由模板自动执行，禁止工具自动产生付费调用。
- malformed snapshot、hash/归属不符、资源超限、legacy/过期/关闭留存策略不满足时明确不可用；不能从当前目标生成一个相似请求冒充历史复现。

## 9. 拟实施文件与验收点

Phase 1 的实际文件和内部接口见第 10 节；Phase 2/3 仍是之后申请所有权的候选路径：

| 阶段 | 候选文件范围 | 必须证明 |
|---|---|---|
| Phase 1 | 新 `internal/integrity/evidencedisplay/types.go`、`redact.go`、相应 tests；新 `internal/integrity/secret/display.go`、`display_test.go`；协调后仅在 `secret/envelope.go` 增加独立 purpose 派生 | 精确/编码/重叠/跨 chunk/短值/上限；输入无突变；fmt/json/slog 无字典或原文；错 org/run/sample/attempt/hash/policy/expiry/key version/tamper 不可解；两种 opener/sealer 均没有分析/Secret 能力。 |
| Phase 2a | Worker `run.go`、`execution_http.go` 的精确采集点与新测试；`repository/execution_evidence*.go` 的 typed 结算扩展；由 root 分配新迁移编号（三方言） | 真实 TLS + 双库，实际 scope 内 Key/全部 headers canary；失租/审计失败全部回滚；新展示证明不能为旧 v1 补标；分析 Content/hash/计数未变化。 |
| Phase 2b | 新可信派生 S1 source、Worker/analysis 装配与 repository；组织保留设置、cutoff、清理路径（另行分配所有权） | 0/30 天等价真实分析；0 天不落响应正文；设置变更/提交竞态；0→30、缩短→延长和清理延迟不复活；S1 无 nonce/seed/原句；摘要/报告正常。 |
| Phase 3 | 新 `repository/evidence_display_read.go`、`run/evidence_display.go`、`api/evidence_display.go` 及相应测试；定向路由、OpenAPI/反射契约、独立前端 | 跨租户/归属断链/旧重试；最终释放前撤权、会话失效、审计/DB失败、expiry 与慢下载；默认接口无 S2；XSS纯文本；复现模板无 endpoint私有参数/key/unsafe shell。 |

特别回归集：

- 真实 Key 放入每种白名单响应头、请求 ID、成功 content/refusal/model 字段；所有自定义 Header 值分别出现在请求/响应及固定编码变体；不能只测 `sk-` 前缀的假密钥。
- 有效 SSE 前缀 + 错误事件、UTF-8/秘密跨 chunk、超大重复编码、嵌套编码超覆盖范围。保留原有效性/数量和明确策略覆盖局限。
- legacy v1、目标轮换/删除、缺旧密钥、AAD 搬到另一组织/Attempt、期限延长、unknown policy：无原文回退。
- 解密准备期间撤权、审计触发器失败、最终事务失败、并发策略设为 0：任何释放回调/HTTP 写入都不得发生；真实数据库故障不能吞成空正文。
- frozen 请求含引号、反引号、美元括号、换行、HTML 标签或不安全 URL 片段：导出始终是纯数据和占位符，不执行、不插值、不渲染脚本。

本阶段结论：Phase 1 已按批准范围实现纯组件和 purpose 隔离。Worker 持久化、0 天可信 S1 链、读取审计、HTTP/UI/复现导出仍是分阶段待实现项；不能关闭 REP-003/005 或标为正式审核通过。

## 10. Phase 1 实现 checkpoint（2026-09-07）

### 已有内部接口与文件

- [types.go](../../internal/integrity/evidencedisplay/types.go)：`Source`、不可普通序列化的 `Prepared` / `Opened`、显式有界 callback、关闭/清零生命周期、认证后严格 canonical JSON 解码。`Prepared` 与 `Opened` 的私有字段名不同，不能用 Go 类型转换把解码值变成可封装的 `Prepared`。
- [prepare.go](../../internal/integrity/evidencedisplay/prepare.go)：`Prepare(ctx, source, key, headers)`。只复用 Adapter 的确定性 `BuildRequest`，固定 `analysis.invalid` 和禁止出站的 Doer；检查冻结 payload/hash/参数一致，再生成独立请求/响应副本。保留完整 int64 seed 字面值，缺失 Usage/TTFT 为 null；不导出 ProviderRequestID、原 HeaderSummary、ContentType 或任意上游错误/警告文本。事件头尾缺口显式 `event_summary_partial`。
- [redact.go](../../internal/integrity/evidencedisplay/redact.go)：固定 `display-redaction-v1`，每值生成 14 个候选变体后去重；最长匹配优先。Key/每个 Header 值至多 8192 字节，Key + Header 名/值总量至多 32 KiB，32 个 Header，字典 2 MiB；非空不足 4 字节、掩码碰撞或疑似第三方秘密整份拒绝。请求/Content 1 MiB、载荷 4 MiB、事件 256；编码分配前保守计长，有界 writer 检查取消，Prepare 使用最长 2 秒的上下文预算。预算不是可抢占任意 Go 指令/不可信回调的硬实时保证。
- [secret/display.go](../../internal/integrity/secret/display.go)：`KeyRing.NewDisplayCapabilities(clock)` 返回只复制 display 派生键的 `DisplaySealer` / `DisplayOpener`；二者不保留 KeyRing，不具备凭证/分析解密方法。`Seal(ctx, DisplayBinding, *Prepared)` 和 `Open(ctx, DisplayBinding, DisplayRecord)` 使用随机 96-bit nonce、AES-256-GCM、精确 AAD 和闭合错误。`DisplayBinding` 时间明确为 UTC Unix 微秒，采集不能在未来，恰好到期即拒绝，封装期限最多 180 天；时钟只能由可信启动装配，nil 使用 `time.Now`，不是 HTTP 参数。最终当前保留策略/cutoff/数据库授权尚未实现，crypto 的期限检查不替代它们。
- [secret/envelope.go](../../internal/integrity/secret/envelope.go)：仅新增 `evidence-display` purpose 派生和对应 keySet 字段，未更改已有七个用途的派生参数或输出。

私有载荷的实际 `source_hash` 为：`SHA256("mii/display-source/v1" || NUL || 已核对的 wire request hash || NUL || json.Marshal(原 NormalizedResponse))`，其中 `||` 表示字节连接，`NUL` 表示一个零字节。该固定版本/域分隔明确来源种类；它既不是原始 HTTP `ResponseHash`，也不是版本化分析证据 `EvidenceRecord.ContentHash`。它在脱敏前计算，即使将来 0 天不保存分析密文，也不假造分析密文哈希。独立 `template_hash` 覆盖实际脱敏 request JSON，`request_changed` 表示该 payload hash 是否不同；独立 `PayloadHash` 覆盖完整展示载荷。未来 Worker/repository 必须从权威同一 Attempt 装配并持久绑定这些不同语义的字段。

`WithCanonicalForSeal` / `WithCanonicalForDisplay` 是可信内部 codec 边界，不是普通 MarshalJSON 或任意 HTTP raw getter；借用 byte buffer 在返回、错误和 panic 时清零。调用者自行复制/日志记录的字符串无法强制追回。`DecodeAuthenticatedCanonical` 名称和注释明确要求先经 display AEAD；它本身不认证来源，不产出可 seal 的 Prepared。持有密钥的可信进程仍须正确装配，不能将纯一致性验证宣传为数据库身份认证。

### 本地测证与未证明事项

回归文件为 [redact_test.go](../../internal/integrity/evidencedisplay/redact_test.go)、[boundaries_test.go](../../internal/integrity/evidencedisplay/boundaries_test.go) 和 [display_test.go](../../internal/integrity/secret/display_test.go)。覆盖固定变体（含 Unicode surrogate pair）、全部 Header 值、重叠/短值/限额/取消、元数据省略、输入与分析字节不变、精确请求绑定、值及指针的 fmt/json/slog 脱敏、借用清零、跨用途/AAD/密文篡改、到期/旧键轮换、并发复用和非 canonical 认证载荷拒绝。七个既有用途以及新 display 用途均有公开合成主密钥的独立 HKDF/key/MAC 固定向量，旧 Envelope/evidence/baseline 等原有单测继续运行。

本地 Windows、项目固定 Go 工具链实测：

- `go test ./internal/integrity/evidencedisplay ./internal/integrity/secret -count=3 -cover`：全部通过，最终覆盖率分别 86.8% / 81.3%，耗时 0.797 / 0.529 秒；secret 包包含原有功能而非仅新文件。
- `go test ./internal/integrity/evidencedisplay -run '^$' -fuzz '^FuzzPrepareKnownCredentialDoesNotLeak$' -fuzztime 15s -parallel 2`：通过，59,793 次执行，16.408 秒。
- `go test ./internal/integrity/secret -run '^$' -fuzz '^FuzzDisplayEnvelopeRejectsChangedAuthenticationTag$' -fuzztime 15s -parallel 2`：通过，65,509 次执行，15.144 秒。
- `golangci-lint run ./internal/integrity/evidencedisplay/... ./internal/integrity/secret/...`：0 issues。
- `go test ./... -run '^$' -count=1`：全仓编译兼容性通过；这是只编译、不运行用例的检查，不冒称全仓功能回归通过。

主任务集成复核已完整读取上述9个文件；两包三轮再次通过0.500s/0.476s，覆盖率86.8%/81.3%，相关evidencedisplay/secret/identity/API/repository lint0。未把此组件验证升级为真实Worker双库或正文读取验收。

最终取消边界反例在修复前使 Seal/Open 两个子例失败：ctx 在最后一次可信时钟检查期间取消，仍返回了结果。修复为先完成最终到期观察，再核对 ctx，现反例与原回归通过；这属于本批尚未提交组件的开发自查，不能描述为已上线事故。

这些是纯组件/crypto 测证，不是真实 Worker 双库/浏览器/付费模型联调，不证明正式安全审核通过。固定一层变体以外的编码不保证识别；专门回归明确双层 Base64 可原样保留，不能宣传“绝无秘密”。旧 v1 密文、正文读取权限/审计、单调 cutoff、0 天正常分析/报告、复现制品导出与前端仍未接入，不因这批单测通过变为已完成。
