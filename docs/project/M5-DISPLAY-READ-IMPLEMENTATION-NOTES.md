# REP-003 / REP-005：授权正文读取与独立请求复现实施方案

日期：2026-09-08。本文保留授权正文/独立请求复现的历史设计，以下拟议接口不是当前代码签名的权威来源。响应正文读取仓储已提交 `22c9046`；服务/API/app 与前端已实际接线并验证，最终集成进度见 `M5-DISPLAY-READ-INTEGRATION-CHECKPOINT.md`、`M5-DISPLAY-READ-REPOSITORY-CHECKPOINT.md`、`M5-DISPLAY-SERVICE-PIPELINE-CHECKPOINT.md`。请求复现仅独立纯组件已提交 `6031891`，本文的请求策略/存储/授权导出仍未实现；不能把设计或响应正文交付算作 REP-005 完成。原始 77 项需求与 M5/M6 审核状态不变。

## 1. 原需求与现有能力

需求依据：

- PRD §6.2，第 155–173 行：正文与脱敏证据分权；API Key 对任何角色均不可回显。§9.8 第 406/408 行分别是 REP-003 样本参数/脱敏正文/响应/Usage/停止原因/耗时与 REP-005 无真实 Key 的复现模板。§10.3 第 478–484 行要求权限、关闭响应留存与导出范围提示。
- PRD §11.1–11.2，第 490–505 行：完整请求/响应、Endpoint 私有参数是 S2；响应默认 30 天、可配置 0～180 天，脱敏样本摘要默认 180 天。**180 天摘要政策并未直接授权将完整请求作为普通摘要保存/公开。** 请求复现保留必须明确仍是 S2。
- PRD 第 552 行使用 `${API_KEY}`；第 667 行要求导出和受限正文访问审计；第 758 行及 TECH 第 1806 行明确关闭响应留存不影响摘要/报告。PRD 第 89 行的可复现证据目标不能用“所有 0 天 Run 都不可复现”关闭。
- TECH §8.2 第 465 行：nonce 明文仅供复现，不进普通日志；§10.10 第 955–959 行区分请求快照/可选密文/脱敏展示；§13.4–13.6 第 1281–1297 行明确 S2、纯文本、组织隔离和强制审计；§18 第 1523–1528 行要求到期删除、保留哈希/摘要、删除凭证且不改原报告哈希。
- 开发计划 M5-04 要求样本删除/过期状态可解释，M5-08 覆盖导出；完整入口还包括 API、前端、契约、安全反例，不是增加 repository getter 即完成。

已核对的可复用实现：

| 能力 | 实际代码 | 不能误用为 |
|---|---|---|
| 权限默认值 | `internal/identity/permissions.go:8`：只有 admin/auditor 默认有 `evidence.body`；所有内置角色都有 `evidence.read`；另有持久显式授权 | 角色名、创建人身份、`report.export` 或 `evidence.read` 自动授正文权 |
| 身份私有能力 | `api/targets.go:68`、`repository/controlauthority.go:24` | HTTP 提交 user/session/org IDs 即可信 |
| 结果一致读取 | `repository/run_history.go:95` 的 `resultReadTransaction(true)`；PG REPEATABLE READ/SQLite DEFERRED | 正文授权；该函数只筛 `run.read/evidence.read` |
| 最终授权事务 | `repository/controlauthority.go:93`、`identity_management.go:77` | 长时间持锁做解密或网络写入 |
| 报告下载范例 | `repository/report_read.go:88`、`run/report_service.go:159` | 原始响应解密接口，或 DB commit 与 socket write 的原子事务 |
| 当前响应政策 | `response_retention.go:36/110`、`identity_management_organizations.go:123` | 预检查快照永久有效；单看当前 days 可以复活旧正文 |
| 展示存储/receipt | `execution_display.go:31`、`execution_derived.go:20`、`execution_derived_body.go:131` | `recorded` 必定有可展示正文；display 也可能是明确失败 marker |
| 展示专用密码能力 | `secret/display.go:75/177`：只复制 display-purpose keys 的 Opener，精确 AAD、期限、版本、哈希、canonical decode | 用户授权、当前组织政策或原始分析/凭证解密能力 |
| 有限脱敏与私有载荷 | `evidencedisplay/prepare.go:161`、`types.go:172/182` | 任意编码/任意第三方秘密都能识别；公开 JSON getter |

已有响应展示封装的 `SourceHash` 是专用 pre-redaction request/NormalizedResponse 摘要，既不是原始 HTTP ResponseHash，也不是 raw evidence ContentHash。使用现有 binding，不新增一套响应展示格式、不比较错误种类的哈希。

## 2. 最小落地接口：准备不授予释放权限

以下是拟新增接口，不是现有 API。采用现有 `run` service 目录，不新增抽象服务框架。

```go
// repository：只接受历史选择器，不接受授权标志、权限字符串、时间或密钥。
type DisplaySelection struct {
    RunID, SampleID, AttemptID int64
    AnalysisRevision int // 第一单元只接受 1
}
func (t *Tenant) PrepareEvidenceDisplay(DisplaySelection) (*DisplayReadSource, error)
func (t *Tenant) PrepareRequestReproduction(DisplaySelection) (*DisplayReadSource, error)

// Source 私有字段绑定 store、actor/session、org、固定动作、选择器、
// 全部 envelope 字节摘要与历史图；普通 fmt/json/slog 不泄露敏感字段。
// 仅可信 service 可以借用一个有界加密投影；不含任何明文和通用 SQL 能力。
func (s *DisplayReadSource) WithEnvelope(func(DisplayReadEnvelope) error) error

// permission/action 由对应具体入口固定，不能由 HTTP 自选。
// 成功返回的 private permit 只能在事务真正提交后生成。
func (t *Tenant) CommitEvidenceDisplayRead(*DisplayReadSource, DisclosureSummary) (*DisclosurePermit, error)
func (t *Tenant) CommitRequestReproduction(*DisplayReadSource, DisclosureSummary) (*DisclosurePermit, error)

// run service：持有 Store + DisplayOpener（后续另有 request-only Opener），
// 不持有 KeyRing、Secret service、网络 client、任意文件读取器。
func (s *EvidenceService) PrepareDisplay(ctx context.Context, org int64, selection DisplaySelection) (*Disclosure, error)
func (s *EvidenceService) PrepareReproduction(ctx context.Context, org int64, selection DisplaySelection) (*Disclosure, error)
func (d *Disclosure) WriteTo(ctx context.Context, dst io.Writer) (int64, error)
func (d *Disclosure) Close()
```

`Disclosure` 不提供 `Bytes()`、`String()`、公开正文 DTO 或自由回调解密 getter。它持有受保护的编码缓冲和并发槽，只有 `WriteTo` 内部能启动最终授权提交；不能在 Prepare 后把明文交还 handler 再期待 handler 自觉复验。route 只得到固定安全 MIME/文件名和 S1 元数据；正文写入经过 service 的单次消费路径。需要 JSON envelope 的 ID/request_id 等亦在这个路径内编码，不能先 `c.success` 再补审计。

建议服务固定 4 个准备槽，不等待无限队列；源密文最多一个，响应展示明文最大现有 4 MiB、请求正文最大 1 MiB，出站编码另有明确总 cap。准备、编码、释放均使用更短者：原 HTTP context deadline 与服务固定期限。建议准备 2 秒、总生命周期至多 10 秒、单次 write 至多 2 秒作为首个待验证配置，不能由请求方提高；这些是设计建议，不是已经通过的性能指标。

`DisplayReadSource` 的 cipher projection 只使用 repository 类型，由 service 装配现存 `secret.DisplayBinding/DisplayRecord`，不让 repository import secret。`DisclosureSummary` 只能包含固定 action/result、投影格式版本、输出 byte count/hash；它不是授权来源，最终事务必须用私有 Source 的真实 scope。permit 绑定同 store、用户、会话、组织、选择器、action、source digest、输出 hash、最长释放期限及单次消费状态，不能换 ctx 的身份或延长原期限。

## 3. 初次读取：授权快照内先元数据和字节 guard

1. 复用 `authorizeOrganization(..., "evidence.body")`、审计 actor 和 `BindControlAuthority`；无权限/跨组织先失败，不根据外组织对象的过期/缺失状态形成存在性探针。
2. repository 先复用 `resultReadTransaction(true)`，在同一快照里以固定 SQL 允许集合再核对 `evidence.body`；复现另需 `report.export`。不能只在 handler 检查，也不能硬编码“创建人允许”。admin/auditor 是默认授权，运营/开发显式授权走已有持久 grant；不私自扩展默认角色能力。
3. 直接核对 scoped Run → 已发布 revision 1 → Sample → 指定 Attempt 与 RequestHash、AttemptNo、最终指针/结算时间；不要复用 `ReadPublishedResult` 去加载整个大结论文档。默认选择最终 Attempt 时，必须在 SQL 中取真实 FinalAttemptID；明确选择重试时返回 `is_final=false`，不可挑最好的一次。
4. 先读取一个 bounded metadata projection、状态和 `OCTET_LENGTH`/SQLite BLOB length；ciphertext ≤ 4 MiB+16、nonce 12、版本/key version/hash/policy 有固定长度。之后最多取一个对象的完整密文，WHERE 保持全部 scope 和摘要条件；不要只 guard 某行然后按较宽条件重取。
5. 同快照读取组织政策，应用 immutable sealed expiry、current day window、monotonic cutoff。保护资源的实际请求哈希来自 Attempt，不从 payload 自声明取代。当前目标删除/轮换不能迫使读旧/新凭证；历史展示依靠自己的封装，不依赖当前 Target/Secret 有效。
6. Source 的私有 digest 包含完整封装、scope、版本、状态、hash、采集/到期时间及必要历史图，后续不得只比较一个 caller-supplied PayloadHash。摘要是读后变化检测，不是抗管理员一致重写数据库的证明。

解密在事务外完成：Opener 验证现有精确 AAD/封装期限/完整性，`WithCanonicalForDisplay` 仅交给受控 codec；响应投影按已有 document 严格字段输出，复现投影只选择 request_json/template_hash/request_changed 和固定说明，不能把整份 response 顺带导出。普通 logging/错误对象不持有借用字节；Close 清除自有 buffers，不能承诺 Go 字符串/外部副本的物理擦除。

## 4. 最终 grant、锁与审计的线性化点

推荐顺序如下。箭头中的解密/编码不持 DB 锁；最终 grant 的所有 SQL 要么一并提交，要么全部回滚。

```text
初次授权快照 → 私有密文 Source → 锁外 Open/验证/受控编码
                                  ↓ 不释放任何明文
最终管理事务：fresh 身份/权限 → org policy → Run/对象锁
             → 源摘要一致 → append 成功授权审计 → 锁后新时钟/自然期限复验
                                  ↓ COMMIT 真正成功
单次短期 release permit → 期限/取消检查 → 有界发送 → Close
```

最终事务复用 `controlTenantTransaction("evidence.body", ...)` 和现有 `managementTransaction`，并再次复验其他两个/三个固定权限。PG 锁顺序：management advisory mutex → user/session → organization `NO KEY UPDATE` → Run → 对应 display/reproduction 行 `FOR SHARE` → audit head。SQLite 延续 IMMEDIATE。不做 Run→organization 倒锁，不改成与 audit FK 冲突的组织 `FOR UPDATE`，不额外引入 Sample/Attempt 逆序锁。

组织、会话、成员/角色的应用变更与该事务通过既有 management mutex/user/session/organization 协议串行。最终图来源仍依赖应用 Run 锁协议；display/reproduction 的物理行锁防最终摘要检查至提交间直接 UPDATE/DELETE。删除/清理的未来实现必须采用同组织→Run→对象→audit 协议，不能由后台绕过。

最终必须检查：原私有 source 所属身份/动作、仍有效的同一已发布修订、Run/Sample/Attempt 关联和选择语义、存储模式/receipt、完整 envelope digest、当前政策/cutoff/显式删除状态。**即使初始 read 和 Open 成功，解密/编码期间已经提交的撤权、会话撤销、禁用、政策 0/缩短、删除或对象变更都必须在这里拒绝。** 不能仅重验最初 permission 切片。

自然时间不能被行锁冻结：先取得组织锁，再调用 `queueTime`（PG `clock_timestamp()`，SQLite 同机时钟）；等待 audit head 后，必须再次取时更新当前 observation，重新做 sealed expiry/day window/cutoff 检查。`managementTransaction` 已在成功 callback 后用原 session.ExpiresAt 再验自然到期（`identity_management.go:140`）；保留该身份时间语义，不盲目改为与业务政策混用的新时钟。最终 body grant 需新增对应的政策/封装到期尾部复验，不能认为 Opener 自己的两次时钟检查已覆盖 DB 锁等待。

`commit` 报错或结局不确定：不生成 permit、不释放字节。审计可能已提交但客户端未收到数据属于“授权已记录但没有确认送达”，不得为了避免多一条审计而释放未经确认的内容。一次性的消费状态只在明确最终成功后进入可发送态，失败/取消/Close 都清理 buffers/槽。

### 审计如何真正绑定这次释放

现有 `AuditCommand` 只有 action/object type/object id/result；`appendAudit` 的 DiffSummary 仅包含固定 reason_code（`repository/audit.go:26/48/89`）。因此不能声称现有 helper 已把 run/sample/attempt/revision/policy/hash/字节数全部审计。

建议同一后续迁移加入轻量、S1-only 的 `integrity_evidence_disclosures`：ID、组织/操作者、固定动作、Run/Sample/Attempt/revision、源种类/封装 policy、source receipt digest、payload/output hash、输出字节数、观察政策 version/cutoff、授权时间、闭集结果。无会话哈希、Key、nonce 明文、请求/响应、Endpoint 或任意诊断。最终事务创建该行并调用现有 `appendAudit`，object type 为固定 `evidence_disclosure`、object ID 为该行 ID，审计与 receipt 同事务。审计 failure 则 receipt 也回滚。若选择扩展 audit helper 的 typed metadata 替代该表，须单独冻结 canonical/大小合同，不能把 JSON 塞进 ReasonCode。

成功事件准确表示 `authorized`，而不是宣称浏览器已经读完。显示与复现分别是 `evidence.body.read`、`evidence.reproduction.export`；正常不可用也记录固定 unavailable 结果。未经授权的访问不记录不存在的对象详情，可沿已有认证失败路径记录固定拒绝事件；不能在已失败事务里追加事件后假称它会保留。

### 发送边界不能做过度承诺

唯一强制成功审计提交发生在**首次明文释放之前**。后续每块只做 fresh read-only 权限/政策/身份绑定复验与 permit 生命周期检查，不通过“先明文、后每块成功审计”伪造原子性。任何后续失败立即停止未发送部分；已发字节无法撤回。

DB COMMIT 与 socket Write 没有共享事务。合理合同是“每份有界输出在 grant 成功提交处取得一次短期授权”；解密期间先提交的禁止一定拒绝，grant 之后才提交的撤销不能倒转这个已经授权的操作。为缩短窗口，WriteTo 才做最终 grant，提交后立即检查原 ctx、session 期限和剩余可释放时长，逐小块（建议 ≤64 KiB）复验，首块也不跳过。

若要求“撤权提交后无论何时都不再有一字节进入 socket”，即使撤权恰落在最后一次数据库检查与 Write 之间，也无法由以上短事务保证；必须引入跨 API 实例的发送/撤销协议或在网络写期间持锁，后者会把慢客户端带进管理/审计全局锁，不建议当最小实现。本方案**不**声称达到该更强合同，不承诺已在 socket/客户端的字节可追回。

自然 expiry 同样无硬实时保证：permit 用最终数据库时间计算短的剩余时长并约束本机 monotonic deadline，Opener 与原会话期限也各自 fail-closed；deadline 在真正 Write 前再查。不能用可任意注入的 clock、请求时间戳或 Background ctx 延长。极端调度暂停/内核传输也不能被 Go 检查瞬时抢占，应如实限定到授权线性化语义。

## 5. 可用与不可用闭集：不把丢记录伪装正常缺失

身份/租户失败优先，返回现有 401/403/404；不返回外组织状态。通过授权且历史 scope 完整后才有下表。字段名和 HTTP 码需随实现写入 OpenAPI/反射合同；以下不是已注册契约。

| 事实 | 建议状态/行为 |
|---|---|
| 已认证 captured envelope、最终政策/期限均允许 | `available`；有界正文或模板 |
| 当前响应 days=0，未违反记录存在性合同 | `unavailable_policy_zero`；请求-only 复现不随之禁用 |
| BodyNotRetained 或未来 request not-retained receipt | `unavailable_not_retained`；不能猜当时是 0 天、缩短还是到期 |
| BodyNotCaptured / 明确旧 capture 失败 | `unavailable_not_captured` 或已有闭集 display failure marker |
| UNCERTAIN 无可信响应副本 | `unavailable_uncertain`；不是“上游没有响应”的断言 |
| captured 行存在，可信采集/封装时间已落在 sealed expiry/current window/cutoff 外 | `unavailable_expired`；不依赖物理清理已执行 |
| 明确不可变删除/清理凭证存在并匹配该对象 | `unavailable_deleted`；现缺此凭证，不能凭 SQL 查无行猜删除 |
| 历史只有 raw v1、没有已认证 display/request 捕获证明 | `unavailable_legacy_unverified`；禁止解密 raw 兜底、读当前/旧 Key 补证或重签历史 |
| 已存在已认证 display-purpose 对象，但 Run 的分析模式是 legacy | 仍可按其真实 display envelope 资格读取；不能按 Run legacy 标签一刀切否定已有 Phase 2 展示证明 |
| BodyRecorded 且要求的 display 行缺失，无删除凭证；重复/跨 scope/未知状态/policy/超限/破损摘要 | 闭合 source-invalid/503，不当作普通 not-captured |
| 本次 Opener 的 unknown key/AEAD/schema/哈希失败，DB/审计失败 | 闭合 unavailable/503；不能伪装过期或自动切回 raw；不暴露密码学具体失败 |
| 本次请求取消/超时 | 不释放；已发送则停止，不能补写另一段 JSON 错误到部分正文后面 |

`DisplayCaptured` 对应 envelope；已有 `unavailable_redaction_policy/safety_limit/source_invalid/cancelled/capture/seal` marker 是持久的采集结果，可映射为其自身可解释状态。本次读取发生的同名错误不是持久证明，不能混用。不可用内容为 null，不以空字符串或伪造空响应代表缺失。摘要/Usage/Attempt/S1 继续通过原轻量接口读取。

后续物理清理必须同时写有 scope、源种类、原 hash/采集/封装到期时间、固定删除原因/时间的 S1 tombstone，并删除 nonce/ciphertext；与删除审计同事务。当前 display failure 行要求所有 envelope 字段为空，不可擅自拿该格式塞删除证明；应新增明确 tombstone/状态迁移。先前已丢失的行没有事实不能回填“已删除”。

## 6. REP-005 完整目标：请求复现与响应留存分离

### 为什么需要新增前置

现存 display document 把 request_json 与 response 一起封装，SourceHash 也包含真实 NormalizedResponse；0 天根本不保存这个 envelope。它不能通过填一个空 response 冒充请求-only证明。冻结 pre-auth RequestSnapshot 没有 Authorization，不代表消息/model/stop 中从未含实际 Key/Header 值。HTTP 不能用原始快照或当前凭证补做一个“差不多”的模板。

**最终目标**：新正常运行在响应 0 天时仍保存按独立请求政策允许的、在真实凭证作用域脱敏并认证的请求复现副本，从而请求模板可正常使用；响应正文仍不可用，S1 分析/报告仍完整。历史未可信捕获、显式关闭请求 S2 留存、到期或安全拒绝必须明确原因，但不能把响应 0 天常态不可用当 REP-005 最终交付。

### 请求 S2 保留政策建议（需要 PO/SEC 明确批准）

新增独立 `request_reproduction_retention_days`，建议默认 180、范围 0～180，另有单调 request cutoff；响应 0 不修改它。180 天作为与样本复现/摘要窗口协调的**新增选择**，不是宣称 PRD 已把完整请求降为摘要。完整请求仍加密、`evidence.body` 授权、导出审计、可单独关闭/删除；不得写默认列表/普通日志。增长不延长已封装 expiry，0→180/缩短→增长不复活旧副本。没有这个独立设置及通知，直接保留 180 天完整请求会是未说明的数据政策扩张。

现有长期 RequestSnapshot/ConfigSnapshot 供可信执行/分析，尚无完整 S2 生命周期，不能因增加复现 envelope 就宣称所有请求明文留存问题已处理。须在 M6 生命周期单元定义这些冻结 S2 的保留、清理与失去重分析能力的语义；默认摘要 180/聚合报告 365 不自动覆盖其合法性。

### 可信捕获和密码能力

- 新建 request-only 的版本化私有 Prepared/Opened（例如 `PreparedReproduction`），共享 `requestForDisplay` 的确定性 wire 校验和既有固定字典脱敏算法；不要复制另一套 adapter 编码，也不要伪造 response 复用旧 envelope。
- 载荷只含：固定格式/脱敏策略、actual request hash、独立 template hash、request_changed、已脱敏 canonical request JSON、允许的固定认证种类/必要 placeholder 数量、冻结协议版本/参数说明。Endpoint 整体是占位，不保留真实 Header 名/值；明确 kind=`request-reproduction`。
- 使用独立 request-reproduction purpose 的 Sealer/Opener 和精确 AAD（org/run/sample/attempt/request hash、manifest hash、版本/policy、captured/immutable expiry、payload hash/bytes/key version）。启动注入的 opener 不得保留通用 KeyRing/Secret 能力。新 purpose/新 envelope 必须有独立向量及 cross-purpose 失败测试，既有 display/source 格式不变。
- 准备必须在当前 `Credentials.Use` 中，拿实际 Key 和**全部**自定义 Header 值。最稳妥位置是 `executionDoer.Do` 的实际 Request body 已核对、ReserveAttempt 成功之后、调用 `client.Do` 之前（`worker/execution_http.go:40`）；不能只在收到响应后捕获，否则超时/崩溃的派发永远丢请求复现。
- 密码工作放在短 SQL 事务外：实际 Reserve 返回 scope → 受 lease 约束取得私有 request capture/数据库采集期限 → 在同 credentials 作用域 Prepare+Seal → 新短 WithLease 同事务核对实际 DISPATCHED/lease/hash、写 request envelope+receipt+审计 → 才继续当前 Do。两个短事务间崩溃可明确为 missing historical capture，不能制造“已发送成功”；捕获记录证明 dispatch intent 的精确请求，不证明字节到达上游。
- 必须持久化独立 request receipt（legacy-unverified/pending/recorded/not-retained/闭集 capture failure），与 response receipt/S1 receipt 分开。正常必需的 record 丢失闭合失败；恢复可保留之前已认证的请求副本，但不得无 Credentials.Use 从旧快照补造。DB/审计失败不得让未确认持久捕获的动作偷偷继续出站；脱敏安全拒绝如何继续真实检测需保留现有实际 Attempt 计数/错误状态，不伪称复现成功。
- 记录通过真实 Attempt FK 绑定，不能开放 HTTP 上传 envelope；不会替换原请求 hash/旧 Manifest、改变原 Token 统计或偷偷落响应。0/7/30/180 响应政策均应与同一独立 request 政策组合验证。

建议新增三方言迁移，编号由 root 分配：request-only encrypted table、request receipt、独立组织 request policy/cutoff、约束/删除 tombstone，以及所选 disclosure receipt。旧记录一律 legacy-unverified，不解密扫描/猜测回填；不把迁移存在当作前置捕获已接好。

### 复现制品安全合同

默认导出纯 JSON 数据制品，不输出可执行动态 shell。包含 POST、`${ENDPOINT}`、`${API_KEY}`、固定可选 `${AUTH_HEADER_NAME}`/编号自定义 header placeholders；不包含真实 host/path/query/userinfo/fragment、Key 的片段或任意原 Header 名值。认证种类仅来自已捕获固定枚举，无法证明时输出通用说明，不能读取当前 Target 猜历史。

模型/temperature/top_p/seed/stop/stream/实际 max_tokens 参数来自已认证 request_json；大 int64 seed 用 RawMessage/整数保持原字面值，不能经 JS Number 破坏。request_changed 和 actual request hash/template hash 必须区分；脱敏后不声称逐字节相同。重试导出固定 Attempt，不默选最终/最好的一次。

禁止把任何模型输出、Endpoint、model、stop、反引号、`$()`、引号、换行或探针正文拼成 curl、PowerShell、heredoc/eval。若以后附执行说明，命令必须完全静态、请求体来自独立文件，且不由产品自动执行或自动产生付费请求。当前先交付可审查数据、版本/哈希/差异与不保证相同上游输出的说明。

## 7. HTTP/页面与待实现文件范围

建议固定 scoped 路由仍沿前方案：`GET /runs/{run}/samples/{sample}/attempts/{attempt}/evidence?analysis_revision=1` 与同级 `/reproduction`。实际实现时只接受规范正十进制 ID、已支持修订、单值 query；禁止请求方提供 path、expiry、权限、policy 或任意格式。复现导出额外 `report.export`，显式 S2 范围提示；不改变普通 JSON/HTML 报告当前不含受限内容的合同。

响应 `no-store`、nosniff、no-referrer；复现 attachment 使用固定 ID 文件名、固定 JSON MIME；不允许 Range/浏览器缓存/条件 304 绕过授权。页面明确点击后加载，纯文本转义、不解释 HTML/Markdown，不写 localStorage、查询日志或默认共享状态。组织/用户/Run/Attempt/revision 切换和 401/403 必须 abort+清空，迟到响应不得回填旧 scope。

候选实施范围：新 `repository/evidence_display_read.go`、`run/evidence_display.go`、`api/evidence_display.go` 及 tests；必要的窄 authority/retention 复用 helper；app 仅注入用途隔离 opener；OpenAPI/反射契约和独立前端。REP-005 全目标另需 request-only codec/secret、Worker pre-Do capture、repository receipt/policy/迁移/清理。所有权按下一任务分配；本文没有更改这些文件。

## 8. 必须验收的可执行反例（本轮未运行）

1. 双库真实管理权限：admin/auditor 默认允许；operator/developer/viewer 无 body 权限拒绝；已授/撤销的显式 body 权限、缺 run.read/evidence.read、复现缺 report.export，跨租户/对象存在性不泄露。
2. 实际 TLS 捕获 → SQL → DisplayOpener → HTTP，Key 与全部 Header 的明文/固定编码 canary 不出现；旧 raw/当前或旧 Secret getter 在该服务中不可调用。
3. 在解密成功后、最终 grant 前 gate：实际管理 SQL 提交 revoke session/disable user/member/revoke grant/response days0/cutoff/删除，断言 **writer 调用数和正文数均为 0**。
4. PG 用独立连接与 `pg_blocking_pids` 证明 org/object/audit 等待；等待跨过 sealed expiry/current window/session 自然到期。SQLite 在真实同事务 audit SQL gate 跨期，最终回滚且零 writer；不要把事先已过期当作跨期证明。
5. 最终审计失败/commit 失败/尾部取消，不得返回可消费 permit、不得释放；合法 grant 后慢客户端撤销则停止剩余块，明确此前已发送不撤回。一次性 token 重放/换用户、篡改动作/hash/ctx 延长期限均拒绝。
6. captured→缺行/换 nonce/ciphertext/expiry/policy/key/hash、交换两条完整 envelope、孤立 scope、历史 retry、未知状态和 byte cap 均失败；有 raw 也不回退。合法 tombstone 与无事实的 missing 必须区分。
7. 独立请求保留：response0/request180 实际无 raw/display response INSERT 但有认证 request-only envelope；完整请求模板可授权导出，S1/分析/报告不变。request0、180→7→180、0→180、过期/物理清理延迟、两事务崩溃/失租、轮换/目标删除均不复活、不伪造。
8. request-only 真实 pre-Do 捕获与 dispatch-intent 语义；响应超时、UNCERTAIN 恢复保留真实请求 proof，而旧无 proof 不补造；Crypto/SQL/AAD 失败不会凭“预认证请求”标签回退原文。
9. JSON/HTML/脚本片段、反引号、`$()`、CR/LF、超长 model/stop/大 seed、请求密钥恰为短值或 schema 标记，验证纯数据输出、整数精度、资源上限、无脚本执行、默认接口/日志/错误无 S2。

完成上述 backend 后仍需实际浏览器入口、可解释过期/删除状态、全契约与统一审核；目前只是可执行方案，不关闭 REP-003/005。
