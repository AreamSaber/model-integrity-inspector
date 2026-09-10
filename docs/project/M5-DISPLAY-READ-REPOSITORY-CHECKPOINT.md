# 响应展示读取仓储 checkpoint

root 最终集成：已完整复核生产代码、migration19、主/fault/migration/lifecycle 四份测试及共享 Source 状态修复。修复后在独占数据库时段运行 `go test ./internal/integrity/repository -run '^(TestEvidenceDisplayRead|TestExecutionLease)' -count=3`，实际 SQLite/PG 全部通过 73.345s；真实应用 0/30 天完整 TLS→正文 HTTP 三轮通过 75.585s。这轮应用尚不含后来新增的17项服务 Writer/并发槽子场景，后者须单独记录。

日期：2026-09-08。状态：仓储响应正文授权读取生产接口、migration19及专项已通过真实SQLite/PostgreSQL三轮；root随后复核发现的Source值复制所有权/格式化保护问题已追加修复，纯红绿测试与lint通过，root实际修复后仓储/lease lookup组合三轮73.345s通过。暂不声称正式验收或REP-003/005、请求复现、清理完成。

## 已冻结API

- `DisplaySelection{RunID,SampleID,AttemptID int64; AnalysisRevision int}`；只接受revision1，AttemptID0是内部按SQL真实FinalAttemptID解析，HTTP由root限制显式正ID。
- `Tenant.PrepareEvidenceDisplay(selection)` → 私有 `*DisplayReadSource`；`Metadata()`安全固定scope/IsFinal/Status/PayloadHash；`WithEnvelope(func(DisplayReadEnvelope) error)` 仅借出clone，`DisplayReadEnvelope`精确为`struct{ Record DisplayEvidenceRecord }`；`Close()`清自有cipher/nonce。
- `DisclosureSummary{FormatVersion,OutputHash string; OutputBytes int64}`；固定`DisclosureFormatVersion=mii.evidence-display-output.v1`、1～8MiB输出上限。summary不是授权信息。
- `Tenant.CommitEvidenceDisplayRead(source,summary)` 真正commit成功后返回私有 `*DisclosurePermit`；`Begin(ctx,summary)`单次消费，`Revalidate(ctx)`逐块fresh只读身份/权限/政策/对象元数据检查，`Close()`终止。单次状态共享私有指针，按值复制permit不能重放。
- Source原始身份/context/会话原期限及最长10s固定；准备查询子ctx2s不会保存到Source。Permit最长2s，取原deadline、session及最终DB计算的sealed expiry/current window剩余时长更短者，用本机monotonic时间限制；不暴露可延长时钟/期限参数。

## 文件与实际边界

生产文件为`internal/integrity/repository/evidence_display_read.go`、`evidence_display_read_source.go`、`evidence_display_read_commit.go`；测试为同目录`evidence_display_read_test.go`、`evidence_display_read_fault_test.go`、`evidence_display_read_migration_test.go`、`evidence_display_read_lifecycle_test.go`。另含migration19 `000019_evidence_disclosures.up.sql`的common/sqlite/postgresql三个文件及`migrations/migrations.go`末尾注册、本checkpoint；历史1～18不改。没有request政策/table、raw fallback、Secret import或清理能力。

初读在同一read snapshot鉴权`run.read/evidence.read/evidence.body`再读取Run→已发布revision→Sample→指定Attempt，不加载ConfigSnapshot/RequestPlan/RequestSnapshot/结论大JSON。只接受合法terminal/scope/receipt；BodyRecorded但display缺行是ErrDisplaySource，即使当前days0也不能伪装普通缺失。legacy模式有合法display可读，不按legacy标签一刀切拒绝；历史未认证只能unavailable_legacy_unverified。

先SQL长度/数量guard，再有界metadata；final先Run锁和display `FOR SHARE`后读取完整cipher，第二次SELECT保持真实scope/hash/版本/时间/长度谓词，避免guard之后等待期间对象变成超大字节。full digest包含全部nonce/cipher及scope/metadata。Metadata/WithEnvelope只借clone、清临时buffer，不提供明文getter。

最终锁顺序复用management advisory→user/session→org NO KEY UPDATE→Run→display SHARE→audit head；receipt+审计同事务。receipt为S1-only，canonical SHA256加入审计ObjectID=`ID:hash`，固定action evidence.body.read/objectType evidence_disclosure/result authorized或unavailable，不修改旧audit canonical或把动态JSON塞ReasonCode。receipt禁止UPDATE/DELETE，后续清理需另行明确定义。

审计等待后再次取DB时间复验policy/expiry；保留managementTransaction自然会话到期尾部检查。未知commit结果没有permit。permit不持S2，Source.Close不破坏已授事实；每块只重验权限/原会话/政策/对象metadata，完整cipher已在grant绑定，避免每64KiB重复读取4MiB。grant后撤销与socket写无法共用原子事务，仍不承诺追回已发送字节或实现绝对“撤销后无一字节”语义。

## 实际验证

- repo编译检查通过；`TestEvidenceDisplayReadFormatting`纯测试通过，覆盖Source/Envelope日志与序列化保护及nil/零值/不完整permit闭合返回错误。
- 获root授权独占数据库时段后，`go test ./internal/integrity/repository -run '^TestEvidenceDisplayRead' -count=1`先后实际通过19.213s、22.505s。最终包含全部新测试的`-count=3`通过84.289s（session74110，exit0）。所有数据库用例均运行真实SQLite与既有本机PostgreSQL隔离schema；PG专项另实际观测锁等待。
- 最终repository lint为`0 issues`；专有文件`git diff --check`无错误。
- 真实仓储闭环：私有capture结算→发布分析→精确Attempt读取；内部AttemptID0选择实际final；显式早期重试Attempt不会被final替代。clone修改不影响源，借出buffer归还后清零；Source.Close不破坏已授permit；两个按值复制permit并发Begin恰好一个成功，后续重放拒绝。
- 授权与来源：原会话撤销、用户/成员停用、分别撤销三权限、换同用户另一会话、取消原ctx、实际管理设置0天、nonce/cipher修改、应有display缺行均拒绝。BodyRecorded缺行即使叠加0天也保持来源错误。无body权限时不会因Run存在性不同泄漏结果。
- 原子性：SQL审计故障回滚receipt与审计；审计持锁等待跨正文期限或原会话自然期限后不授permit且全部回滚；延迟外键在真正COMMIT阶段失败，同样不返回permit，且已执行的receipt/audit更新完整回滚。
- 真实PG锁调度：独立事务持audit head，`pg_blocking_pids`证明grant确实等待；等待期间另一事务修改display会因FOR SHARE超时，随后DB时钟越过sealed expiry再释放head，grant拒绝且无残留receipt/audit。
- grant后逐块检查：政策归零、撤权、原ctx取消、实际display缺行拒绝后续Revalidate；不新增逐块audit，原authorized回执保留其既有授权事实。
- 有界读取：注入超限cipher的受控坏库反例，确认在nonce/cipher投影查询前由SQL长度guard拒绝，统一ErrDisplaySource。
- migration18→19：真实旧raw/display字节保持不变；注入DDL失败时ledger仍18、表/触发器及PG函数均完整回滚；去掉故障后重试19成功且不伪造历史披露回执。

## 保留边界与交接

root追加复核的值复制问题：旧Source导出值内含独立mutex/closed但共享cipher切片，且Source/Permit保护方法只有pointer receiver。实际纯红测复现值JSON/格式化/日志保护绕过、复制Close后原对象仍可借出已清空bytes、零值WithEnvelope panic。修复为Source仅持共享私有state指针，Source和Permit的格式化/JSON/日志保护改为value receiver；保留Permit共享atomic一次性状态，Source所有读/关闭/授予使用同一mutex/closed状态，nil/零值/空state闭合拒绝。纯测试还覆盖并发复制Close不会清除已借出的独立clone、归还后clone清零；`^TestEvidenceDisplayRead(Lifecycle|Formatting)`十轮0.109s PASS，repo lint0。前述84.289s双库证据发生于此追加修复之前；root随后独占串行执行修复后`^TestEvidenceDisplayRead|^TestExecutionLease`组合双库三轮73.345s PASS，真实app旧0/30天三轮75.585s PASS（均由root报告，本agent未重复启动数据库测试）。

仓储测试使用结构合法的合成display envelope，并不替代AEAD解密证明。root独立负责真实TLS→DisplayOpener→service→HTTP及浏览器；root已报告实际0/30天双库app首轮25.542s通过，但其服务可复制值生命周期补测、前端及最终集成复核仍归root，不计作本agent完成。

本单元不提供明文getter、原始密文回填、请求复现、历史正文清理或tombstone；每块Revalidate也不重新AEAD解密。真实审计commit与网络输出仍存在不可原子耦合的边界，不声称收件人已接收或撤权能追回已发送字节。

本agent未执行Git、未改legacy冻结文件和全局台账。先前专项测试已结束并已向root归还数据库时段；无本agent在途测试。追加生命周期修复及root复测结果已冻结记录，后续双库只在root明确重新授权时执行。
