# 响应正文保留清理：仓储工作单元

2026-09-08。实现范围为 raw/display 响应正文的真实每日调度、短批次物理删除、删除事实与审计、授权读取适配；Worker/app/HTTP/前端及报告状态由 root 集成。本工作单元不关闭包含样本180天、聚合/报告365天、审计密封分段的完整 M6-07。

## 冻结接口与存储

- `JobQueue.ScheduleResponseRetention(ctx) error`：复用真实 Runner consumer，每次最多发现16个缺少调度记录的组织、推进一个组织的一个 Run。持久日轮次、Run 游标、活动批次及最近观察时间；轮转包含停用组织，停用不是提前删除依据。失败/取消批次保留原 Job 结果，仅推进其 Run 的当日游标、继续组织后续 Run；次日新轮次重新检查失败 Run，不在每秒 maintenance 中无限重试，也不让坏首 Run 永久饿死健康后续 Run。
- `TenantTransaction.DeleteResponseEvidenceBatch() error`：无自由对象ID/时间/政策/限额/操作者输入，只接受当前 `CompleteWith` 的精确 `JobRetentionDelete` 批次 lease。旧 ObjectID=organization 的 queue-only Job 保留，但无清理能力；实际 Job ObjectID=batchID，持久 batch/job/run/creator、固定幂等键和组织活动批次必须一致。
- `Tenant.ReadResponseRetentionSummary(runID) (ResponseRetentionSummary,error)`：使用既有 `resultReadTransaction(true)` 与已发布 revision1，要求当前 `run.read` 和 `evidence.read`。字段为 ObservedAt、PolicyDays/PolicyVersion、AttemptCount、RawDeletedCount、DisplayDeletedCount、DisplayExpiredCount、DisplayRetainedCount、LastDeletedAt；均是 S1。Retained 是当前保留策略内的已存加密副本数量，不保证解密/披露资格，也不代表所有保留类型已交付。合法业务完整性错误保留 `ErrRetentionSource`；DB/取消继续既有安全错误分类。
- 新 migration020 仅追加注册，1–19保持原字节。新表 `integrity_response_retention_schedule`、`integrity_response_retention_batches`、`integrity_evidence_deletions`；原索引之外追加捕获时间/日调度/回执查询索引。新迁移不扫描解密或回填历史删除。

## 实际删除与信任边界

每批上限32个来源对象、8 MiB 实际 ciphertext 字节。只从 SQL 提取固定元数据及 length，不将 nonce/ciphertext 传入 Go 清理代码。先验证每个对象结构，再应用批次总量限制；单行破损不能被静默跳过为成功零批。

资格分别按 raw 的原 `CreatedAt/ExpiresAt` 与 display 的原 `CapturedAtMicros/ExpiresAtMicros` 判定。0天、原封装到期、单调 cutoff、当前day窗口是闭集删除原因；精确等号到期。未来/破损时间失败关闭，组织disabled不等于删除全部。0→30/缩短→增长不降低cutoff或延长旧封装expiry。

锁顺序为 consumer/精确Job → 组织 `NO KEY UPDATE` → 调度状态 → Run → raw/display对象 → audit head。组织锁后和对象锁后重新取现有DB时间；调度所有成功分支（包含插入后的早返回）统一尾部复验consumer。真正删除、删除item、completed批次、游标和审计在 `CompleteWith` 同事务，最终Job代次/owner/期限继续由原队列确认。清理单元在审计写入后另复验SQLite持久consumer owner/新鲜期限，不续租或复活已过期consumer。任何 SQL、审计、COMMIT、取消或fence失败都不能留下成功回执。

`Claim/reconcile`共用固定SQL，仅对精确org/batch/job/run/creator/幂等键且planned的清理Job豁免组织disabled限制，取消请求、尝试耗尽及坏租约仍执行原规则；旧org-only/普通Job/错误批次绑定不能借此在停用组织运行。

删除item保存原 scope、request/content/source hash、捕获/封装到期/删除时间、固定原因和实际字节；无正文、nonce、Key、会话hash或自由文本。批次canonical包含全部有序item和原政策观察，SHA-256以 `batchID:hash` 绑定实际既有HMAC审计事件。读取必须校验canonical、精确completed Job、实际审计签名/历史版本/操作者，不只相信普通SQL中的hash字段。仅本单元的审计私有helper使用同事务DB时钟，且audit head等待后重新观察，保持审计时间不早于批次时间的验证；其余既有审计caller时间和canonical行为不变。回执不能修改/删除；已删来源不能通过应用INSERT重新建立。

历史 Run.created_by 只表示存储工作的历史发起者，reason固定为 `response.evidence.automatic_expiry`；不是当前登录、当前成员权限或用户此刻审批，ctx中的伪造Actor不获信任。

保持 `BodyRecorded` 的历史捕获事实。合法display删除回执新增 `unavailable_deleted`，无回执丢行仍失败；回执与正文共存、错scope、摘要/签名破损或与Attempt receipt冲突不能降级成普通不可用。raw-only legacy删除不制造display捕获证明或派生S1。

summary对剩余display使用单条LIMIT1537联合Attempt的有界元数据查询，复用展示行结构验证和保留判据；未来捕获、Attempt范围/状态/receipt矛盾、损坏key/hash不计为正常保留。只投影固定字段和nonce/ciphertext长度，不取S2字节、不开逐行查询。合法`unavailable_seal`等无密文展示S1状态保持原样，不计为captured副本或伪造display删除事实。

S1、Attempt/Usage、Run Manifest/配置、已发布分析和原报告均不被清理代码修改。响应0天不自动决定独立request-only政策。基础schema仍存在的旧可选正文列，以及ConfigSnapshot/RequestSnapshot/RequestPlan、样本/报告/审计其余生命周期需要后续明确单元；不得据此宣称全部S2已清理。

## 已取得的真实证据

- 首轮专有双库：`TestResponseRetentionCleanup` **3.709s PASS**。真实仓储legacy/derived执行→发布→0再30策略→日调度→真实批次Job→物理删除→已删除授权读取、summary、不可复活；独立raw到期、权限、旧org-only Job、错误lease代次、20迁移回滚及历史保留。
- 扩大专有双库单轮 **26.736s PASS**：raw/display DELETE、item INSERT、batch UPDATE、audit INSERT、零行DELETE、真实延迟外键COMMIT、取消与末尾Job fence逐处失败，原子回滚且同lease恢复；audit签名/item篡改、原文共存、无凭证缺行、并发调度/完成，34来源对象分32+2批和重新Open/consumer后恢复。
- PG真实组织、display SHARE、audit head等待以 `pg_blocking_pids` 证明；释放后在原2秒ctx内完成。与SQLite consumer跨期专项合计 **2.779s PASS**。
- root只读复核指出调度早返回遗漏末尾consumer；新增真实SQLite INSERT后等待跨consumer期限+noeligible早返回反例。临时去除尾复验时实际 **FAIL 0.646s**（已过期仍返回nil）；立即恢复生产修复后与typed篡改专项 **4.207s PASS**。未保留红测变更。
- 真实10 MiB ciphertext对象在8 MiB批次上限下分为 **6 MiB+48字节 / 4 MiB+16字节** 两批，双库 **1.179s PASS**。它是仓储opaque数据/真实SQL限额测试，不是修改后密文可认证的声明。
- 本单元尾consumer与PG时钟差两项真实红绿：SQLite在DELETE+审计INSERT后真实逾期，原实现错误提交；PG真实server-side `clock_timestamp()+5 seconds`模拟远端时钟超前，原实现已提交删除却拒绝其签名凭证。原双项 **1.397s FAIL**；最小修复双项 **1.207s PASS**。
- 组织内坏首Run/好后Run，原调度双库 **0.757s FAIL**（后续Run无Job）；修复联同原fairness及disabled独立到期 **2.433s PASS**。其中disabled原本被通用队列取消，已采用严格绑定例外并补8类拒绝用例，不把组织停用当删除资格。
- summary未来捕获、Attempt范围/状态/receipt、key_version、payload_hash的6类SQL篡改，原实现双库 **3.718s FAIL**（仍返回retained=1）；批量元数据修复联同实际删除/独立期限/时钟差 **6.926s PASS**。
- 扩大单轮 **49.225s PASS**：全部cleanup及既有`TestJob*`、`TestQueueMigration*`、`TestPostgresClaimSkipsLockedJob`、`TestAudit*`双库；保留旧队列完整性和审计回归。
- 最终完整`TestResponseRetentionCleanup*`及纯边界**真实双库三轮143.240s PASS**。包含真实typed Bind→WithRecords(raw+unavailable_seal)→Finish→发布→策略0再30→真实Job，只删除raw且原display无密文S1逐字不变；summary rawDeleted1/displayDeleted0/retained0，正文读取仍为unavailable_seal而非伪造deleted。
- 原`TestEvidenceDisplayRead*`、`TestDisplayEvidence*`及保留政策/migration/锁兼容测试**真实双库39.987s PASS**；最终全部repository lint再次**0 issues**。
- 最后仓储全包编译 `-run '^$'` **0.089s PASS**；全repository lint **0 issues**。初次lint缺bundled Go PATH未运行，后修环境并实际执行；不是忽略失败。

最终cleanup扩大三轮及旧展示读取/保留政策/migration兼容回归已通过，生产实现冻结，DB测试时段已归还root。root已另报告真实应用双库流水线 **32.471s PASS**，本agent不以其代替仓储专项。没有Git提交/推送或正式审核声明。

## 与后续审计/样本清理的关联

本次只追加审计，不删除审计。`integrity_audit_segments`虽有表，现全链验证仍要求从sequence1连续事件；审计清理必须另实现密封段/永久锚点及独立维护权限。migration19披露回执不是删除回执，且其不可删除触发器与sample/attempt/result外键是未来180/365天父对象清理的真实依赖，不可直接级联删除绕过。
