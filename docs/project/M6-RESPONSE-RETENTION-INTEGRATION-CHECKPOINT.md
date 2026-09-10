# 响应正文清理：实际应用集成 checkpoint

2026-09-08，进行中，未正式验收。依据 PRD11.2、TECH18、M6-07、ADR-0006。范围是当前 raw/display 响应副本的每日异步物理清理与可验证删除事实，不是摘要/结果/报告/审计全生命周期完成。

## 实际接线

- 新migration20与仓储每日持久调度由专有repository单元实现。32行/8MiB固定批次，真实Job、原consumer和CompleteWith fence；删除、S1-only凭证、审计与Job完成同事务。独立raw/display期限，组织停用不是提前删除资格，旧history不补造删除记录。
- `worker/response_retention.go` 提供固定handler，不接受HTTP/调用方选组织、时钟、限额或actor；nil/无fence事务不可删除。app真实注册JobRetentionDelete，原两秒维护期限内调用ScheduleResponseRetention，不开第二SQLite消费者。
- `run/response_retention.go` 输出精确12字段的 `mii.response-retention-summary.v1`，仅revision1，run ID保留十进制int64字符串；观测时间/政策/计数/最后删除时间显式返回，缺失时间为null。矛盾计数、超过实际Attempt数、未来删除时间失败关闭，不能把失败展示为0。
- `GET /api/v1/runs/{id}/response-retention?analysis_revision=1` 要求run.read+evidence.read，不扩展report.export/evidence.body。HTTP入口在setup/session查询前固定4准入槽，原上下文最长2s；拒绝HEAD/body/transfer encoding及重复、额外query。沿用标准request_id envelope、no-store等安全头，限额429、来源损坏503，范围内合法无数据200。
- 该动态S1观察不改报告文件/哈希/修订，也不证明保留中的副本已成功解密或可向调用者披露正文。新增正文deleted状态仅适用于仓储已验证删除凭证后；无凭证缺行仍错误。

## 已有局部证据

- app/run/API/worker完整编译通过（无测试运行），证明真实接口已接线而非pending草案。
- root新DTO闭集/整数ID/null及错误计数、HTTP严格输入/准入、handler取消/零事务纯测试三轮通过：run0.110s、API0.151s、worker0.120s；三包lint0。初轮只有测试误把12字段写成13的计数错误，改为精确字段清单长度一致断言，不改生产DTO。
- 前端独立34文件891项、typecheck/lint/build通过；原报告export权限不变，仅加手动动态状态面板。构建532.91kB提示仍保留；mock组件测试不是后端真实性证据。
- 仓储初轮双库3.709s、扩大故障26.736s，以及额外consumer/PG锁2.779s由专有agent执行。正在补末尾consumer复验的真实红绿、typed来源错误、最终扩大回归及完整证据说明，不混作root全产品通过。

## 实际应用验证与扩大回归

root已接 `internal/app/response_retention_pipeline_test.go` 到现有真实TLS 0/30天双库应用流程。清理前经真实HTTP读取状态与已发布分析、下载两格式报告，保存全部S1 payload/MAC身份；真实管理0→30使既往正文受单调cutoff排除，仅推进隔离测试组织的日调度状态以免等24小时，仍由实际app维护→Job→删除执行。随后必须观察raw/captured副本零行、已提交批次Job、deleted/null正文、精确S1/分析/报告字节与哈希不变、权限撤销403及完整审计通过。

初轮session24634失败30.161s；带闭集状态计数的单PG session48589失败7.302s，证明18次Attempt对应17份captured展示密文和1条unavailable_seal，summary retained17正确。原helper把BodyRecorded误作每次展示封装成功，现改为直接读取实际raw/captured对象数，独立保存无密文的不可用S1记录并要求清理后逐字不变；正向正文场景选真正captured的样本。未调整生产时钟/封装/限制，也不推断该次seal失败的唯一原因。

修正后root实际执行 `go test -tags webassets ./internal/app -run '^TestApplicationActualTLS' -count=1 -timeout=3m`，session81561终态PASS32.471s。实际0/30天、SQLite/PostgreSQL应用链路及上述删除/原始报告字节、S1身份、权限/审计断言全部通过；该正则不包含名称为TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization的独立多块测试，后者和全app三轮仍需扩大回归。清理仓储最终新增反例仍在进行，本结果不是完整M6-07或V1验收。

本轮root新增纯契约/DTO/API/handler三轮通过（0.215s/0.110s/0.099s/0.099s）；全前端已更新至34文件911测试PASS34.77s，typecheck/lint/build通过，JS533.23kB警告未抑制。这些均不是双库实际清理或浏览器端到端的替代证据。

日调度测试加速不等于经过真实24小时；浏览器真实页面仍需另验。完整请求复现、S2请求快照策略、摘要180天、聚合/报告365天和独立维护角色的审计密封分段清理仍在原范围内，未完成。不能删除旧审计日志或将新正文删除凭证等同于已有披露授权回执。

## 最终集成收口（覆盖上文当时待验证状态）

仓储专有最终实际双库清理三轮143.240s、清理与原Job/Queue/Audit单轮49.225s、旧展示/政策/迁移39.987s均PASS。末尾consumer复验、DB与审计同源时钟、失败首Run不饿死后续Run、disabled组织精确batch Job例外、summary损坏元数据及真实不可用S1记录保留均有专项反例，详见M6-RESPONSE-RETENTION-CLEANUP-NOTES.md。

root session83572串行扩大回归已终态exit0：`go test -tags webassets ./web ./internal/app -count=3 -timeout=5m` PASS（web0.396s、app150.603s），包含前述独立多块权限撤销测试；完整API SQLite50.177s、显式PostgreSQL91.782s均PASS；`go test ./internal/integrity/worker -count=1 -timeout=6m` 实际双库PASS145.402s。没有并行重启数据库套件，也没有修改超时或把观察超时当作测试失败。Windows辅助连接独立测试单元已提交c7e5ae3，未改生产或原期限；响应清理本次交付已完成上述本地验证，远程新CI和浏览器验收仍待完成。
