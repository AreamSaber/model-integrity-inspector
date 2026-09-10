# 真实大正文分块授权回归 checkpoint

日期：2026-09-08。状态：独立实际app测试已通过SQLite/PostgreSQL单轮真实回归13.924s，编译及lint通过；本有界测试单元已冻结供root最终集成复核，不代替里程碑审核。

## 范围与原规格

仅新增`internal/app/evidence_stream_pipeline_test.go`与本文。入口为`TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization`，分别使用现有隔离SQLite及PostgreSQL fixture。没有修改app/Worker/Repository/secret/原pipeline或任何资源上限，也不需要共享hook。

依据PRD §10.3/§11.1–11.2、TECH §13.4–13.6/§18及`M5-DISPLAY-READ-IMPLEMENTATION-NOTES.md` §3–5/§8：正文仍为S2、先授权审计commit后输出、每块fresh权限/身份/政策检查、自然时间不能被冻结、不能追回已发bytes或声称数据库与socket同事务。

## 真实链路与有界输入

复用`pipelineDatabase`、`testConfig`、`pipelineHTTP`和保留配置helper；本文件建立独立真实app、实际HTTP初始化/登录/Target/Precheck、quick estimate+confirm及发布结果，不重复与本任务无关的报告/基线流程。

受控TLS上游使用既有`mockupstream.Config.Responder`。precheck成功之后arm一次，只有首个实际Run响应返回16KiB的`<`字符与固定末尾标记；其它响应保持原默认合成生成规则。该字符串经真实JSON转义约为96KiB，导致真实Worker展示载荷和最终服务编码超过64KiB；响应本身仍远低于1MiB，展示低于4MiB，输出低于8MiB，quick计划与预算不变。没有更改捕获时钟、lease、AEAD或从手填cipher/fake opener产生数据。

从实际发布Run查询其真实final Attempt且display `state=captured`、`plaintext_bytes>64KiB`。原HTTP cookie经真实Principal→固定audit actor→BindControlAuthority；真实主密钥文件派生窄DisplayOpener，调用生产EvidenceService。原会话ID/expiry由实际cookie哈希经GetSession确定，不取任意最新会话。

## 实际通过断言

正例要求真实writer至少两次调用、每块最多64KiB；总字节数与已提交receipt一致，完整SHA256与审计回执output_hash一致。独立SQL连接在首次writer内确认receipt及精确`ID:receipt_hash`审计已提交。解码后原始content必须逐字等于实际TLS大字符串；规范JSON再次编码不得漂移，内层payload SHA256须匹配PayloadHash，Run/Attempt/final语义必须准确。这不是仅凭buffer长度推断“多块成功”。

同一个真实已捕获对象的反例：

- 首块交给writer之后分别撤销run.read/evidence.read/evidence.body；测试隔离schema中精确保存/恢复原role/member权限行，不宣称走过管理HTTP撤权。
- 分别取消原Prepare ctx及独立Write ctx，二者仍绑定同一原会话。
- 首块之后等待原生产permit两秒上限自然经过；不注入时钟或延长期限。
- 将原真实会话expiry暂设1.5秒后的真实时间，在该expiry尚未到达时确认首块已发，再等自然跨期；只恢复精确原session ID的原expiry，不伪造封装expiry。
- 最后通过真实组织管理HTTP PATCH、读取真实CAS version，将响应保留设置为0；不通过直接改display行制造政策状态。

每个反例都要求writer恰好一次、返回已发送字节恰好64KiB、实际部分输出等于正例前缀、只有一条原grant、没有补写错误JSON、不可重放，审计链仍完整。授权回执描述已授权而不是已全部送达。

## 实际验证与保留边界

`go test ./internal/app -run '^$'`编译通过0.098s；最终app lint `0 issues`。独立fixture已接root冻结的`prepareWithNetworkAndLogger`和`pipelineDiagnosticBuffer`：prepare/serve共用同一可信结构化logger，只有失败时在shutdown/close清理后打印最多32KiB，不再将真实CI诊断丢到io.Discard。

root明确授权独占数据库时段后，首轮带`webassets`真实双库执行6.780s失败：正例多块成功，但测试错误地用随机receipt ID的DESC顺序当时间先后，后续断言会选到旧的最大ID。已只修测试，改用同组织审计`sequence`的真实顺序，并以receipt ID和canonical hash做精确JOIN；`repository.NewID`由OS CSPRNG生成，不能假设单调。此失败不作为生产授权漏洞证据，预算/超时/时钟均未放宽。

修复后实际执行：`go test -tags webassets ./internal/app -run '^TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization$' -count=1`，SQLite/PostgreSQL及全部正反例PASS，13.924s（session2965，exit0）。该终态包含原permit自然跨期、原会话自然跨期及实际管理PATCH0，不是仅编译或事先已过期的替代测试。专有diff检查无错误。

root报告之前17场景的较小正文服务helper实际双库首轮30.875s通过；它不构成本文件的多块证明，亦未混用为新测试终态。

本单元覆盖明确完成于首块回调内的变化与后续块之间的检查，不保证最后检查与内核socket写之间的硬实时撤销，不能追回第一块。它未新增HTTP分块传输协议、浏览器回压或网络送达回执，也未等待真实30天sealed expiry；自然过期验证对象明确为permit及原会话，不能将其描述为已完成历史正文物理清理。

未执行Git。专项测试已结束并已向root明确归还数据库时段；无本agent在途测试。两个专有文件冻结供主任务最终集成复核，后续root三轮与本次单轮证据分别记录。
