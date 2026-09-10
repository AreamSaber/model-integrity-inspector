# 授权正文读取：服务、HTTP、前端集成 checkpoint

2026-09-08。M5-04/REP-003 与 M6-07 的响应正文单元；不代表请求复现、清理、全产品或正式审核完成。仓储及 migration19 已提交 `22c9046`，本单元使用其真实接口。

## 实际交付与边界

- 生产 app 派生用途隔离的 DisplayOpener，run.EvidenceService 不持原始响应解密能力、凭证服务或网络客户端。
- 精确历史 Run/Sample/Attempt/revision1 的 GET，必须同时有 run.read/evidence.read/evidence.body。明确拒绝 HEAD、Range、条件请求、请求 body、重复及额外 query，不提供 raw fallback。
- 4 个准入槽在身份/设置昂贵查询前限制 HTTP，同时服务独立限制 4 个准备缓冲；原请求最长 10s、准备开箱 2s、每次网络写入最多 2s；服务总输出 8MiB，64KiB 分块。槽满固定 429，不无限排队。
- 敏感 DTO 仅在私有编码器存在，标准 request_id 计入输出 hash/size。审计及 S1-only 授权回执必须实际 COMMIT 成功后才允许首次 Write；各块复验原会话/权限/保留策略。不能将数据库提交与 socket 写原子耦合，也不声称回执证明浏览器已接收。
- no-store/nosniff/no-referrer，无 ETag/Content-Length。审计失败输出固定错误，无正文；部分正文 Write 尝试后不得追加错误 JSON。
- Source 与 Disclosure 都采用共享私有状态，按值复制不能泄露格式化/JSON/日志内容、重复释放槽或重放。重复 Write 不取消已在途原 writer；Close 取消但 writer 返回前不提前放槽。所有终态清除拥有的编码缓冲，consumer error/panic 不向外传原始错误。
- 前端只有显式点击且刷新三项权限后读取；切组织/用户/Run/样本/Attempt、关闭、卸载、401/403 或迟到响应都清除 DOM/引用并取消。纯文本 React 展示，不解释 HTML/Markdown；不宣称 JS 字符串物理擦除或追回用户另存的字节。

## 已取得证据

- Root 发现值复制保护/双释放和重复 Write 取消原 writer 的真实红测后修复，服务生命周期三轮通过；nil/零值、16 个并发 Close、取消传播均补回归。
- 仓储实际双库 `^(TestEvidenceDisplayRead|TestExecutionLease)` 三轮 73.345s：涵盖撤权、真正 COMMIT 失败、自然期限、PG 锁等待、迁移回滚及共享 Source 修复。仓储测试不代替 AEAD 证明。
- 实际 app TLS→真实捕获/AEAD→分析发布→正文 HTTP，0/30 天 SQLite/PG 三轮 75.585s。新增 17 项服务 writer/准入/原会话/首次写出前提交可见性场景，随后独立实际 app 单轮 30.875s。正常 S1 HTTP 仍拒绝敏感内容。
- 完整 Worker 双库修复后回归 183.003s PASS。服务/API 纯测试三轮 0.117s/0.107s PASS；contracts 全包三轮 0.468s PASS；相关 lint 0 issues。
- 前端最终 32 文件 816/816、typecheck/lint/build 通过；root 三文件专项 87/87 通过。Vite 527.01kB 单包的 >500kB 警告仍保留，不提高阈值。
- 本轮完整控制面 API 在独占数据库时段按 SQLite 后 PostgreSQL 串行通过：50.232s / 83.307s（session72767）；服务/API 专项再三轮0.110s/0.098s，contracts全包三轮0.441s、相关lint0。没有把仅SQLite的默认身份后端测试当双库结果。

## 实际应用安全诊断

追加 `prepareWithNetworkAndLogger` 将可信启动 logger 接给现有 Worker；真实应用 fixture 使用相同 logger。`serve` 原有失败返回/停止顺序/期限不变，仅输出固定 phase、class、caller_done；客户端测试错误仅输出固定分类，URL/DSN/SQL/body/原始错误不可进入日志。失败后最多输出32KiB线程安全诊断快照。

独立6项纯测试同时包含恶意 Error() 格式化即panic的wrapper、封闭字段/canary、深包装timeout、并发缓冲限额和实际serve状态机无DB合成listener。普通及webassets三轮0.119s/0.114s、lint0，详见 `M5-APP-CI-DIAGNOSTICS-NOTES.md`。此为诊断能力，不是原Windows故障根因或修复证明；86.815s全app编译于诊断前，诊断后的真实应用验证须另记。

## 当前缺口与失败证据

- 新正文页面未取得真实浏览器验收。工具拒绝本机新测试 URL (`ERR_BLOCKED_BY_CLIENT`)，没有访问页面或绕过。该次 hold 后端测试还未带 webassets tag，其 45.688s（含等待）只证明后端测试成功，不是前端/性能证据。
- 本轮追加 `go test -tags webassets ./web ./internal/app -count=3 -timeout=8m` 独占双库回归已终态成功（session65776）：web 0.499s、app 86.815s，实际包含内嵌前端与新增17项服务 helper。这是本机快照证据，不能反推远端 Windows 失败已修复，亦不替代浏览器操作。
- 新真实大响应 TLS 专项已实际通过：`TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization` 双库单轮13.924s、lint0；完整多块输出与原受控响应及canonical/output/payload hash一致；首64KiB后撤三权限、取消、permit/原会话自然跨期及真实管理PATCH0均不再发下一块。首轮6.780s失败是新测试错误地以随机ID排序回执，改用真实audit sequence并精确绑定ID:hash后通过，没有改生产限制。详见 `M5-DISPLAY-STREAM-PIPELINE-CHECKPOINT.md`。root最终 `go test -tags webassets ./web ./internal/app -count=3 -timeout=8m` 已终态PASS：web0.500s、app138.674s（session26993），实际双库完整应用包含新诊断、17项服务helper和大响应全部场景；该快照不含后续清理migration20或正则优化。root诊断纯测试三轮0.114s与app/run/API/contracts组合lint0亦通过。
- 远端 `01165e1` CI34185808446 已终态failure。Windows 第二轮 webassets 实际 app 的0天SQLite在第二个Run状态轮询失败，13.46s子测试尚未达到默认15s周期续租，不能归为旧renew故障。quality 在非repository/非Worker前置race组的 `TestRequestReproductionLargeBoundedRequestAndExpansion` 返回 `MI_DISPLAY_CANCELLED`，2.73s，尚未开始实际Worker六分组；不是旧600s超时或某Worker分组失败。两项分别调查，不放宽期限/减少用例。Linux打包/镜像/六组repository race/依赖扫描成功，不代表全绿，该远端也不包含本单元。
- 独立 request-only 组件已有 `6031891`，尚无独立策略/存储/Worker/HTTP/UI；完整 REP-005 不关闭。正文物理到期删除、删除凭证、报告/摘要生命周期均未由本单元完成。
