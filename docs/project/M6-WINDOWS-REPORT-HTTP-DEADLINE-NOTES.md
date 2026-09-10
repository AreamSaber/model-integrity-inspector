# M6 Windows 报告状态 HTTP deadline 诊断

2026-09-10。本单元只改真实应用 pipeline 的测试观测与其纯回归；没有改变生产 HTTP、数据库池、Worker、授权、报告事务、5 秒 Client.Timeout 或业务期限。**当前尚未复现远端等待层，不宣称根因已修复。**

## 本次 CI 的独立证据

[CI 34430463313](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34430463313)，提交 `57c5571c3d2947686c8fe7717a2743cafac31d7d`，20 job 终态为18 success、Windows 与 required 两项 failure。quality 成功，不是旧的一轮全仓/setup/import-cycle 失败。

- Windows `package-windows-2025` job `102724716259`，step 6 `Build versioned package`。
- 首轮 `go test -p 1 -count=1 ./...` 已全部通过：app 56.258s、repository 442.281s、worker 137.781s；前端930测试通过。
- 失败在 `scripts/package.ps1:56` 第二轮 `go test -count=1 -tags webassets ./web ./internal/app`，其 web 包0.088s成功，app 包42.020s失败。
- `TestApplicationActualTLSFromInitializationThroughPublishedEvidence/sqlite` 测试总时长15.74s，在当时 `artifacts_pipeline_test.go:52` 轮询 `GET /api/v1/reports/{id}` 的 Client.Do 失败：`class=deadline_exceeded, request_context=none`。测试总时长不是单个请求时长；该客户端实际期限仍是5秒。
- 应用 bounded diagnostics 明确 `truncated=false`，只有 `control listener started`。没有 worker claim、database_unavailable、worker_exit 或 shutdown 失败记录。现有日志不能确定报告格式、请求是否已获得连接/到达handler，以及是否在等待SQL池、驱动或响应。
- package 在03:03:54Z以 `Embedded frontend integration tests failed`/exit1结束；不是25分钟 job timeout。required job `102728902716` 的7个其他 needs 均 success，仅 PACKAGE=failure，因此是派生门禁失败。

不把本次现象自动归到旧的 SQL claim 错误，也不把 CI 耗时、Windows 或“可能并发”当作已证明原因。

## 已核对真实路径

`api.getReport → authorizeOrganization → Identity.Principal / Store.BindControlAuthority → ReportService.Get → Tenant.GetReport → resultReadTransaction / reportPermissions / reportRow`。

GET 不执行 ReportService.Create 的 readiness 检查，不生成报告，不读取报告文件，也不进入下载并发门。它会多次确认真实 session、user、RBAC，并在一致读事务中读取报告元数据。

SQLite 实际 app Store 只有一个连接；`resultReadTransaction` 在此连接上显式 BEGIN DEFERRED，而 Worker 的 LoadReportSource、FreezeReportSource、最终 PublishReport/Job/audit 使用同一个 Store。数据库连接竞争是需要观测的候选，但仅凭这条调用链不能认定本次 CI 正在等它。没有发现本次 artifacts 轮询之前遗留未关闭辅助事务的证据。

## 新增测试专用观测

1. 为单个真实 HTTP 请求附加标准 ClientTrace。只保存 get/got connection、reused、connect完成/失败、request写入/失败、first response byte、DNS/TLS 开始/结束布尔值及耗时。所有地址、URL、headers、TLS server name、错误正文均丢弃；阶段输出是闭集。
2. 每个请求仅在仍未完成的第4秒采样一次 runtime.GoroutineProfile，先于5秒超时取消可能使handler退栈。固定512个 StackRecord，拒绝按运行时请求数重新扩大分配；每条解析最多128个含内联 frame。只将实际 getReport、database/sql 池获取、SQLite driver、Worker 调用身份转为计数，不输出原函数名、堆栈文字、PC或局部变量。
3. 正常完成/早退都 stop-and-join 定时回调；callback 不等待主调用持有的锁，stop不持锁等待。已启动采样必须完成才能结束该请求辅助观测；不会留下读已清理fixture的后台任务。正常请求第4秒前完成不会采样。
4. 失败时同时输出取消前一次观测与失败当下观测。`profile_complete` 只表示runtime的整个 goroutine集合装入固定容量，**不证明每个调用栈完整**。不同GoOS、编译内联、StackRecord深度或handler及时退出会造成缺失；0计数一直是 unknown，不能证明不存在锁或池等待。SQLite driver计数也只是调用层观测，不等同实际锁等待。
5. 记录单次采样开销 `observation_ms`，不把这些测试观测开销作为业务性能验收。格式循环只额外记录固定 json/html/csv 标签，不记录report/Run/org ID、hash或路径。

没有在请求失败后重试，没有跳过用例，没有降低断言或放宽5秒与原40秒收敛期限；默认生产logger/ORM保持原有安全边界。

## 已有本地实测

- 诊断纯层：真实 loopback HTTP handler barrier 区分等待响应头与等待响应体，显式取消后Client加入结束；地址/错误/证书canary不进入闭集摘要。固定4秒定时器的快完成不采样、已开始callback的cleanup必须等待、重复stop/结果已结束均覆盖。审阅后将cleanup即时非阻塞观察改为保持真实sampler barrier的25ms观察窗口，避免cleanup尚未执行导致假通过；这不是业务超时调整。加强后完整纯专项三轮 **0.204s PASS**。
- 与Windows job一致显式不设置PG DSN的原第二轮命令：session29663 exit0，web **0.392s PASS**、完整webassets app **26.815s PASS**。这不是双库回归，也不是历史失败红绿。
- 原失败用例保持5秒，webassets连续5轮：session85791 exit0，**53.367s PASS**。这组自然运行没有复现远端deadline，不能当作修复证明；当时已经有错误时的trace/profile，4秒预取消采样在随后完成。
- 新观测版 `-tags webassets` 双库真实30天/0天两条pipeline三轮，12个完整fixture：session54465 exit0，**115.035s PASS**；General DSN已配置，两个数据库均真实运行。General DB已明确释放，无运行中数据库测试。最新 app lint **0 issues**，vet **exit0**。

下一步必须依据真实失败时的阶段/取消前采样确定等待层，再用可控同机制反例先红后绿地验证最小修复；若命中生产授权/SQL/Worker实现，需要独立明确修改范围。仅合并这些诊断不能关闭本次CI问题，也不能宣称全部Windows稳定性已修复。

root 收口：全文复核两个新测试文件及两个既有测试文件 diff，要求加强上述等待
阶段证明后，重新运行全部诊断纯测试 **20轮0.687s PASS**；app vet/lint退出0、
0 issues。原5秒客户端、40秒收敛、生产路径均不变。该单元是安全观测交付，不是
远端超时根因修复；提交后新CI的结果必须按实际新提交身份单独记录。
