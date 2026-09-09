# M5-08 / REP-007 CSV Worker 与 HTTP 交付检查点

## 范围

本单元完整核对 PRD §9.8、S1/S2/S3 隐私要求、报告冻结与失败不得损坏检测
结果的约束，以及现有报告内核、持久化来源、真实 Worker 和 HTTP 下载链。
只修改 `worker/report_generate.go`、`api/reports.go`，新增各自 CSV 回归与本文。
仓储/存储 CSV 格式闭集由另一单元接入；没有修改 CSV 内核、UI、契约或台账。

这是 CSV 产品链中的后台生成和下载接入，不代表 PDF、UI、完整 M5 或最终
审核已完成。CSV profile 细节、独立 JSON 树重建和单元格防御证据见
[CSV 内核检查点](M5-CSV-REPORT-NOTES.md)。没有 Excel/LibreOffice 实测承诺。

## 生成与冻结

- `generateReportArtifact` 显式区分 `json`、`html`、`csv`。JSON/HTML 仍使用
  原 `report.Generate`；CSV 只调用 `report.GenerateCSV`，不为 CSV 生成 HTML。
  未知、大小写变体、MIME 字符串和路径式格式均闭合为 `ErrReportInvalid`，
  不再有默认 JSON 回退。生成失败不返回部分字节或发布能力。
- 保留真实报告任务租约、受权来源加载、S1 快照构建、冻结、文件落盘、实际
  文件 SHA-256 对照以及 fenced completion 内原子发布顺序。仍由报告来源
  和最终发布分别检查持久化创建者的当前权限；登出不会冒充持久化撤权。
- 每个 CSV 请求创建独立报告行，保留其自己的 ReportID、CreatedAt 和已冻结
  来源。既有 JSON/HTML 报告不转换、不覆盖。重试复用同一 CSV 快照并拒绝旧
  租约发布；只有同一 Snapshot 的 JSON/HTML/CSV 才共享内容哈希。不同报告行
  不因基于同一 Run 就具有相同内容哈希。
- 数据库存储及 API DTO 的 `schema_version` 仍为文档 `mii.report.v1`。
  `mii.report.csv.v1` 是 CSV 四列长表中的编码 profile，不替换报告 schema，
  不增设 `csv_schema` 请求参数或 DTO 字段。
- CSV 文件哈希使用实际 CSV 字节，不复用 JSON 文件哈希；最终发布沿用
  `ReportPublication`，失败保持机器结果不变。文件已落盘但发布被撤权或审计
  插入回滚时，未发布孤立文件不可通过下载服务访问。

## 下载边界

下载成功精确返回 `text/csv; charset=utf-8` 和
`attachment; filename="report-<id>-r<revision>.csv"`。MIME 与扩展名均由固定
三格式 switch 选择，未知已存格式不能回退为 JSON 或进入附件响应。

保留原 `report.export` 与租户权限、ready 状态、存储文件哈希/长度校验、下载
审计、最多四个并发下载的服务预算，以及以下既有响应头：

- `X-Content-Type-Options: nosniff`
- `Cache-Control: no-store`
- `Content-Security-Policy: sandbox; default-src 'none'; base-uri 'none'; form-action 'none'`
- `Referrer-Policy: no-referrer`
- 实际 `Content-Length`、`X-Report-Content-Hash`、`X-Report-File-Hash`

没有增加可覆盖格式、路径或敏感内容的 query 参数。未知请求字段、重复字段、
`include_restricted_content=true` 继续被拒绝。每块最多 64 KiB、每次写入
2 秒 deadline、总传输 1 分钟、每秒重新检查权限和 session 的原边界不变；
本单元没有把现有的定期撤权检查夸称为每字节即时撤权。终止和异常路径仍由
`defer download.Close()` 释放下载预算。

## 实际回归

所有运行使用仓库固定 Go 1.26.7。只在主线移交的 General PostgreSQL 测试实例
独占时段执行数据库测试；不启动/重启数据库、不访问 Backup 实例、不回显
DSN 或凭据。测试复用真实 SQLite/PostgreSQL、租约队列、适配器序列化、加密
证据、分析发布、受权快照、文件存储和 HTTP 路径；合成上游响应不访问付费或
公共模型接口，没有用 mock 替换产品仓储、生成器或下载服务。

新增 Worker tests：

- 同一 CSV 已冻结快照的 JSON 对照内容哈希、CSV 独立文件哈希/全部字节、
  新租约重试、旧租约拒绝、FrozenAt/SourceHash 不变、恰好三个独立文件。
- JSON/HTML 老行和文件逐字节不变，报告生成不改变已发布机器分析。
- 真实存储关闭、预取消、来源加载前撤权、文件写后最终发布撤权、SQLite/
  PostgreSQL 真实审计 INSERT trigger 故障。各失败无 ready/部分发布元数据，
  有权限的独立读者也不能下载孤立文件；撤权按真实 runner 处置完成报告失败，
  审计链保持有效。
- 预取消在现有仓储来源边界映射为 `ErrUnavailable`，未另改旧错误策略。
  来源撤权是 Job Fail + Reconcile；最终发布撤权才调用专用
  `FailReportGeneration`。测试不把两种能力混为一谈。

新增 HTTP tests：

- 实际 HTTP server/client 完整验证 JSON/HTML/CSV 附件、精确 MIME/文件名、
  双哈希、线上 Content-Length 和全部安全头。CSV 标准 reader 回读，确认
  文档 schema、ID、免责声明、开发/未校准标记、审查省略、各报告内容节存在。
- CSV 排队不可下载、幂等回放、独立列表行和旧报告不变。篡改实际 CSV 文件后
  返回 503、不发附件或哈希头、不泄露损坏内容，既有 JSON 仍可正常下载。
- 严格输入、CSRF、无 session、无导出权限、跨租户隔离与权限授予/撤销。
- 四个真实下载占满预算时 HTTP 429；关闭可恢复。受控慢 ResponseWriter
  只推进一个字节后，通过真实管理 API 撤销权限，后续不再写出；再次取得
  全部四个服务下载名额证明中止路径释放资源。控制 writer 只用于确定时序，
  没有替换认证、报告服务或文件读取产品路径。

已执行证据：

- Worker 新增 CSV + 格式闭集 tests：SQLite/PostgreSQL 各三轮，PASS，27.391 秒。
- HTTP 新增 CSV + 格式闭集 tests：显式 SQLite 三轮 PASS，12.171 秒；
  显式 `MII_IDENTITY_TEST_DRIVER=postgres` 三轮 PASS，18.049 秒。
- Worker 全部 `^TestReport`（既有 JSON/HTML + 新增 CSV）SQLite/PostgreSQL
  各三轮 PASS，60.205 秒，包含原消费者撤权后继续及实际基础设施故障回归。
- HTTP 全部 `^TestReport` 显式 SQLite 三轮 PASS，23.092 秒；显式 PostgreSQL
  三轮 PASS，51.294 秒，均包含旧 JSON/HTML 下载和权限/完整性回归。
- Windows 两包 `go vet` 和 golangci-lint 通过，0 issues；
  `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 两包 build、vet、lint 通过，0 issues。
  Linux 结果仅为交叉构建/静态检查，不是 Linux 原生测试或 race detector。
- 第一次新增测试运行曾因上述旧错误映射/两类失败 API 区别，以及版本节点
  应为 `/result/versions` 的测试假设失败；核对真实实现后修正测试，未修改
  旧产品行为来制造通过。其后完整三轮结果如上。

以上测试及静态命令全部已终态，数据库独占时段已交回主线。没有将旧 CI 成功
或未经执行的平台作为本批新增改动的验证；不在本单元做 Git 写操作或审核批准。
