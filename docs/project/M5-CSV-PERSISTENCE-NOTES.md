# M5-08 / REP-007 CSV 仓储与私有存储检查点

## 范围

本单元完整复核 PRD §9.8、冻结 CSV 内核说明、报告仓储创建/读取/冻结/发布/
重试/权限/审计实现与回归、私有存储规范和平台测试，以及 migration14 的
SQLite/PostgreSQL 不可变约束。只修改/新增：

- `internal/integrity/repository/report_records.go`
- `internal/integrity/repository/report_csv_test.go`
- `internal/integrity/reportstorage/store.go`
- `internal/integrity/reportstorage/csv_test.go`
- 本文。

不改 Worker、API、前端、OpenAPI、冻结 CSV 内核、全局台账或 Git；不新增
migration22，不修改旧迁移。新增 CSV 制品的产品发布链仍需上述上层接入，
本单元不是端到端 CSV 功能交付或独立审核批准。

## 生产变化与不变项

仓储私有 `validReportFormat` 与存储私有 `validArtifactFormat` 分别统一各自
模块的闭集，仅精确接受 `json`、`html`、`csv`。未增加跨层依赖。

仓储的创建输入、读取记录验证及对象名生成均使用同一闭集；存储的 Put 与
Reference.Name 也共用一个闭集。CSV 格式的大写、空白、路径、NUL/CR/LF
变体及未实现的 PDF、ZIP 不被接受。

继续沿用既有“一个报告行对应一种文件格式”的模型：

- `format` 已是 TEXT，唯一键含组织、Run、分析修订、格式、报告修订，故不需
  数据库迁移。CSV 拥有新的报告/Job ID 和自己的格式修订序列。
- `schema_version` 仍是文档 `mii.report.v1`。`mii.report.csv.v1` 是 CSV 内容
  profile，不可写入该列。
- 请求幂等哈希包含格式；同 key/same request 复用原行，换格式产生冲突。
- 既有权限、组织隔离、创建者绑定、三项授权复验、冻结源、租约 generation、
  发布时间与审计事务未修改。文件存储本身不授予组织访问权。
- 旧 JSON/HTML ready 行、源、哈希、文件路径与文件字节不变；不会给历史行
  自动补写 CSV。ready 不可变、冻结源不可变的数据库触发器仍原样执行。
- 新 CSV 的 ReportID/GeneratedAt 与历史记录不同，因此不要求其内容哈希
  等于历史 JSON/HTML 行。仅同一 Snapshot 的不同导出具有同一内容哈希。

私有文件仍位于 `org-<id>-<sha256>.<format>`，复用有界写入、受限 staging、
原子无覆盖链接发布、实际句柄权限/链接数检查、完整长度与 SHA-256 校验。
保持真实 16 MiB 上限；损坏的同名对象不被重试偷偷覆盖，不返回部分文件。
原存储的崩溃 orphan、双链接恢复以及 Windows 目录 fsync 限制没有被消除；
本单元没有增加目录清扫、总磁盘配额或实例管理。

## 测试设计与证据

仓储新增四个顶层测试，其中三个使用既有 `eachDatabase` 执行真实 SQLite
与隔离 PostgreSQL schema：

1. 格式/对象名闭集及文档 schema 不与 CSV profile 混淆。
2. 已有 JSON/HTML 发布后创建独立 CSV；同 key 幂等、跨格式冲突，CSV/JSON
   各自递增到修订2；混合历史保持完整；旧行全部字段保持不变；尝试修改 ready
   format/hash 被真实触发器拒绝；创建审计仅一次。
3. 实际移除测试 audit signer 验证创建及发布回滚；冻结源不能替换；重试后旧
   lease 不能发布，当前 lease 复用冻结源；下载审计拒绝不匹配长度/哈希。
4. 分别撤销 `run.read`、`evidence.read`、`report.export`，读取、幂等重试、
   Worker 源及最终发布都拒绝；仅允许准确结算失败，不留可下载文件引用。

仓储用例的 S1 payload 与 publication 是明确标注的合成 opaque fixture，用于
测试真实事务，不冒充真实 CSV 渲染或真实文件生成。CSV 内容与 hash 重建由
冻结内核测试负责，实际 Worker/HTTP 文件全链由 root 的上层单元验证。

私有存储新增三个测试，使用真实临时目录/文件：

- CSV Put/Read/重试保持字节、文件身份、mtime；旧 JSON/HTML 字节、哈希、
  文件身份和 mtime 均未改变；组织对象名独立；成功后无 staging 残留。
- 实际硬链接拒绝、同长度字节篡改拒绝、重试不覆盖坏文件；非法名字与引用
  拒绝，失败后的 staging 清理仅作用于本次受控临时文件。
- 实际写入/读取恰好 16 MiB，超过一字节及空数据拒绝；取消读写不返回数据或
  产生新对象。该层不解释内容，因此边界用字节 fixture，不称其为完整 CSV。

Windows 原生执行结果：

- `go test ./internal/integrity/reportstorage -count=3 -cover`：PASS，0.693 秒，
  包级覆盖率 77.0%，包括原平台 ACL/junction/link 回归。原符号链接测试在主机
  缺少创建权限时仍可按原行为跳过，不把跳过记为该路径通过。
- root 授予 General DB 独占时段后，新 `^TestReportCSV` 单轮 PASS，4.605 秒；
  再 `-count=3 -v` PASS，13.755 秒，日志明确列出所有 SQLite/PostgreSQL 子例
  都通过，无 PostgreSQL skip。执行会话 77244 已终态0，随后立即交回 DB 时段。
- PostgreSQL 仅使用 root 提供的 General DSN；未输出 DSN，未启动/停止任何
  实例，未接触 Backup 测试实例。fixture 仅创建/清理其明确拥有的隔离 schema。
- 仓储/存储 Windows vet 已通过。静态检查发现一处测试读取变量路径，补充
  精确 G304 注释说明由当前测试 Put 铸造的受控路径及篡改验证目的，不豁免
  生产路径或任意输入检查；最终两包 golangci-lint 为 0 issues。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 的两包测试交叉编译、vet、
  golangci-lint 均通过（0 issues），仅编译/静态检查，没有执行 Linux 测试。

Linux 原生文件权限与 race 验证仍依赖既有 CI；本地交叉编译/静态检查不能
代替原生执行。本单元不声称真实浏览器下载、电子表格程序验证或生产验收。
