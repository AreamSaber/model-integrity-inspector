# M5-08 CSV product integration checkpoint

日期：2026-09-09。CSV 生成、持久化、真实 Worker、HTTP、前端与应用清理回归
已接通；不是 PDF、完整报告生命周期、M5 完成或正式审核批准。
原 REP-007 的 PDF/CSV 全部范围仍包含在 Goal 中，需求矩阵仅改为进行中。

## 产品接线与不变项

- 创建格式精确限定 json/html/csv。CSV 直接读取已冻结的同一报告来源，调用
  GenerateCSV，再经受控文件存储、文件 hash 复验、Job 租约/fencing 和审计事务发布。
  不把未知格式降级为 JSON，不按下载参数转换旧文件，不修改原报告或机器分析。
- 报告文档保持 mii.report.v1；CSV full-node profile 为 mii.report.csv.v1。
  内容 hash 与实际文件 hash 独立，保持 16 MiB、S1、权限复验、CSRF、撤权、
  并发槽位、取消、no-store/nosniff、附件与 sandbox CSP 边界。
- 固定 CSV MIME 为 text/csv; charset=utf-8，旧 JSON/HTML MIME/扩展名不变。
  前端按报告实际格式下载，而非使用当前创建选项。先验证精确响应头、长度和
  SHA-256 才请求浏览器保存，Blob URL 生命周期不变。
- 无新依赖或迁移；Schema/OpenAPI 生成器与客户端同步，PDF 未被顺带开放。
- 应用测试默认必须存在且仅存在三个 ready 格式。只有显式 browser hold 才允许
  更多独立报告；全部额外行也逐项捕获并在清理后校验，不过滤掉浏览器创建的行。
  缺格式、重复 ID、未知格式、非 ready、外部 Run、CSV profile 冒充文档 schema
  都有反例。真实 CSV 的 header、全节点、样本数量/索引、来源身份、免责声明、
  开发/复核状态有额外独立应用断言。

## 本轮失败与修正

1. 首次真实浏览器创建 CSV 后，旧应用夹具仍要求报告恰好两条，完整测试
   306.782s FAIL。没有将页面成功当作整个测试通过。现改为默认精确三格式，
   browser hold 可有额外报告但必须全部保存并比较，原清理/结果/审计断言保留。
2. 应用新格式 if/else 触发 QF1003；改显式 switch 并拒绝未知格式，静态检查通过。
3. 最终文案首次全前端 929/930 通过，唯一 App.test.tsx:197 还匹配旧 JSON/HTML
   文案。真实 DOM 已显示三格式与未实现限制。同步这一断言，并增加 PDF、复核
   快照未完成及正式审核未完成断言；会话/导航/三次网络/GET/组织断言均保留。
   随后完整 930 项通过，不删用例、不放宽安全或版本检查。

## 真实浏览器与完整应用终态

root 使用最新最终 bundle index-CLnmtlgz.js，对实际 Go app + 临时 SQLite +
受控 TLS 上游的 127.0.0.1:49571 执行浏览器流程。没有用 mock 替代产品后端。

- Run 2362014713556967824，固定分析修订 1：18 样本，风险 21、置信度 27、C。
- 原 JSON 2203151465123956394、HTML 1421780081549347044、CSV
  440650769055093572 均为报告修订 1。
- 显式选择 CSV/确认 S1 后，新建 7555960204004944292，报告修订 2，实际经过
  queued 到 ready。文件 76,013 字节；内容 hash
  sha256:c7a8100249c2edb7321731db0c2af1208768aa102115f6550257874034796861；
  文件 hash sha256:b401941061b43611ff50e0f2a12ebce563cf4c582c21bd87c6680663980d9fef。
- 下载新 CSV 与原 HTML/JSON/CSV，客户端长度/hash 验证成功；原三者分别
  64,410 / 26,986 / 76,012 字节，身份与修订不变。没有核验浏览器落盘文件，
  不声称 Excel/LibreOffice 导入或实体文件已保存。
- 回到结果总览仍为风险 21 / 置信度 27 / C；新外围文案可见；浏览器
  error/warn 日志为空；退出后显示登录页及“已退出当前会话”。
- root 在五分钟 hold 到期前写入该测试返回的精确 browser.stop 标记，同一
  测试继续所有权限、真实日清理 Job、逐报告文件、S1、结果及整链审计校验，
  最终 PASS 288.417s（含人工驱动浏览器时间）。不是跳过后半段或重启测试。

## 最终验证

命令均为实际终态。固定 Go 1.26.7 / Node v24.19.0 / pnpm 11.19.0。
数据库 DSN 仅从受忽略文件放入命令环境，不在文档记录凭证。

| 验证 | 结果 |
|---|---|
| root go test -tags webassets ./internal/app -run '^(TestApplicationActualTLS\|TestPipelineReportInventory)' -count=3 -v -timeout=5m | PASS 111.340s；30日与0日完整链各三轮，SQLite/PG 均实际执行 |
| root browser hold：TestApplicationActualTLSFromInitializationThroughPublishedEvidence/sqlite | PASS 288.417s，包含新 CSV 和其后完整清理断言 |
| root report / reportstorage 全包三轮 | PASS 4.276s / 1.056s |
| root 完整 contracts 三轮（最终需求矩阵后） | PASS 0.851s |
| 仓储 CSV 三轮、实际 SQLite/PG | PASS 13.755s，详见 persistence notes |
| Worker 全部 TestReport 三轮、双库 | PASS 60.205s，详见 delivery notes |
| HTTP 全部 TestReport 三轮 | SQLite 23.092s / PG 51.294s PASS |
| 最终全前端 | 34 文件 / 930 tests PASS，Vitest 33.32s |
| 前端 typecheck / lint | PASS；最后仅测试断言变更，复用最终已构建 bundle |
| root go vet ./...、全仓 golangci-lint（switch 修正后） | PASS / 0 issues |
| root 所有 CSV 相关 Go 包再次 lint | 0 issues |

Worker/API/存储新旧格式、安全、撤权、失败原子性与重试详细证据见
M5-CSV-DELIVERY-NOTES.md、M5-CSV-PERSISTENCE-NOTES.md；前端失败/修正/完整复测见
M5-CSV-WEB-NOTES.md；内核独立重建、转义、边界见 M5-CSV-REPORT-NOTES.md。

已提交基线 9ad2e68 的 CI34329687200 已全部 20 jobs success，含真正 Linux
pg-backup-native、双库 race、Windows/Linux package、image、quality 和 required。
这证明此前 PG 单元，不用于追认本次尚需提交并独立运行 CI 的 CSV 上层修改。

仍缺 PDF、报告人工复核快照、完整差异/重分析、报告配额/生命周期，以及其他
M5/M6/M7/M8 和 SEC/ALG/OPS 原计划。没有正式签字、生产发布或付费调用。
