# M5-08 / REP-007 CSV 前端与接口契约接线

日期：2026-09-09。状态：前端格式、受限下载和 OpenAPI/生成器契约已接线并完成本机单元、类型、lint、构建验证。完整 CSV 浏览器验收与后端双库验收不在本单元，不能据此标记 CSV、REP-007、报告生命周期或 M5 整体完成。

## 需求及修改范围

核对 PRD §9.8（REP-006/007/008）、§10.2–10.3、§11、§12.3、附录 A/B，以及 report README、CSV 内核说明、现有报告 API/下载/界面及测试。当前目标明确包含 P1 CSV，未以旧版范围说明将其移出任务；PDF 不随本次 CSV 自动开放。

本单元仅修改：

- `web/src/reports-api.ts` 及对应测试。
- `web/src/report-download.ts` 及对应测试。
- `web/src/components/results/ReportsPanel.tsx` 及对应测试。
- 后续浏览器发现的外围文案：`web/src/components/history/RunHistory.tsx`、`web/src/components/results/ResultsPage.tsx` 及对应测试。
- `scripts/read-contract-schemas.go`、`docs/api/openapi-v1.json`。
- 新增 `tests/contracts/report_csv_test.go` 和本文。

没有新增依赖，没有改动基础 API 客户端、报告存储/Worker/API 实现、CSV 内核、PG 文件、全局台账或 Git。ReportsPanel 原有动态正文保留状态面板及其权限边界保留。

## 行为和安全边界

格式闭集为 `json | html | csv`。CSV 与已有格式使用同一显式选择、S1 范围确认、三权限复验、CSRF 和幂等提交机制；不允许 PDF、大小写别名、任意格式或受限正文。创建结果未知时保留原 body/格式/幂等键，只能手动恢复同一次请求。

界面明确提示：生成 CSV 是独立新报告，旧 JSON/HTML 记录只下载各自原格式，不转换或覆盖。选择框用于将来的创建，不影响已有记录的下载按钮或具体下载 URL；没有添加格式转换 query。生成不触发模型调用或重新分析，也不伪造人工复核快照/校准或批准。

下载 MIME 使用完整 switch：

| 存储格式 | Accept | 响应 Content-Type / Blob type | 附件后缀 |
| --- | --- | --- | --- |
| json | `application/json` | `application/json; charset=utf-8` | `.json` |
| html | `text/html` | `text/html; charset=utf-8` | `.html` |
| csv | `text/csv` | `text/csv; charset=utf-8` | `.csv` |

未知格式明确失败，不默认为 JSON 或 HTML。CSV 沿用精确报告 ID/修订/格式和终态不可变元数据绑定；下载前重新读取当前权限和同一报告。保留 same-origin、禁止重定向、no-store、attachment 文件名、nosniff、限制性 CSP、UTF-8 检查、Content-Length、16 MiB 上限、实际 SHA-256 文件哈希、独立内容哈希头以及 60 秒总期限。

只有校验后的原始字节才进入 Blob；不解析/重排 CSV、不在 iframe 中打开文件、不将其单元格重新导出。CSV profile 为 `mii.report.csv.v1`，它不是 `Report.schema_version`：报告元数据及其中的文档版本仍严格为 `mii.report.v1`。客户端校验传输字节一致性，不独立证明报告结论、数据库来源或 CSV 内核的全内容语义。

原有组织/账号/Run/分析修订切换、用户取消、卸载、401/403 撤销和 Blob URL 回收逻辑未替换；不缓存到 localStorage/sessionStorage。下载完成提示仅说明已经请求浏览器保存，不宣称真实文件已经落盘。

## OpenAPI 与契约

ReportRequest 与 Report 的 format 枚举同步开放 CSV；请求仍只含原三个字段。下载响应新增 `text/csv`，标明精确 UTF-8 Content-Type、四列长表及 `x-csv-profile=mii.report.csv.v1`。JSON/HTML 内容契约、文档 schema 和权限/CSRF/组织 header 保持。

专用 Go 契约同时核对闭集格式、S1 输入、文档/profile 分离、文件上限、session/权限/必需 header、不可按需转换的下载参数、三个媒体类型和两种哈希。12 个负向变异覆盖遗漏 CSV、误开 PDF、版本混用、profile/MIME/charset 缺失、受限内容、组织/CSRF/权限遗漏、转换参数和文件哈希丢失。AST 检查真实生成器的格式赋值，防止后续重新生成规范时丢失 CSV。

## 实际验证

第一次尝试被既有工具链校验阻止：PATH Node 为 `v24.20.0`，不符合 `v24.19.0`，当时前端测试未开始。随后使用仓库既有 `.tools/node-v24.19.0-win-x64`，仅前置当前命令 PATH；实际版本核对通过，未改工具链策略或机器 PATH。pnpm 保持 `11.19.0`，Go 保持 `1.26.7`。

| 验证 | 实际结果 |
| --- | --- |
| 首轮三份相关前端测试（最终 UI/取消专项补充前） | 3 文件 / 75 tests PASS，24.56 秒；不是最终总数 |
| CSV 功能接线时全量 `pnpm --dir web test`（下述外围文案修正前） | 34 文件 / 930 tests PASS，37.46 秒 |
| `pnpm --dir web typecheck` | PASS |
| `pnpm --dir web lint` | PASS，保留 deny-warnings |
| `pnpm --dir web build` | PASS，Vite 构建 1.25 秒；主 JS 533.57 kB / gzip 157.77 kB，出现 500 kB chunk 提示，未调高阈值或加入代码分割变更 |
| `go test ./tests/contracts -run '^TestReportCSV' -count=3` | PASS，0.360 秒 |
| `go vet ./tests/contracts` / `golangci-lint run ./tests/contracts` | PASS / `0 issues.` |
| 实际 `go run ./scripts/read-contract-schemas.go` 后解析输出 | format 精确为 json/html/csv，Report schema 保持 mii.report.v1；不写生成文件 |
| 本单元源文件尾部空白检查 | PASS |

新增前端用例使用受控 fetch fixture 和真实本地 SHA-256/流/Blob 路径，覆盖 CSV 创建、原记录保留、选择 CSV 后仍按旧格式下载、未知创建的同键恢复、CSV 精确 MIME/附件/双哈希、等长篡改、取消及 401/403；原权限、组织切换、轮询 ID/修订、保留摘要、下载取消与 URL 撤销测试全部继续执行。

没有运行数据库测试、真实浏览器下载或 Excel/LibreOffice 导入，也没有调用上游模型。后端生产接线及双库/浏览器/全仓验收由 root 与对应开发单元负责；本记录不将受控前端单元测试当作完整端到端交付。

## 浏览器发现后的外围文案修正

root 随后报告其真实浏览器创建 CSV 报告 `1224812274393290950`，状态 ready，76,022 字节，客户端下载的内容/文件哈希头绑定及文件字节校验通过；同时发现历史结果页和结果总览底部仍只写 JSON/HTML。本单元未独立执行这次浏览器流程，该记录属于 root 的交接证据。

按该实际发现，仅将 RunHistory 和 ResultsPage 的两处静态说明补为 JSON/HTML/CSV，并明确 PDF 导出、报告内人工复核快照尚未实现。完整导出权限、正文不可混入报告、原文下载/请求复现尚未接入、正式审核未完成等边界继续保留；没有修改事件、权限判断、网络请求、ReportsPanel 功能或后台行为。

文案修正后：RunHistory、ResultsPage、ReportsPanel 三个相关测试文件共 47 项 PASS，4.01 秒；typecheck、lint、build 均 exit 0。新构建主 JS 为 533.72 kB / gzip 157.85 kB，Vite 报告 141 ms；500 kB 提示仍保留。新增四个源/测试文件尾部空白检查通过。

root 的上述浏览器流程基于外围修正前的 bundle；这次文案回归和重新构建不是修正后 bundle 的完整 E2E 重跑，也不能据此宣称 PDF、复核快照或其它未完成项已完成。当前本单元完整冻结范围为前述 14 个文件（10 个原 CSV 前端/契约文件，加 4 个外围组件/测试文件）。

## 最终文案版本全前端复跑

2026-09-09 16:52（Asia/Shanghai）再次核对固定工具链：Node `v24.19.0`、pnpm `11.19.0`。只前置当前命令 PATH，没有编辑冻结代码、使用数据库/浏览器或执行 Git 写操作。

| 终态命令 | 实际结果 | 命令墙钟耗时 |
| --- | --- | --- |
| `pnpm --dir web test` | **FAIL，exit 1**；34 文件中 33 PASS / 1 FAIL；930 项中 929 PASS / 1 FAIL；Vitest 65.64 秒 | 69.607 秒 |
| `pnpm --dir web typecheck` | PASS，exit 0 | 12.746 秒 |
| `pnpm --dir web lint` | PASS，exit 0 | 1.757 秒 |
| `pnpm --dir web build` | PASS，exit 0；Vite 1.16 秒；500 kB chunk 提示保留 | 7.829 秒 |

唯一失败为 `src/App.test.tsx` 的 `real API interaction boundary > recovers an existing session without submitting credentials and preserves safe navigation`。第 197 行仍匹配旧的 `JSON/HTML 报告。正式审核尚未完成` 连续文案，而实际 DOM 已显示 `JSON/HTML/CSV 报告。PDF 导出与报告内人工复核快照尚未实现。正式审核尚未完成`。失败点是外围文案变更后未同步的应用级文本断言；不能因此宣称全套前端测试通过。该文件不属于冻结的 14 文件，本次仅报告给 root，没有擅自修改或删除断言，需要修正该断言后真实复跑。

最终构建产物已可供 root 使用：`web/dist/assets/index-CLnmtlgz.js`（533,721 字节；Vite 显示 533.72 kB / gzip 157.85 kB）及 `web/dist/assets/index-DZRCxojm.css`（13.80 kB / gzip 3.81 kB）。`web/dist/index.html` 与 JS 的写入时刻为 2026-09-09 08:52:34 UTC。本次没有执行该 bundle 的浏览器验收；成功构建不替代失败的测试门禁，也不代表 V1.0 或未实现项目完成。

## 应用级文案断言修正后的最终终态

root 随后亲自修正 `web/src/App.test.tsx` 的旧文案断言：明确匹配 JSON/HTML/CSV，并独立保留 PDF/报告内人工复核快照未实现、正式审核未完成及报告不代表获批的提示断言。原有三次网络调用、GET 方法、组织 header 和安全导航覆盖仍保留；本单元只读确认，没有编辑该文件。

2026-09-09 16:59（Asia/Shanghai）使用再次实际核对的 Node `v24.19.0` / pnpm `11.19.0` 重跑：

| 终态命令 | 实际结果 | 命令墙钟耗时 |
| --- | --- | --- |
| `pnpm --dir web test` | **PASS，exit 0**；34 文件 / 930 项全部通过；Vitest 33.32 秒 | 34.152 秒 |
| `pnpm --dir web typecheck` | PASS，exit 0 | 9.885 秒 |
| `pnpm --dir web lint` | PASS，exit 0，保留 deny-warnings | 0.664 秒 |

先前的真实失败保留在上节作为回归与修复证据；本节才是修正后最终全前端测试终态。本次只改测试预期，没有改应用源码，故按 root 要求不重复构建，继续使用上节已经成功构建的最终 bundle。

root 同时交接其真实浏览器会话 `49571` 的终态：PASS，288.417 秒，覆盖新 CSV 修订 2、旧三种格式下载、原机器分数保持、退出会话及保留清理断言。本单元没有操作浏览器或数据库；该结果明确归属 root 的独立验收证据，不能外推为 Excel/LibreOffice 导入、PDF、人工复核快照、整个 M5 或 V1.0 完成。
