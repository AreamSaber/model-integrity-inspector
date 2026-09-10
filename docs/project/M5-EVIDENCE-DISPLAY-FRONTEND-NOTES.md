# REP-003 授权响应正文前端 checkpoint

2026-09-08。本单元仅接实际 response-display 服务，不实现 request-only 复现 UI，不改变 S1 分析/报告，不代表正式审核或全部 REP-003/REP-005 完成。

## 已落盘范围

- 新增 `web/src/evidence-display-api.ts` / `.test.ts`。
- 新增 `web/src/components/results/EvidenceDisplayPanel.tsx` / `.test.tsx`。
- `web/src/components/results/ResultsPage.tsx` 仅接入正文权限入口、单一 Attempt 选择器、正文面板及说明文案。
- 本说明。没有修改 `api.ts`、通用大小限制、DB、后端、已冻结 request-only 纯组件、全局台账或 Git。

## 实际接口与验证边界

接口仅能构造 `GET /api/v1/runs/{run}/samples/{sample}/attempts/{attempt}/evidence?analysis_revision=1`。所有 ID 用十进制字符串校验到 int64 正数范围；不接受路径别名、query 注入、任意 URL、其他修订或调用者提供的大小上限。组织通过现有 `X-Organization-ID` 请求头发送。发出 fetch 前私有复制 selection，后续调用者修改其原对象也不能改变迟到响应的校验范围。

root 已将实际 `EvidenceService.PrepareDisplay` 输出补为标准 `{data,request_id}`，请求编号进入最终输出字节摘要。前端没有为正文开一个“允许缺少 request_id”的例外：沿用原 `api.request` 的 mandatory request_id、same-origin cookie、no-store、redirect:error、45 秒有界读取、解压后 8 MiB 成功响应上限、64 KiB 错误上限、UTF-8/媒体类型/声明长度/流读取次数/取消检查。既有普通 JSON 上限本来就是 8 MiB，本次未放宽。

成功 data 限定版本 `mii.evidence-display-output.v1`，精确绑定 run/sample/attempt/revision/is_final；状态闭集与当前后端一致。available 必须包含 hash 与完整 `display-redaction-v1` 文档。不可用状态必须 `content:null`，允许后端保留的合法 payload_hash（例如到期但密文尚待清理），不制造空正文。

内容严格限定现有版本、策略、source/request/template hash、request_changed、metadata_omitted 和 response schema；拒绝额外 Header/Endpoint/provider request ID 等字段。响应 Usage 只接受 null 或不大于 Number.MAX_SAFE_INTEGER 的非负安全整数，与当前 Go display validCount 一致；毫秒、HTTP、停止/解析分类与最大 256 项事件摘要均作闭集/范围校验。JSON 数字不是观测值时不补 0。

request_json 只做语法检查，**显示和保存的始终是服务端原字符串**，不由 JSON.parse 结果重编码，避免完整 int64 seed 经 JS Number 舍入。页面展示实际请求 hash、脱敏模板 hash、服务端认证载荷 hash，明确 request_changed；这些为已认证服务端副本提供的摘要，浏览器不声称独立验证了 AEAD 或全部规范字节。

## 交互与明文生命周期

1. 初始结果、S1 页、样本摘要和正文面板 mount 均不会自动请求正文；正文面板 mount 连权限都不主动读取。
2. 只有点击“查看 Attempt … 的脱敏正文”才先重新请求当前用户/组织权限，必须同时具有 `run.read`、`evidence.read`、`evidence.body`，再 GET 正文。`evidence.read`、`report.export` 或前端推断管理员身份都不能替代 `evidence.body`。
3. 样本只挂载一个正文面板，默认选择最终 Attempt（没有最终则第一个）；切换 Attempt 不自动加载。org/user/run/sample/attempt/revision/is_final 任一变化通过 keyed scope 卸载旧面板、abort 在途操作并清空显示。
4. 再次手动读取时先清掉既有正文，再核验权限。关闭面板、关闭样本、离开结果视图、卸载均取消；对不响应取消的迟到 fetch/正文答复同时检查 signal 与当前 operation identity，不再显示或触发过期的权限回调。
5. 权限不足、实际 401/403、会话/改密门禁均清空数据、取消请求，通知父结果页清掉 S1/正文缓存；格式/网络/503 错误也不保留上次正文。没有 storage、全局明文缓存、Blob URL、自动下载或自动重放。
6. React 普通文本 / `<pre>` 转义，绝不解释 HTML/Markdown、不生成动态 shell。复用 `result-card`、`run-metrics`、`result-hash`、`review-explanation`；局部 min-width:0、overflow-wrap:anywhere、pre 最大宽度与横向溢出保护，不改全局样式。

响应为空字符串且文档 available 时显示“已认证副本中的正文为空”；这与不可用状态有明确区别。0 天、不保留、未捕获、不确定、到期、旧历史无可信脱敏证明、脱敏失败、资源限制、来源错误、取消、捕获失败、封存失败分别说明。没有不可用时回退 raw 的按钮，也没有未实现的下载假按钮。

限制：JS 字符串及浏览器/开发者主动复制的已展示资料不能保证物理擦除；这里只释放组件引用并清除 DOM。权限变化只有在应用收到新上下文/权限/拒绝信号时可见，不能承诺撤回已发 socket 或用户已保存的字节；后端最终授权/审计/流期间复验是另一层职责。本轮未使用真实敏感数据做浏览器截图，也未把 DOM/CSS 检查说成真实窄屏视觉验收。

## 验证

使用固定 Node 24.19.0 / pnpm 11.19.0。只运行前端测试，无 DB 测试。

- API 专项 32 项：正确固定路径与超 2^53 ID、13 状态闭集、错误 scope/revision/finality、schema/数组冒充分类/不安全数值/事件/UTF-8 大小、未知字段、无 request_id、截断/非法 UTF-8、8 MiB 解压后上限和流取消、401/403、迟到响应，以及 caller mutation 不改变原请求范围。
- 面板专项 40 项：显式请求、真实三权限、无自动 S2、纯文本/大 seed、null Usage、全部不可用状态、空正文、再次请求前清空、初/后期撤权、scope 重挂载、关闭/卸载迟到响应、重复点击、实际 ResultsPage 单一 Attempt 切换、父视图撤权清除。
- 与原 ResultsPage 回归合并：3 文件、86 项通过（2.86 秒）。初轮新增 `it.each` 数组夹具被 Vitest 展开成单个字符串造成 5 失败，修正为具名对象夹具后通过；没有放宽生产权限判断。
- 完整前端最终冻结态：32 文件、816 项通过（37.32 秒）；此前 814、815 项全套亦通过。
- `pnpm --dir web typecheck` 通过；`pnpm --dir web lint` 无警告通过。
- 最终 `pnpm --dir web typecheck` / `lint` / `build` 均通过；保留 Vite 单 bundle 超过 500 kB 的非阻断提示（527.01 kB / gzip 156.28 kB），没有提高 warning 阈值掩盖提示。该终态包含局部 overflow-wrap/min-width 样式与请求 selection 快照修正。上述 6 文件已冻结供 root 复核；无 Git 操作。

root 追加复核：3 文件最终专项 87/87 通过（2.97s），契约全包三轮 0.468s 通过；真实应用新增服务场景在 SQLite/PostgreSQL、0/30 天单轮 30.875s 通过。真实浏览器尝试被工具以 `net::ERR_BLOCKED_BY_CLIENT` 拒绝，未读取页面、未绕过限制，新建空白测试标签已关闭。该次后端 hold 测试没有启用 `webassets`，会提供明确的未构建前端 503，因此即使后端测试最终通过，也不能计作内嵌前端或浏览器验收；后续必须使用实际构建和 `-tags webassets` 的实例。

后续：真实正文页面浏览器验收和完整产品验收仍缺。request-only 可信复现已有独立纯组件，但其保留、捕获入库和 UI 并不包含在本单元。
