# M6-01 组织检测总览：最小实现提案

2026-09-07。只读需求/实现核对后的开发提案，不是已实现功能、正式审核或性能验收。本文不变更 PRD、规则权重或发布门槛。

## 依据与现状

- PRD 10.1 要求组织检测总览包含目标数、近 7/30 天任务数、风险分布与异常趋势；11.1 将评分、Usage、延迟和渠道关系列为组织隔离的 S1。交互稿 `docs/design/INTERACTIONS-V1.0.md` 的 overview 节另要求近期开销、空组织引导、失败不显示假零值、系统管理员显式切组织。
- TECH 10.10 禁止默认列表读取 JSON 大字段；14.1 要求权限控制入口/字段，后端仍校验。PRD 12.1 / TECH 19 的性能与容量需实际验收，不能由本提案宣称通过。
- 现有 `run/trends.go` / `api/run_trends.go` 是单目标、当前 Run 页的 Attempt 统计；不能遍历分页拼装组织总览。总览不调用它，也不调用逐 Run `ReadPublishedResult`。
- `repository/run_history.go:resultReadTransaction` 已提供 SQLite pinned `BEGIN DEFERRED`、PostgreSQL `REPEATABLE READ READ ONLY`，在同快照复验用户、会话、成员和 `run.read`。它只固定检查 run/evidence 权限，不能据此读取未授权的目标总数。
- 现有 `idx_runs_org_created(organization_id,created_at,id)` 可限定组织时间窗；结果主键 `(organization_id,run_id,analysis_revision)` 可定位 revision 1。现有目标索引未以 `deleted_at IS NULL` 限定全部当前目标，软删除历史较多时需增加当前目标部分索引。

## 建议接口与时间窗

新增 `GET /api/v1/overview?days=7|30`，组织仍来自严格 `X-Organization-ID`；拒绝未知、重复、空 query，不支持客户端指定组织、时区、as_of 或任意大窗口。默认 7 天。前端用 7/30 切换读取相应完整窗口，不伪称同时完成两个窗口查询。

一次 GET 在一个授权只读事务中读取组织当前 IANA 时区并固定 `as_of`；以组织时区计算含今日的 7/30 个日历日，从第一个当地日 00:00 开始，到 `as_of` 为止，使用半开区间 `[start_utc,end_utc)`。今日为未完成日，不能和完整日作直接下降判断。每天的 UTC 起止也返回；使用 Go `time.AddDate` 的当地日边界处理 DST 的 23/25 小时，不用 UTC 24 小时或数据库环境时区替代。未知/损坏时区失败，不静默改 UTC；尤其当前管理验证允许 `time.LoadLocation("Local")`，总览不能把它当稳定 IANA 地区，应提示管理员选择 UTC 或明确地区。建议新仓储文件引入标准库 `time/tzdata`，使单二进制与容器行为一致。

返回闭集 DTO，包括组织 ID（十进制字符串）、schema/version、`scope=organization_window`、时区、精确窗口、`as_of`、`analysis_revision=1`、`development=true`、`calibrated=false`。不返回名称、模型、Endpoint、正文、任意诊断、Secret 或自由文本结论。

## 指标口径

1. **目标数**：当前组织 `deleted_at IS NULL` 的目录记录，按 `active/disabled` 分列，总数等于两者和。这个数不受 Run 时间窗限制；标注“当前目录目标，含禁用”，不是可连通/可调用数。已删除目标的历史 Run 仍参加窗口统计。
2. **任务数**：以 Run 的 `created_at` 归属窗口/当地日期，每 Run 一次。返回完整闭集状态计数，和等于窗口 Run 数；不以请求、Job 或 Attempt 代替任务数。
3. **不新增含混的任务成功率**：`COMPLETED` 表示当前分析流程的完整结果状态，不意味着上游每次调用成功或模型健康。总览第一版仅展示 Run 状态计数。Attempt 成功率仍在真实目标趋势页，口径为 `confirmed_successes / all_dispatches`，分母包含失败/未知/在途，重试不是独立样本；总览不取平均百分比，也不以 completed_samples/request_count 计算成功率。因此无需新增全组织 Attempt 扫描或延迟聚合，与 HIS-001 不重复。
4. **风险分布与每日风险信号**：只读取同组织、`analysis_revision=1 AND is_published=true` 的内联摘要列。无发布结果单列 `unpublished_runs`；发布结果的 `overall_risk=NULL` 单列 `unscored_runs`。有可估综合风险的结果按现有六种风险分类计数，分布分母为有分值的已发布结果数，不能将未发布或不可估当低风险。证据不足不是健康判定。
5. **版本/检测包分层**：风险分布及每日风险信号按四个冻结版本 + 检测包分 cohort；不跨版本平均分数。每天呈现各 cohort 的原有风险类别计数，不新增“异常”阈值、不认定显著恶化。若多个 cohort，同时显示“组成与规则版本变化，不能归因上游行为”；同版本也不证明样本或配置可比。Run 总数可以跨 cohort 相加，但不得将这种计数相加包装成统一风险统计。
6. **近期开销**：汇总窗口 Run 中既有 `estimated_cost_micros`，明确 USD micros、派发阶段估算而非供应商账单。已知费用 Run 与未知费用 Run 数分列；有未知时 `complete_total_micros=null`，已知小计只能标“已知部分”。没有任何已知观测时小计为 null；空窗口显示无任务，不显示估算成功。已知且确实为零仍可显示 0。所有 SUM 保持整数，越界失败，不转 float 或溢出截断。

建议返回结构为 `window / targets / runs / costs / risk_cohorts / daily`，每日结果最多 30 天。所有计数非负安全整数；各分母/分项和交叉核对。真实空窗口的计数可以为 0，比例与不可估值仍为 null；“没有数据”“没有权限”“数据库错误”不能互相替代。

## 授权、查询和失效边界

- 最小第一版整个接口同时需要 `run.read` 与 `target.read`。缺任一项就 403，完全不返回另一区块；不从系统管理员标志推断组织权限。前端可以引导用户访问其仍有权的单独历史页，但不能把受限卡片显示为 0。
- Handler 初检后，仓储在同一只读快照复验当前用户/会话/强制改密/组织/成员、`run.read`，并在 callback 内用仅允许 `target.read` 的固定授权查询复验目标权限；无调用方任意 permission 字符串或授权 bool。组织时区和所有计数在此快照读取，不能先后调用多个 Service 拼结果。
- 撤权发生在快照开始前应拒绝。快照读取开始后的并发撤权不改变既定快照；这不是瞬时撤权承诺。查询有短总期限，下一次读取重验。浏览器任何失败、组织/账号/窗口变化和离开页面清空/abort，不保留旧组织缓存，不在 localStorage 保存。
- 业务查询仅采用按组织/时间索引限定的 SQL 聚合和有界 CTE，不向 Go 或前端加载整窗 Run、Attempt 或结果正文。不要复用 `historyQuery` 的逐 Run 样本相关子查询和当前目标描述 JOIN。
- 先以 `LIMIT cap+1` 在 SQL 内做窗口 Run 和当前目标的基数保护，再聚合；初始开发保护建议两者各 10,000、cohort 上限 16、响应上限 256 KiB。超过上限整个请求返回明确 `MI_OVERVIEW_LIMIT`，不返回截断统计或假总体。这是可调整的开发安全界限，不是已验证生产容量；M7 大数据验收如不满足，后续实现经事务维护的 rollup/优化，不能悄悄去掉上限。
- 聚合 SQL 数量固定（目标保护/聚合、Run 保护、状态/费用/每日、风险 cohort/每日、组织时区等最多 6 条业务查询；既有固定鉴权流程另计），禁止按 Run 发 N 条 SQL。每日边界可参数化为至多 30 行边界 CTE，跨数据库一致，不能对整列 `created_at` 使用不可索引的字符串转换。
- 提议本接口端到端 DB context 2 秒、进程级最多 2 个并行聚合/同组织 1 个，忙时 429 + Retry-After；不无限等待连接池。取消停止 DB，沿用受限事务回滚。2 秒是新接口保护上限，不放宽任何既有业务期限，也不证明 P95 指标已达成。
- 在 SQL 中验证每条被聚合的状态、摘要闭集、已支持冻结版本、C/D 等级、置信度范围与不可估约束；自由文本先做字节上限。未知/非法摘要不得进入低风险或“其他正常”，而应整次 503 `MI_ANALYSIS_RESULT_INVALID`。不读取 `conclusion_json/config_snapshot/error_summary`。
- 建议错误闭集：400 参数错误；401/403 会话/成员/权限/强制改密；429 聚合忙；503 `MI_OVERVIEW_LIMIT` / `MI_OVERVIEW_TIMEOUT` / 配置异常 / 服务不可用 / 结果损坏。除 genuine 空窗口以外，不返回成功 envelope 的空数组掩盖错误。响应 `Cache-Control: no-store`，无出站、写入或自动报告。

## 拟改文件与验证

独立新增：

- `internal/integrity/repository/overview.go`、`overview_test.go`、`overview_read_test.go`：固定授权、只读快照、读取时区后计算当地日期窗口/DST、SQL 聚合/上限/双库测试；不要先在另一事务读取时区。
- `internal/integrity/run/overview.go`、`overview_test.go`：窗口元数据核对、闭集 DTO、分母/安全整数投影。
- `internal/integrity/api/overview.go`、`overview_test.go`：严格 query、权限、并发/期限、响应上限。
- `web/src/overview-api.ts`、`overview-api.test.ts`、`web/src/components/overview/OverviewPage.tsx`、`OverviewPage.test.tsx`：真实 GET、7/30 切换、计数卡片/文字分布/每日表格、失败/空/无权限/取消，无依赖新增。

仅必要共享接线：`internal/integrity/api/control.go` 的注册；`web/src/components/SessionLayout.tsx` 用新 OverviewPage 替换旧 Overview；`web/src/App.test.tsx` 同步新的真实总览请求。后端合同/台账仍由 root 同步，不在此子任务擅改。

索引建议：SQLite/PostgreSQL 都增加 `integrity_targets(organization_id,status,id) WHERE deleted_at IS NULL` 的部分索引。不修改旧迁移；实施时先由 root 分配下一版本号（三方 up.sql + `migrations/migrations.go` 注册；当前只观察到已冻结 14，不预占其他 agent 的下一号）。现有 Run 时间与 Result 主键索引保持不变。

必须回归：精确 7/30 边界、午夜/闰日/DST/坏时区、当前日 partial 标记；已删/禁用目标与旧 Run；同时间不同 ID；各状态、无结果/NULL 风险/混合版本/证据不足；重试不影响 Run 数；未知成本/整数溢出；跨租户/成员/会话/权限撤销与快照一致性；SQLite 不占写锁、PostgreSQL 同快照、取消回滚；cap+1/超长字段/损坏摘要 fail closed；两库 EXPLAIN 证明时间窗与当前目标索引实际使用；前端不累计页、不自动重试、不把缺失显示 0，真实浏览器切组织与 7/30 页面。性能/百万样本仍归 M7 独立验收。
