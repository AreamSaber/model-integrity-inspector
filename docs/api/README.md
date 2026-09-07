# API v1 开发契约（M0-06）

版本：1.0.0-draft；2026-09-07。文件：openapi-v1.json（OpenAPI 3.1）。正式 TL/FE/QA 批准待统一审核；契约存在不表示接口已实现。页面对应 INTERACTIONS-V1.0.md，实际进度以持续开发台账和需求矩阵为准。

## 约定

- 前缀 /api/v1；所有业务 ID 使用十进制字符串（数据库仍为 int64，避免 JS 精度丢失）。UTC RFC3339 时间；金额为整数微单位，单价未知/风险维度缺失使用 null，不使用 0 冒充已知。
- JSON 成功 envelope 为 data + request_id；错误为 error{code,message,details} + request_id。详情只可包含 field/retry_after_seconds/reason 分类，不回显凭证、完整 Endpoint query 或上游原始正文。
- 会话使用 HttpOnly/Secure/SameSite=Strict Cookie。仅显式 loopback 开发模式可使用非 Secure；浏览器不保存密码/Key/session 到 localStorage。认证写请求校验 X-CSRF-Token 与同源 Origin；匿名登录/初始化同样检查 Origin。跨站请求不提供宽泛 CORS。
- 首次初始化还需引导授权：远程/HTTPS 部署要求 `X-Setup-Token` 与独立环境变量中的一次性引导令牌匹配（至少 32 字符）；仅明确的 loopback HTTP 模式允许真实 loopback 客户端不带令牌。`X-Forwarded-For` 不用于放宽此规则。初始化成功后该写入口永久关闭；令牌不存入数据库或浏览器持久存储。
- 业务组织通过 X-Organization-ID 明确选择，后端必须核验成员权限；系统管理员跨组织操作须单独授权并审计理由。成员接口路径组织与权限绑定；不存在/跨租户对象统一 404，不回显它的元数据。
- 列表使用 limit（默认 25、最大 100）和 opaque cursor；管理目录及目标列表使用唯一ID稳定升序，运行历史使用created_at/id稳定倒序。下一页游标签名并绑定用户或组织、资源和过滤条件，非法或换范围游标返回400。列表不含正文、Secret密文或大JSON。
- 写请求使用精确大小写的JSON字段；拒绝重复字段（含嵌套对象）、未知字段、重复文档、无效UTF-8及超过32层的嵌套，正文上限64KiB。不可空字段显式null拒绝；PATCH通过省略字段表示不变。已实现管理与目标接口均使用此解码边界。
- 乐观锁更新携带 version；冲突 409，客户端重新拉取。写请求有最大体积限制，未知字段拒绝（additionalProperties=false）；模板参数、Header 和 Endpoint 仍须领域层校验。
- Run 创建/预检/报告/回放/备份返回 202，后台由数据库 Job 执行。预检已增加 GET 读取结果；不在 Handler 同步等待上游。
- SSE 使用带同源 Cookie 和组织 Header 的 fetch 流；Last-Event-ID 是与路径相同的 `<Run ID>:<持久版本>`，不是授权。每次连接必发当前数据库快照（终态也发），其 data 与 GET Run 相同而不带 envelope；客户端拒绝身份/冻结配置变化或版本倒退，断线及终态通知后 GET 原 ID 核对，最多12连接/1小时。每2秒重验持久会话/账号/成员/权限，DB与写操作1秒期限，10秒心跳，单连接5分钟；撤权发闭合错误码后关闭。每进程64连接、每用户4连接，超限429 Retry-After:5。不依赖 EventSource 传自定义 Header，绝不自动重发 POST。事件不含正文和凭证。
- 下载使用已授权数据库记录解析的路径，不接受用户文件路径；返回 attachment、nosniff、HTML sandbox CSP。下载/正文读取需审计。报告不包括 S3 凭证，默认导出脱敏证据；canonical hash 对去除 content_hash 的 JSON 计算，需版本化规范。
- 自定义 Header 整体 writeOnly，与 API Key 同一加密 Secret；目标读接口只返回掩码/版本。保留 Header、CRLF 和不安全地址拒绝，Key 更换使用独立权限。
- report、risk、confidence 与人工 review 分离；只读接口绝不从 Secret 重新构造内容；黑盒最高 B，无有效样本必须 insufficient。

## 权限实现要求

每个操作 x-permission 标记领域权限，不等同于现有实现。read 指当前组织可读；run.cancel-own-or-any 按 PRD（管理员/审计员可停止，运营/开发仅本人）；高成本、自定义包、正文访问、secret.replace、report.export 必须再按角色/显式授权检查。系统角色与组织 admin 不可混淆。任何角色都无 Key 回显权限。

## 验证和冻结

运行 .tools/go/bin/go test ./tests/contracts 检查 77 项追踪完整性、路径/参数/引用/敏感字段和原型覆盖。这是仓库语义回归，不替代完整 OpenAPI 规范校验、真实 API 契约测试或 E2E。实现每组 API 后，应补上实际请求/权限/失败路径测试，将 x-development-status 和台账据实更新；未实现接口不得返回样例成功数据。

正式 schema/接口变更与客户端同时提交；不默默缩减原计划。P1 reanalyze、Webhook、OIDC、PDF/CSV 不作为当前 API 已完成项。

## Run 控制链路（持续开发）

当前55路径/74操作/109 schema；这些数量包括尚未实现的计划接口，不是交付完成数量。有效权限读取及 Run estimate/confirm/read/cancel、SSE、历史/结果/S1证据、目标趋势及组织总览均有真实HTTP测试。`RunQuote`包含草稿ID/有效期、冻结版本、预算和保守估算；`ConfirmRunInput`不接受完整执行计划或第二套选项。自定义选项与当前生成器上限一致；未来baseline/early_stop仍列为待实现，当前严格拒绝传入。运行时现接入实际分析和可读结果，确认按真实 readiness 与版本/费用/权限准入开放；依赖未就绪仍明确503。

已确认草稿的重复确认使用同一owner/org/hash Run收据，保留于Run而非即将过期的S2草稿行；被清理的未确认草稿为404，尚未清理但过期为409。金额未知不等于零费用；默认已知价格金额上限和所有管理员收紧均在报价/签名前生效。详细开发限制见DEV-RUNTIME-V1.md。

`GET /runs` 使用轻量 RunHistoryItem。历史/结果/证据及趋势六条 route 已标记 implemented-database-backed；现仅支持固定修订1，默认结果和趋势只需 run.read，statistics/Finding/Sample/Attempt 另需 evidence.read。结果只返回闭集 S1、开发/未校准状态和C/D；未执行或缺失不伪造分数。schema 与45个实际 Go 投影（含报告及组织总览）的字段/必填/可空/封闭结构由 `TestPublicRunReadSchemasMatchActualClosedDTOs` 比较；辅助 `go run scripts/read-contract-schemas.go` 只打印候选 schema，仍需人工复核领域语义及 API 失败路径，不能代替权限测试。生成输出不是完整 OpenAPI，不得整体覆盖其他未注册 schema；本次仅定向合并10个 Overview schema。

## 组织总览（M6-01 开发单元）

`GET /api/v1/overview?days=7|30` 同时需要 `run.read` 和 `target.read`，在一个只读快照复验持久会话、组织、成员与两项权限。`days` 默认7，拒绝未知/重复/空/补零参数；组织来自 Header，不接受自选组织时区或 as_of。UTC/IANA 组织时区决定含今日的7/30个日历日，Run按 `created_at ∈ [start_utc,as_of)` 归属，今日明确 partial；DST不按固定24小时计算。`Local`/损坏时区明确503，不静默改UTC。

当前目标总数包含禁用、排除软删除，与时间窗无关。任务按Run计数、11种状态分列；COMPLETED不等于所有HTTP调用成功。已发布固定revision 1风险按检测包及四版本分层，不跨版本平均分；未发布/无分值单列。费用仅为既有Run估算，已知小计与未知Run分列，未知或空窗的完整总額为null。cohort的c1等ID只在本响应内关联每日明细，不是持久业务ID。端点不读取正文、Endpoint、凭证、conclusion_json或逐Run样本。

保护上限：窗口Run/当前目标各10000，cohort16，响应256KiB；超限返回 `MI_OVERVIEW_LIMIT`，绝不截断为总体。精确GET从middleware入口到数据库读取使用2秒context，超时 `MI_OVERVIEW_TIMEOUT`；聚合准入每进程2/每组织1，非阻塞忙返回429 `MI_OVERVIEW_BUSY` 和 `Retry-After: 2`，不承诺限住认证前全部流量。坏时区为 `MI_OVERVIEW_TIMEZONE_INVALID`，坏S1为 `MI_ANALYSIS_RESULT_INVALID`；其他会话/权限/初始化/服务错误沿用闭合规则。`Cache-Control: no-store`。这些是开发资源保护，不是生产P95/容量验收。

真实TLS Quick18+Custom9经Worker发布后，SQLite/PostgreSQL实际应用三轮61.209s验证了7/30窗口、两Run而非27Attempt、独立包分层、未知费用null及每日分母。仓储/API另有双库索引EXPLAIN、10000+1拒绝、整数溢出、撤权快照及取消回滚回归。前端27文件623测试及typecheck/lint/build通过；root总览/应用105测试复跑通过。真实SQLite浏览器验证7/30切换、刷新快照、历史跳转/返回、退出和无控制台错误，hold121.660s含交互等待，不是性能结果；不是浏览器活动任务故障验收。

## 目标历史趋势（HIS-001 后端开发单元）

`GET /api/v1/runs/trends?target_id=<ID>` 对应 operationId `listRunTrends`。必须携带当前会话 Cookie、`X-Organization-ID` 及正十进制字符串 `target_id`，权限为 `run.read`；S1 聚合不要求 `evidence.read`。每次请求在同一个只读快照中复验持久会话/账号/组织/成员/权限并读取 Run 与 Attempt。不是前端过滤授权，也不重新解密响应；该后端单元不等于趋势前端已接入或正式审核通过。

筛选沿用历史列表：`q`、`status`、`package`、`model`、`channel_id`、`risk_level`、`date_from`、`date_to`，另有 `limit`（默认25，范围1–100）和 opaque `cursor`。日期为包含边界的 Run 创建时间，接受 RFC3339Nano 并规范为 UTC；起点不得晚于终点。`q` 是当前目标名称/模型的大小写不敏感字面子串；`model`、`channel_id` 匹配当前实时目标档案，均不是冻结历史请求。三项文本最多128个 UTF-8 字节，拒绝 NUL/CR/LF；显式空的 model/channel_id 拒绝，空 q 表示无搜索条件。重复或未知参数拒绝；不接受 `analysis_revision`、`include`，修订固定为1。

按 `created_at DESC,id DESC` 返回 `{data:{items:[{run:RunHistoryItem,attempts:AttemptTrend}],next_cursor,scope,analysis_revision,success_rate_basis,latency_basis,development,calibrated},request_id}`。`next_cursor` 无下一页时为 null；签名游标有效期24小时，绑定 reader、组织、趋势资源/修订、规范化筛选和 q，不能用于 `/runs` 或更换范围。改变 limit 不改变范围；锚点正常状态变更保留创建时间/ID位置。未知/其他组织的 target 在已经授权的当前组织中返回200空页，不泄漏对象是否存在；已删除目标仍按 target_id 保留历史，当前档案字段可为 null。

每个 Run 独立返回固定 revision 1 的已发布风险/置信度、版本和真实派发 Attempt 聚合。尚无发布结果时 `run.result=null`。`scope` 固定 `run_page`：最多100条当前页及只用于判断下一页的一条探测行，不提供全部目标、全部组织或全历史汇总；翻页之间运行状态可以合法变化。

| 字段 | 真实口径与缺失处理 |
|---|---|
| dispatched / retry_attempts / logical_samples | 包含每次重试的派发记录数 / attempt_no>1 的记录数 / 已派发的不同逻辑样本数。独立预检不包含在此 Run 口径内；重试不变成独立统计样本。 |
| succeeded / failed | 成功须同时是 COMPLETED、VALID/VALID_WITH_WARNING、HTTP 200、无 error 且开始/完成时间有效。failed 是其余已知完成且无效的结算，包括协议、安全、取消等失败；COMPLETED 本身不是成功。 |
| uncertain / in_flight | 分别为 UNCERTAIN 和尚未结算的 DISPATCHED，单独展示，不能当作已知失败或成功。 |
| success_rate_percent / success_rate_denominator | `100 × succeeded / dispatched`，分母明确包含重试、unknown和在途；无派发时百分比为 null，分母为0。仅未知/在途但没有已证实成功时百分比可为0，这不是“它们都失败”，更不是未来成功概率。 |
| latency_samples | 有合法非空 duration_ms 的已结算 COMPLETED Attempt 数，包含成功和失败。缺失观测、在途与 UNCERTAIN 恢复的占位0均排除；实际观测到的0毫秒保留。 |
| latency_mean_ms / latency_min_ms / latency_max_ms | 上述有效观测的均值/最小/最大值，`latency_samples=0` 时三者均为 null。表示客户端总耗时，不是 P95、TTFT 或供应商内部计算时间。 |

`dispatched=succeeded+failed+uncertain+in_flight`，同时等于 `logical_samples+retry_attempts`；不使用 Run 完成数/有效样本数替代调用分母。当前实现尚不清理 Attempt 元数据，因此 request_count 与派发记录数不一致时拒绝结果，而不是猜测缺失记录。SQL 仅按选定 Run 和组织读取 S1 聚合，内部最多读取3001条记录并对超过3000条的 Run 拒绝；未知 status/validity/error、断裂身份绑定、负数或超过86400000毫秒的 duration 等损坏数据返回503 `MI_ANALYSIS_RESULT_INVALID`，不降级成空页或0。不会读取请求快照、响应正文、证据密文或 conclusion_json。

错误边界：400 `MI_INVALID_REQUEST`（参数/游标/范围）；401 `MI_SESSION_REQUIRED`；403 `MI_PERMISSION_DENIED` 或 `MI_PASSWORD_CHANGE_REQUIRED`；409 `MI_SETUP_REQUIRED`（尚未初始化）；500 通用 panic 保护及503数据库/读依赖不可用使用闭合 `MI_SERVICE_UNAVAILABLE`。共用契约保留429网关限流响应，但当前趋势 handler 没有独立限流器，声明不表示限流已实现。所有错误不带上游正文或原始异常。`development=true`、`calibrated=false`；风险仍受C/D等级及黑盒替代解释限制，不证明模型真假或供应商内部行为。

`tests/contracts/run_trends_test.go` 检查真实 Go 路由/handler 的注册、授权和固定响应常量，检查参数、operation、错误枚举、分页上限、可空分母与递归无S2闭集。实际双库行为回归位于 `internal/integrity/api/run_trends_test.go` 和 `internal/integrity/repository/run_trends_test.go`；契约检查不替代这些请求/并发快照/权限测试。
