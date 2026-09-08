# M6-01 / SYS-006：真实只读运行状态首阶段

开发实现与边界记录，2026-09-08。不是正式审核、发布批准或完整 SYS-006 / SYS-008 验收；本阶段包含真实只读后端及已接线前端页面。不含设置、迁移执行、维护、备份或恢复动作。

## 基线与目的

对应 PRD 9.0 SYS-006、11.1 数据分级和 11.2 保留策略；TECH 5.0、11.0、13.5/13.6、14、15、18、19.4/19.5；开发计划 M1-09/M6-01；INTERACTIONS 的 system 页面。已有公开 `/health`、`/ready`、`/version` 保持原用途，不新增公开详细诊断。系统状态页不能由单个 Run 状态替代，也不能把缺失监测项标健康。

## 授权与 API

`GET /api/v1/system/health`，会话 Cookie + 单个标准十进制 `X-Organization-ID`，不接受 query/body。HEAD 明确 405；GET 无 CSRF 写操作。使用现有契约的 `system.read`，不添加或修改权限策略。当前 Principal 的 system 权限依赖持久化 `is_system_admin`，普通组织 admin 不因此获得系统角色。`/auth/permissions` 是组织权限列表，不能据其中缺少 system.read 推断系统角色不存在。

HTTP 前置认证限制无权工作；仓储在同一只读快照复验启用用户、未撤销未过期会话、密码时效、非强制改密、系统管理员、所选组织和成员启用，以及 `run.read`、`audit.read` 两项实际 grants。系统角色不豁免组织权限。不遍历组织、不接用户路径、不查询其他组织的任务/审计数据。收集本地 Runner 观测后再用新事务复验授权，已提交撤权则不返回快照；不缓存授权。

正常诊断含局部失败仍为 200 envelope；400 输入错误，401 会话，403 权限/强制改密，409 初始化要求，429 `MI_SYSTEM_STATUS_BUSY`，503 `MI_SYSTEM_STATUS_TIMEOUT` 或 `MI_SERVICE_UNAVAILABLE`。不回显数据库、文件系统或密码学错误。数据库不可用导致当前身份无法复验时直接 503，不凭缓存角色返回诊断。

## 闭合投影

实际类型：`identity.SystemStatus`。organization_id/user_id 是字符串；时间 UTC。固定组件字段、固定 state/source/reason，无任意 detail/error 文本。

- `observed_state=ok|degraded` 仅描述已经观测的检查，**不是整体 ready**；`coverage=partial` 明示远端 Worker、当前存储可写性、周期配额、清理和备份仍未完整观测。首阶段不存在“全部健康”返回值。
- database：同快照授权与实际 SELECT 成功，只说明当前读连接，不证明写可用或容量。
- schema：对预期 migration 完整版本/name/checksum/status 比对；只返回预期数和最多预期数+1的已观测行数。异常为 error，不输出名称/哈希/SQL；不执行迁移。`observed_migrations` 不是超限情况下的精确全量数。
- local_worker：all 模式读取真实 `Runner.Ready()`，启动领取前、失败/停止后为 error。server 模式为 not_applicable。该原子观察发生于数据库观察之后，不声称它们是同一个跨系统事务。
- remote_workers：unavailable。现 PostgreSQL 队列没有远端消费者注册表；Job 租约及 API `/ready` 不能证明远端消费者当前存活。
- organization_jobs：只统计所选组织 pending/running Job，分 pending_ready、pending_delayed、running_leased、running_expired；总和必须一致。Job 不是 Run、Attempt 或独立统计样本，重试不会被当作新样本。不是历史成功率或积压时长告警。
- organization_audit：当前组织链头及最后至多两条事件，使用原有纯验证规则。verified_tail_events 仅 0～2 的尾部数量，不是全链认证。已初始化读路径的空/缺失链头视为 invalid；不输出事件内容/HMAC/hash。启动的全链检查不被重新包装成持续全链健康。
- master_key/report_storage：只记录本进程成功启动安全验证的时刻，state=startup_verified；不持续读取主密钥，不解密全部凭证，不创建探测文件，不枚举报告目录，不宣称当前容量、写权限、所有制品完整性均正常。来自真实 prepare 流程，不来自用户布尔输入。
- build：当前受信编译/运行版本和内置 bundle 版本；未知 commit/构建时间为 null。若嵌入调用方未传 CLI Build，则使用本二进制 `buildinfo.Current()`，不编造发布版本。无主机路径/DSN/主密钥版本/客户端配置。
- retention_policy：显示当前组织已设置的正文天数与当前实现固定 30 天写策略，但 state=unavailable、明确尚未把组织设置绑定到写入策略；配置为 0 不冒称已停止正文留存。
- organization_periodic_quotas：unavailable，不能以未消费的 quota_json 或空对象宣称日/月配额生效。既有 Run 硬预算/层级并发不变，本阶段不伪造其剩余额度。
- retention_cleanup/backup_restore：unavailable。存在 Job 类型不等于运行时已注册清理 handler；没有持久化备份/恢复回执不返回“从未失败”或“已备份”。临时预估过期和 Run/report reconciliation 不等于数据保留清理。

## 资源与安全上限

- 精确 GET/HEAD 路径在 middleware 的 SetupStatus/Current 认证 DB 读取之前设置总计 2 秒 context 与写 deadline。
- 独立进程级两请求无等待 admission 在认证前获取；组织级一请求在授权后获取。请求结束释放，不保留空闲组织 ID。不改变 Worker 领取、取消、收尾或 fencing 期限，不宣称生产容量验收。
- 只读事务：PG REPEATABLE READ READ ONLY；SQLite pinned connection + BEGIN DEFERRED，取消时 bounded rollback，不占用 BEGIN IMMEDIATE 写锁。
- Job 查询使用现有 `(organization_id,status,id)` 索引，子查询最多 10,001 条；超过 10,000，该组件为 unavailable 且所有计数 null，不返回被截断的健康总数。
- schema 最多当前预期条数+1；审计最多一个链头与两条事件。所有实际读出的可变文本在 SQL 中字节封顶；审计超限用不可规范化的控制字符 sentinel，不能把损坏的大字段截成合法原值继续验证。
- 响应 JSON 最多 31 KiB，留 1 KiB envelope 空间；no-store/nosniff。没有原文、密钥、secret reference、端点、目录路径、HMAC 或任意上游错误内容。
- 不调用遍历全部组织的 `VerifyAllAudit` 作为页面探测，不获取新队列消费者，不触发网络/维护/导出。

## 前端实现与集成边界

新增 `web/src/system-status-api.ts` 与 `components/system/SystemStatusPage.tsx`，页面参数扩展现有 `ManagementContext` 并要求显式 organizationID；共享 SessionLayout/App/api.ts 由集成任务接线，不在本单元修改。预期路由为 `#/system`，角色标记只供导航提示，不能代替真实响应授权；页面本身不凭 systemAdmin 布尔标志接受或拒绝状态。没有额外权限接口预检，避免将组织 permissions 列表冒充系统权限来源。

- 仅首次进入及手动刷新发出一次真实 GET，无 query/body、自动轮询、POST 或出站模型请求。复用已有 same-origin Cookie、组织头、no-store、redirect:error 的有界 JSON 请求读取器与 45 秒客户端总期限；后端认证前 2 秒保护期限不变。没有无限响应流读取或自动重试。
- 客户端严验字符串组织/用户 ID 与当前 scope 相同；固定字段、组件专属 state/source/reason 元组、时间格式、版本格式、计数范围及分母相等。DTO 再限制 31 KiB；不接受额外 S2 字段、自由错误文本、路径或端点。已初始化的成功审计尾部必须实际验证 1～2 个事件；异常/不可观测时计数和末尾时间都为 null。
- 当前数据库快照、当前本地 Runner 及本地启动记录分别标来源和时间。远端 PostgreSQL 与本地进程使用不同主机时钟，客户端不编造先后关系或时钟偏差容忍常数；同一数据库来源的 checked_at 必须匹配 observed_at。
- 已观测项未返回错误也始终显示覆盖不完整，不显示全系统绿色健康标志。任务 null 计数显示“未知 / 无观测”，只有真实空队列显示 0；Job 不是 Run、成功率或独立样本。审计只说明尾部校验，主密钥和报告存储只说明启动校验。
- 手动刷新立即清空原快照；网络失败、503、429、权限撤销、畸形身份/响应均不保留旧状态。401、无法信任正文的 401/403 进入现有会话失效流程；强制改密进入既有改密门控。用户/组织切换创建独立页面 scope，离开、切换或重读取消旧请求；迟到响应不能覆盖新 scope 或触发旧会话回调。
- 加载状态、错误聚焦、刷新后的标题焦点和键盘操作已实现；观测表采用现有可横向滚动的表格类，无新增全局样式、依赖、备份/恢复/清理/设置伪按钮。不将暂未接入的维护能力显示成“从未失败”。

独立客户端与页面 88 项受控真实 fetch 交互测试已通过；全前端 30 文件 / 739 项测试、TypeScript、lint、生产 build 通过。build 仍提示现有入口 chunk 超过 500 kB（警告，不调整阈值）；新页面尚未在本单元接路由，故不宣称这次 build 已包含可访问的系统页面或已完成真实浏览器验收。

## 验证范围

新增仓储双库验证授权、撤权、损坏 schema/审计大字段、Job 分类与超限、快照一致性、SQLite 不阻塞另连接写入、PG READ ONLY、取消后连接可复用。HTTP 验证当前会话、普通系统角色拒绝、组织绑定、输入拒绝、响应脱敏、组织/全局 admission、认证前 deadline、读取中注销与数据库失联。实际 app 流程初始化登录后观察真实 SQLite/PG all Worker 起停，并验证 PostgreSQL server 的远端 Worker unavailable。全部测试仅本机数据库/HTTP，无上游付费调用。

主任务已把 `#/system` 接到上述页面，新增App级组织切换、无组织、服务端拒绝、会话撤销和离开取消测试；接线后全前端744测试、lint、typecheck/build通过。SQLite实际应用浏览器登录、系统读取及手动刷新已验证，页面正常显示迁移15条、活动Job为0、尾部2事件、真实本地Worker状态和明确不可观测项。2026-09-08新实例追加全会话注销后重新登录→系统读取，390×844视口实际clientWidth/scrollWidth均375，console warn/error为空，视口已恢复；完整浏览器故障验收尚未执行。正式审核、灾备演练、生产容量仍单列，不由本阶段状态页推导。
