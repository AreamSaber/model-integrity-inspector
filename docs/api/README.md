# API v1 开发契约（M0-06）

版本：1.0.0-draft；2026-09-07。文件：openapi-v1.json（OpenAPI 3.1）。正式 TL/FE/QA 批准待统一审核；契约存在不表示接口已实现。页面对应 INTERACTIONS-V1.0.md，实际进度以持续开发台账和需求矩阵为准。

## 约定

- 前缀 /api/v1；所有业务 ID 使用十进制字符串（数据库仍为 int64，避免 JS 精度丢失）。UTC RFC3339 时间；金额为整数微单位，单价未知/风险维度缺失使用 null，不使用 0 冒充已知。
- JSON 成功 envelope 为 data + request_id；错误为 error{code,message,details} + request_id。详情只可包含 field/retry_after_seconds/reason 分类，不回显凭证、完整 Endpoint query 或上游原始正文。
- 会话使用 HttpOnly/Secure/SameSite=Strict Cookie。仅显式 loopback 开发模式可使用非 Secure；浏览器不保存密码/Key/session 到 localStorage。认证写请求校验 X-CSRF-Token 与同源 Origin；匿名登录/初始化同样检查 Origin。跨站请求不提供宽泛 CORS。
- 首次初始化还需引导授权：远程/HTTPS 部署要求 `X-Setup-Token` 与独立环境变量中的一次性引导令牌匹配（至少 32 字符）；仅明确的 loopback HTTP 模式允许真实 loopback 客户端不带令牌。`X-Forwarded-For` 不用于放宽此规则。初始化成功后该写入口永久关闭；令牌不存入数据库或浏览器持久存储。
- 业务组织通过 X-Organization-ID 明确选择，后端必须核验成员权限；系统管理员跨组织操作须单独授权并审计理由。成员接口路径组织与权限绑定；不存在/跨租户对象统一 404，不回显它的元数据。
- 列表使用 limit（默认 25、最大 100）和 opaque cursor；管理目录及目标列表使用唯一ID稳定升序，运行历史将使用created_at/id稳定倒序。下一页游标签名并绑定用户或组织、资源和过滤条件，非法或换范围游标返回400。列表不含正文、Secret密文或大JSON。
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

当前52路径/71操作/72 schema；新增有效权限读取及Run estimate/confirm/read/cancel的真实HTTP测试。`RunQuote`包含草稿ID/有效期、冻结版本、预算和保守估算；`ConfirmRunInput`不接受完整执行计划或第二套选项。自定义选项与当前生成器上限一致；未来baseline/early_stop仍列为待实现，当前严格拒绝传入。运行时缺完整分析链时明确503，不返回虚假的完成检测。

已确认草稿的重复确认使用同一owner/org/hash Run收据，保留于Run而非即将过期的S2草稿行；被清理的未确认草稿为404，尚未清理但过期为409。金额未知不等于零费用；默认已知价格金额上限和所有管理员收紧均在报价/签名前生效。详细开发限制见DEV-RUNTIME-V1.md。
