# API v1 开发契约（M0-06）

版本：1.0.0-draft；2026-09-07。文件：openapi-v1.json（OpenAPI 3.1）。正式 TL/FE/QA 批准待统一审核；契约存在不表示接口已实现。页面对应 INTERACTIONS-V1.0.md，实际进度以持续开发台账和需求矩阵为准。

## 约定

- 前缀 /api/v1；所有业务 ID 使用十进制字符串（数据库仍为 int64，避免 JS 精度丢失）。UTC RFC3339 时间；金额为整数微单位，单价未知/风险维度缺失使用 null，不使用 0 冒充已知。
- JSON 成功 envelope 为 data + request_id；错误为 error{code,message,details} + request_id。详情只可包含 field/retry_after_seconds/reason 分类，不回显凭证、完整 Endpoint query 或上游原始正文。
- 会话使用 HttpOnly/Secure/SameSite=Strict Cookie。仅显式 loopback 开发模式可使用非 Secure；浏览器不保存密码/Key/session 到 localStorage。认证写请求校验 X-CSRF-Token 与同源 Origin；匿名登录/初始化同样检查 Origin。跨站请求不提供宽泛 CORS。
- 业务组织通过 X-Organization-ID 明确选择，后端必须核验成员权限；系统管理员跨组织操作须单独授权并审计理由。成员接口路径组织与权限绑定；不存在/跨租户对象统一 404，不回显它的元数据。
- 列表使用 limit（默认 25、最大 100）和 opaque cursor；默认 created_at/id 稳定倒序；下一页游标绑定组织/过滤条件，非法或换组织游标返回 400。列表不含正文、Secret 密文或大 JSON。
- 乐观锁更新携带 version；冲突 409，客户端重新拉取。写请求有最大体积限制，未知字段拒绝（additionalProperties=false）；模板参数、Header 和 Endpoint 仍须领域层校验。
- Run 创建/预检/报告/回放/备份返回 202，后台由数据库 Job 执行。预检已增加 GET 读取结果；不在 Handler 同步等待上游。
- SSE 使用带同源 Cookie 和组织 Header 的 fetch 流；Last-Event-ID 仅携带事件游标。重连可先收到当前快照，客户端按版本丢弃旧事件，再 GET 最终状态/冻结结果；不依赖浏览器 EventSource 传自定义 Header。事件不含正文和凭证。
- 下载使用已授权数据库记录解析的路径，不接受用户文件路径；返回 attachment、nosniff、HTML sandbox CSP。下载/正文读取需审计。报告不包括 S3 凭证，默认导出脱敏证据；canonical hash 对去除 content_hash 的 JSON 计算，需版本化规范。
- 自定义 Header 整体 writeOnly，与 API Key 同一加密 Secret；目标读接口只返回掩码/版本。保留 Header、CRLF 和不安全地址拒绝，Key 更换使用独立权限。
- report、risk、confidence 与人工 review 分离；只读接口绝不从 Secret 重新构造内容；黑盒最高 B，无有效样本必须 insufficient。

## 权限实现要求

每个操作 x-permission 标记领域权限，不等同于现有实现。read 指当前组织可读；run.cancel-own-or-any 按 PRD（管理员/审计员可停止，运营/开发仅本人）；高成本、自定义包、正文访问、secret.replace、report.export 必须再按角色/显式授权检查。系统角色与组织 admin 不可混淆。任何角色都无 Key 回显权限。

## 验证和冻结

运行 .tools/go/bin/go test ./tests/contracts 检查 77 项追踪完整性、路径/参数/引用/敏感字段和原型覆盖。这是仓库语义回归，不替代完整 OpenAPI 规范校验、真实 API 契约测试或 E2E。实现每组 API 后，应补上实际请求/权限/失败路径测试，将 x-development-status 和台账据实更新；未实现接口不得返回样例成功数据。

正式 schema/接口变更与客户端同时提交；不默默缩减原计划。P1 reanalyze、Webhook、OIDC、PDF/CSV 不作为当前 API 已完成项。

