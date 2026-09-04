# M0-02 Review Record

计划编号：M0-02  
负责人：TL  
依赖：M0-01（已通过）  
当前状态：已通过  
批准记录：项目方于 2026-09-04 明确批准 M0-02 架构与 ADR 包

## 开发目标

完成独立系统架构和关键 ADR，明确模块、信任与故障边界，以及单机 SQLite、生产 PostgreSQL、数据库 Job、信封加密和两种部署路径。

## 实际交付物

- `docs/architecture/SYSTEM-ARCHITECTURE-V1.0.md`
- `docs/adr/ADR-0001-runtime-and-module-boundaries.md`
- `docs/adr/ADR-0002-dual-database-and-migrations.md`
- `docs/adr/ADR-0003-database-job-queue.md`
- `docs/adr/ADR-0004-secret-envelope-encryption.md`
- `docs/adr/ADR-0005-deployment-and-optional-adapters.md`
- `docs/adr/ADR-0006-audit-log-integrity.md`
- `scripts/verify-m0-02.ps1`

## 测试证据

执行命令：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-m0-02.ps1
```

预期并实际验证：架构图、信任/模块/角色/故障/审计完整性边界存在；6 份 ADR 均包含决策、后果、替代方案和回滚/安全数据影响；Secret 调用与唯一存储边界、SQLite/PostgreSQL 路径及可选依赖边界明确；任务状态未越过审核。

实际输出：

```text
M0-02 verification passed.
Architecture: context=present, trust-boundaries=present, module-boundaries=present, role-map=present, failure-boundaries=present, audit-integrity=present
ADRs: total=6, status=accepted
Database paths: SQLite=standalone, PostgreSQL=standard-production
Optional dependencies: Redis/S3/OIDC/KMS=not-required-for-core
Task status: M0-01=passed, M0-02=passed, total tasks=91
```

交付物 SHA-256：

```text
8838bc23193917317e2269fc69831b80aebf08560139215496efd32a42784fe0  SYSTEM-ARCHITECTURE-V1.0.md
23db4707256183d54a594786fc2c8cfe80cc52911a2fa2f26cc68afce9160348  ADR-0001-runtime-and-module-boundaries.md
617fca1620f812fdcf809b85a6f13675970e3dcbfd594e14f7a8e61457646efc  ADR-0002-dual-database-and-migrations.md
8b700a7b83531d9ed7156bd272a2f10878b3791f413df5542416090993de6485  ADR-0003-database-job-queue.md
74189d58298bf7ccf69cd68828951135cd7f821e29c24d38e0b44954034594dd  ADR-0004-secret-envelope-encryption.md
d395ea0b3eb162c87489cadd4009cd9d846e617e1257f4b69082e5f3999998d0  ADR-0005-deployment-and-optional-adapters.md
c73fe82789451af2a753ac5a309d61aa5745c91d413c27424d6723d37f456879  ADR-0006-audit-log-integrity.md
33c4d6dcecf1f3fd4b434e6414e72f58be447864d43a23b356d4bf76a1cda0f9  verify-m0-02.ps1（兼容根目录 README）
c85f64b9851afa6cf4e8223622b81eb4623f0c6fdcc025d2e238d5692cae5e27  TECH-SPEC-V1.0.md（M0-03 单制品目录澄清）
```

## 重新审核问题关闭记录

| 原级别 | 问题 | 修复结果 |
|---|---|---|
| P1 | 运行图中 Safe HTTP 直接调用 Secret 且直接写 Sample | 已改为 Worker 按 `secret_id` 获取短生命周期凭证，Safe HTTP 只负责安全传输，响应经 Adapter/parser 后由 Worker 写 Sample。 |
| P1 | PRD 要求不可篡改审计，但架构只有普通审计表 | 已新增 ADR-0006，采用应用权限只追加、按组织 HMAC-SHA-256 链、密封分段和恢复验证，并明确超级管理员威胁模型边界。 |
| P2 | Target 与 Secret 重复持有自定义 Header 密文 | 已删除 Target 的 `custom_headers_encrypted` 字段；API Key 与全部自定义 Header 统一进入版本化 Secret 载荷。 |
| P2 | `APP_ROLE` 未映射具体组件 | 已补充 `server`、`worker`、`all` 组件矩阵、迁移责任、SQLite 单领取器约束及 Analyzer/Report Job 归属。 |
| P2 | DEK 包裹格式不明确 | 已冻结默认 HKDF-SHA-256 用途分离和 AES-256-GCM DEK wrapping envelope，明确独立 nonce、tag、版本及 KMS 元数据。 |
| 次要 | 审核命令使用历史绝对路径；S3 分类易与对象存储混淆 | 已改为仓库相对命令，并将数据分类写为“S3（极敏感级）”。 |

## 安全与数据影响

- 本任务仅冻结架构设计，不创建数据库、不处理凭证、不调用外部 Endpoint。
- Secret ADR 固定 AES-256-GCM 信封加密、密钥用途分离、AAD、只写不可回显和主密钥外置边界。
- API Key 与全部自定义 Header 只有一个版本化 Secret 事实源；Safe HTTP 无主动取密权限。
- 审计事件采用应用只追加、按组织 HMAC 链和密封分段，数据库离线篡改可检测。
- Safe HTTP、组织 scope、合成数据、日志脱敏和黑盒证据上限被纳入模块边界。
- 未引入 Redis、S3、OIDC、KMS 或其他业务系统强依赖。

## 性能影响

当前无运行时影响。设计明确 SQLite 单活跃写领取器与 PostgreSQL 多 Worker 路径；精确单机容量必须由 M7 实测冻结。

## 审核通过标准完成情况

| 标准 | 状态 | 证据 |
|---|---|---|
| 独立系统架构图和模块边界 | 已完成 | System context、runtime/trust boundary、module table。 |
| SQLite 与 PostgreSQL 路径明确 | 已完成 | 架构第 6 节、ADR-0002。 |
| 数据库 Job 与租约语义明确 | 已完成 | ADR-0003，含两种数据库领取、租约、幂等和 uncertain attempt。 |
| 密钥边界明确 | 已完成 | ADR-0004，含信封加密、轮换、错误和备份边界。 |
| Secret 调用与存储边界唯一 | 已完成 | Worker 是唯一按引用取密模块；Target 不另存 Header 密文；Safe HTTP 只传输。 |
| 部署路径与可选依赖明确 | 已完成 | ADR-0005，默认无 Redis/S3/OIDC/KMS 依赖。 |
| 运行角色映射明确 | 已完成 | 架构第 7 节及 ADR-0001 明确 Server/Worker/All 的组件和迁移/Job 责任。 |
| 审计完整性边界明确 | 已完成 | 架构第 9 节及 ADR-0006 明确只追加、HMAC 链、分段清理和威胁模型。 |
| 故障边界可解释 | 已完成 | 架构第 8 节覆盖上游、Worker、DB、密钥、报告和可选适配器。 |
| TL、OPS/SEC 审核 | 已完成 | 项目方于 2026-09-04 明确批准；架构与 6 份 ADR 均更新为 Accepted。 |

## 已知限制与回滚

- 具体 Go/Node 版本和依赖锁定属于 M0-03，不在本任务中提前假定。
- SQLite 精确支持容量将在性能测试后写入运维限制。
- 本轮只有文档变更；若审核要求调整，修订架构/ADR 即可，无数据迁移或运行时回滚。

## 审核结论

审核结论：已通过。重新审核提出的两项 P1、三项 P2 和两项次要问题已全部关闭，交付物、批准记录和验证证据齐全；可以进入 M0-03。M0 Gate 仍需等待 M0-03～M0-08 全部通过。
