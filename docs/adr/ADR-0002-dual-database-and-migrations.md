# ADR-0002: SQLite and PostgreSQL database path

Status: Accepted  
Date: 2026-09-04

## Context

单机模式必须零外部数据库依赖，标准生产必须支持并发 Worker、可靠租约和百万级样本查询。SQLite 与 PostgreSQL 的锁、JSON、ID 和时间语义不同，不能用未经验证的隐式兼容处理。

## Decision

- SQLite 用于单机和小规模正式部署；标准生产必须使用 PostgreSQL。
- 使用 GORM 管理领域持久化映射和迁移步骤，复杂领取/索引使用受控的方言 SQL。
- `schema_migrations` 是迁移事实源；迁移有全局锁、校验和状态记录。
- 采用 expand → deploy → contract；破坏性 contract 至少延迟一个版本。
- Repository 接口强制显式 `organization_id`，禁止无 scope 的业务查询方法。
- JSON 大字段不进入默认列表，Job/分页/历史查询建立显式索引。
- SQLite 只允许一个活跃 Job 写领取器，所有写事务保持短小；PostgreSQL 使用连接池和行级锁。
- 精确 SQLite 容量/并发上限由 M7 实测冻结，在此之前不作未经验证承诺。

## Consequences

- 必须为两种数据库运行迁移、Repository、锁和恢复测试。
- 方言 SQL 只能存在于数据库适配层，并提供等价行为测试。
- 数据库迁移失败不得留下半完成 schema；无法事务化的 DDL 必须使用前置检查和恢复步骤。

## Alternatives rejected

- 仅支持 PostgreSQL：不满足单机零依赖交付。
- 仅支持 SQLite：无法可靠满足标准生产水平扩展。
- 自动 destructive down migration：可能造成不可逆数据丢失，不符合回滚边界。

## Failure, rollback, security and data

升级前备份数据库和报告 manifest。expand 阶段应用回滚不回滚数据库；确需数据恢复时使用备份并明确 RPO。组织 scope 在 Repository 和 Job 消费端双重校验，迁移脚本不得导出正文或 Secret。
