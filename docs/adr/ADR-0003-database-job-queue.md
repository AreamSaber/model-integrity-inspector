# ADR-0003: Database Job queue with leases

Status: Accepted  
Date: 2026-09-04

## Context

系统需要持久化长任务、崩溃恢复、取消、预算和至少一次执行，同时默认不能依赖 Redis、NATS 或云队列。

## Decision

- `integrity_jobs` 是核心队列，Job 只保存组织 ID、业务对象 ID 和非敏感选项。
- 创建业务对象和首个 Job 必须位于同一数据库事务。
- PostgreSQL 使用 `SELECT ... FOR UPDATE SKIP LOCKED` 领取；SQLite 使用短事务条件更新和单活跃领取器。
- 默认租约 60 秒，每 15 秒续租；过期 Job 可回收。
- 处理器采用至少一次语义，通过业务幂等键避免重复副作用。
- 已发出但结果未知的上游调用标记 `UNCERTAIN_ATTEMPT`，计入预算但不重复作为有效样本。
- 取消先持久化标记，Worker 在派发前和边界点检查；已发请求不被伪装成未发生。
- P1 外部通知使用事务 outbox；核心检测不依赖 outbox dispatcher 或外部消息系统。

## Consequences

- 管理数据和队列共享数据库，需要连接池、短事务、公平轮询和积压告警保护控制面。
- 租约恢复可能重复进入处理器，因此每一步都要有幂等边界。
- 可选队列适配器未来必须保持相同 Job 状态、租约、幂等和取消语义。

## Alternatives rejected

- Redis 为默认队列：违反独立部署边界。
- 内存队列：进程退出后丢任务，无法恢复和审计。
- exactly-once 声明：外部 HTTP 调用无法获得真实 exactly-once 保证。

## Failure, rollback, security and data

数据库不可用时停止领取，不在内存伪造完成。Worker 崩溃由租约回收；reconciler 处理永久无进展任务。Job 载荷禁止包含 Key、鉴权 Header、正文或可还原 Secret 的信息，并在消费时复核组织作用域。
