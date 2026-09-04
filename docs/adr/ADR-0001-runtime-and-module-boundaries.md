# ADR-0001: Modular monolith and runtime roles

Status: Accepted  
Date: 2026-09-04

## Context

V1.0 必须独立部署，同时提供 Web、API、Worker、分析和报告能力。单机用户需要最低安装复杂度，生产用户需要拆分 Server/Worker 和水平扩展，但不能维护两套实现或依赖其他业务项目。

## Decision

- 使用 Go 模块化单体，一个版本化 `mii` 可执行文件和容器镜像。
- `APP_ROLE=server | worker | all` 决定启动组件；默认单机为 `all`。
- `server` 启动 Web、Control API、身份/RBAC、管理查询、健康/指标并负责竞争迁移锁，不领取异步 Job。
- `worker` 启动 Job consumer、Scheduler、Probe、Secret 出站作用域、Adapter、Safe HTTP、Sample、Analyzer、Report Job 和 reconciler；只校验 schema 兼容性，不执行主动迁移，也不提供管理端业务写 API。
- `all` 启动两者并集；SQLite 只允许一个 `all` 进程和一个活跃 Job 领取器。
- React + TypeScript 产物通过 Go `embed` 嵌入 Server。
- 领域模块只通过接口访问 Repository、时钟、随机源、网络、主密钥和报告存储适配器。
- HTTP Handler 不包含规则或 SQL；Adapter 不包含风险判定；Analyzer 不进行网络或 Secret 访问；Safe HTTP 不解析 `secret_id` 或调用 Secret Service。
- 后台工作全部通过数据库 Job 编排，不从 Handler 同步执行长检测。

## Consequences

- 单机制品和生产制品一致，减少部署漂移。
- 模块错误可通过角色进程和租约边界隔离，但仍需禁止包级反向依赖。
- Worker 扩展不要求复制 API/静态前端负载。
- V1.0 不采用微服务网络调用；未来拆分必须保持 Job、幂等和领域接口语义。

## Alternatives rejected

- 从首版拆分微服务：增加部署、鉴权、追踪和一致性成本。
- Server 同步执行检测：会让上游故障和长响应拖垮管理面。
- 前端独立强制部署：破坏单机一体化和单制品目标。

## Failure, rollback, security and data

角色配置错误必须导致启动前校验失败。异步 Job 只能由 `worker`/`all` 领取，Analyzer 与 Report Generator 通过独立幂等 Job 运行。回滚使用上一 `mii` 制品，不逆向删除数据库对象。模块不得共享包含 Secret 明文的通用 DTO；日志和 Trace 在基础设施边界统一脱敏。
