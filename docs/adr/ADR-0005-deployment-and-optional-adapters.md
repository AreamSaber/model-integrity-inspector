# ADR-0005: Deployment modes and optional adapters

Status: Accepted  
Date: 2026-09-04

## Context

项目必须提供单机发布包和 Docker Compose，同时允许未来接入 KMS、对象存储、OIDC 和其他队列。可选集成不能侵入核心领域或成为默认安装前提。

## Decision

- 单机包包含 `mii` 可执行文件、嵌入式 Web、配置模板和迁移；运行时使用独立数据目录、SQLite、主密钥文件和本地报告目录。
- Docker Compose 使用同一镜像拆分 `APP_ROLE=server` 与 `APP_ROLE=worker`，并编排 PostgreSQL、报告卷、容器 Secret 和健康检查。
- Server/Worker 使用相同版本和数据库迁移兼容窗口；启动时验证 schema、规则/模板/tokenizer SHA-256 和配置。
- 默认实现：本地账号、数据库 Job、文件/容器 Secret 主密钥、本地/共享文件报告。
- 可选接口：Identity Provider、Key Wrapper、Job Queue、Report Store、Webhook。适配器必须显式启用并通过配置校验。
- 移除或未配置 OIDC、KMS、Redis/NATS、S3-compatible 适配器时，核心登录、目标、检测、分析和报告完整可用。
- Helm、包签名和非数据库队列列为 P1，不进入 V1.0 必需安装路径。

## Consequences

- 相同制品覆盖两种部署，版本和行为更容易复现。
- Compose 需要共享报告卷；报告元数据以数据库为准，文件失败不能覆盖发布分析。
- 可选适配器必须拥有隔离的健康状态和故障文案，不能改变核心领域语义。

## Alternatives rejected

- 单机和生产维护不同代码分支：容易产生安全和迁移漂移。
- 强制 S3/KMS/OIDC/Redis：违反默认独立交付边界。
- 将完整前端作为外部 CDN 依赖：破坏离线/私有部署和制品一致性。

## Failure, rollback, security and data

升级采用 expand → deploy → contract；回滚优先恢复上一应用制品并保留数据库与报告。配置输出、健康接口和 Compose 日志不得回显 Secret 路径内容、凭证或完整 Endpoint query。备份包含数据库、报告和 manifest，不包含明文主密钥。
