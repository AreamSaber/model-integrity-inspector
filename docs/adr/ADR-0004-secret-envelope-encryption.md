# ADR-0004: Secret envelope encryption

Status: Accepted  
Date: 2026-09-04

## Context

API Key 和自定义鉴权 Header 属于 S3 极敏感数据，必须持久保存供 Worker 调用，但任何角色都不能取回明文，且数据库、日志、Trace、报告、备份和普通错误不得包含明文。

## Decision

- 每个 Secret 生成随机 256-bit DEK，使用 AES-256-GCM 和独立随机 96-bit nonce 加密由 API Key 与全部自定义 Header 组成的版本化凭证载荷。
- 默认文件/容器 Secret 模式使用 HKDF-SHA-256 从版本化主密钥派生用途隔离的 DEK wrapping key、fingerprint HMAC key 和 audit-integrity HMAC key；不同用途使用固定且互异的 `info`。
- 默认 DEK wrapping 使用 AES-256-GCM 和独立随机 96-bit nonce。`encrypted_data_key` 是版本化 envelope，包含算法标识、wrap nonce、wrapped DEK 与认证 tag；KMS adapter 返回的 opaque ciphertext 也必须携带 provider、key id/version 和算法元数据。
- 业务数据库保存 wrapped DEK envelope、凭证密文、payload nonce、key version、HMAC fingerprint 和 `last_four`；Target 只保存 `secret_id`，不得另存自定义 Header 密文。
- AAD 至少包含 `organization_id`、`secret_id`、`secret_version` 和 `key_version`。
- 主密钥默认从权限受限文件或容器 Secret 加载；KMS 仅为可选 wrapping adapter。
- Worker 是唯一可按 `secret_id` 调用 Secret Service 的业务模块；Safe HTTP 不解析 Secret 引用或主动取密。明文只在出站请求作用域及底层发送所必需的内存中短暂存在，使用后清除可控缓冲并取消引用；不进入 `error`, `fmt`, JSON DTO 或 telemetry。
- Secret API 仅支持创建和替换；响应只返回掩码、版本和审计元数据。
- 主密钥轮换优先重新包裹 DEK，不解密重写业务明文；失败可按记录重试。

## Consequences

- 主密钥丢失会导致 Secret 永久不可解密，因此备份和主密钥必须分开保管并演练匹配校验。
- KMS 适配器不得在故障时静默回退到文件主密钥；若启用 KMS，还必须提供独立的 fingerprint/audit-integrity HMAC key provider 或明确配置的外置用途隔离密钥。
- `last_four` 只用于掩码，HMAC fingerprint 只用于同环境复用识别，均不得作为鉴权值。
- 单元、集成和 canary 扫描必须覆盖成功、错误、轮换、日志和备份路径。

## Alternatives rejected

- 数据库透明加密：不能阻止应用日志、查询和导出泄漏。
- 单一主密钥直接加密全部 Secret：轮换成本和密钥使用范围过大。
- 可逆 Key 查看接口：违反只写不可回显要求。

## Failure, rollback, security and data

主密钥缺失、权限过宽、长度或版本不合法时 Secret Service 不就绪并阻止外部调用，但错误只暴露分类码。删除目标后按保留策略物理删除密文和 DEK 引用；历史报告不得依赖 Secret。轮换操作和失败均进入不含明文的审计日志。
