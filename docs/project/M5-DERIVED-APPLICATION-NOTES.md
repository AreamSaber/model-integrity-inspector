# M5 派生证据应用接线

日期：2026-09-08。开发集成证据，待统一正式审核；不表示完整 V1.0 或正文生命周期已完成。

## 实际生产入口

`internal/app/app.go` 在可信启动时用已加载 KeyRing 的独立 derived-source MAC 用途创建 sealer/verifier。新 run.Service 生成并签入 `mii.derived-s1.v1`，HTTP 不能选择模式。实际 Run Worker 使用 builder/sealer，分析器使用 verifier，原 Runner 的维护回调接入两阶段恢复，并保留分析、报告和草稿清理路径。

已确认旧 Manifest 不重签、不升级。分析器保留旧模式所需的 EvidenceKeys；新模式不读取正文，也不因 S1 缺失而回退到正文。用途限定能力不能代替全链路的凭证隔离或完整轮换交付验收。

## 完整应用测试

`TestApplicationActualTLSFromInitializationThroughPublishedEvidence` 和新增 `TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts` 共用实际应用流程，分别验证30天和0天。不是直接替换底层策略字段：初始化并登录后，通过真实管理 HTTP PATCH 设置组织期限并检查版本回执。

0天测试在新建的独占数据库/PG schema 中安装真实数据库拒绝约束：任何 raw/display INSERT 都失败。约束持续覆盖预检、首次完整检测和再次检测，不用先插入再删除模拟未保存。

两条路径均执行：初始化、登录、组织策略设置、目标配置、受控 TLS 预检、估算确认、实际 Runner/分析发布、授权结果/样本/Attempt/发现读取、追加复核、实际基线/JSON和HTML制品流程、确认幂等、重复检测与原结果不变、审计完整验证和正常应用关闭。

额外直接读取真实数据库验证：两个 Run 都使用新模式；18+9次实际 Attempt 全部完成且各有一条认证 S1/派生回执；30天存在对应两类正文，0天两类正文均为零且所有 body receipt 为 not_retained。S1 的密码学/源绑定由真正的派生分析发布路径验证，不把行数当作认证证明。实际 HTTP helper 持续拒绝 API key、ciphertext、nonce、request plan 等受保护内容出现在响应。

## 验证结果与限制

固定 Go 1.26.7；从既有忽略目录静默加载真实 PostgreSQL 测试 DSN。

- 首次接线后的原完整应用测试双库1轮通过：12.745s。
- 两条完整应用测试 SQLite/PostgreSQL 各3轮通过：79.678s；无 PostgreSQL skip。
- 本轮 features/app lint：0 issues。
- 生产维护的实际 failed/cancelled Job 无凭证恢复专项此前双库3轮通过：4.691s。

测试耗时不是性能容量指标；应用测试使用受控本地 TLS 上游，不是真实付费调用，也不代替浏览器交互验收。旧已确认 legacy 的0天写入策略、授权正文 HTTP/UI、实际清理及完整备份恢复仍须实现。此时最新全绿 CI 为 b6d03ec / 34182141504，不包含本接线，必须对提交后的整体版本重新验证。
