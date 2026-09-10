# M6-05：历史报告清单 v3 与原行摘要

2026-09-10。开发单元已实现；正式审核待完整开发后统一进行。
本单元不代表完整备份恢复、历史文件映射或恢复启用已经完成。

## 要解决的原要求

TECH SPEC 19.5、AC-23 和 M6-05 要求数据库、历史报告、配置和规则完整备份，
恢复后验证数据、报告及密钥。migration 14 为报告增加的发布字段允许 NULL，
没有给已有 ready 报告回填不可变 source、文件摘要或创建任务。
不能忽略这些历史记录，也不能用当前报告生成器重建并伪造历史来源。

## 兼容协议

- 新 `mii.backup-manifest.v3` 保留 v2 多租户工件身份，新增可选 `legacy_reports`。
  原 v1/v2 的 canonical 字节与固定 SHA-256 均保持不变；旧版本拒绝非空扩展。
- 每条历史记录保留组织／Run／报告／分析修订身份，`mii.legacy-report-row.v1`
  原行摘要，以及固定 `legacy_unverified` 状态。原始格式、schema、存储定位、
  声明摘要、正文和所有 NULL 字段留在数据库快照中，不在 manifest 暴露自由文本。
- 文件状态严格区分 observed、missing、unmapped；只有 observed 携带实际文件
  身份并进入归档条目。观察到的零字节文件使用空内容 SHA-256，与缺失文件不同。
  observed 只证明观察和传输一致，不授予报告来源可信性或下载／执行／恢复启用权限。
- 原行协议绑定方言和固定 20 列顺序、类型、NULL、长度与精确值；全部 TEXT 流式
  哈希，禁止 JSON、Unicode、换行或 hash 文本规范化。SQLite 时间保留原 TEXT
  字节，PostgreSQL 时间规定原生 timestamp binary 8 字节。详见
  `M6-LEGACY-REPORT-ROW-DIGEST-NOTES.md`；纯摘要组件不能证明数据库取值来源。
- metadata 总条数包括无文件历史行，最大 65,533；在 typed JSON 分配前检查。
  canonical manifest 最大 16 MiB，全部文件加 manifest 最大 1 TiB，身份全局唯一。
  v3 不增加 sealed audit segment 支持、不扩大 key/version 边界、不降低既有校验。

## 真实测试证据

1. 首次加入 v3 后，完整包三轮仅旧测试将 v3 当作 unknown version 的断言失败；
   改用 v999 保留未知版本拒绝测试，不放宽生产校验。后续独立 golden／16 MiB
   真实边界测试三轮 **3.213s PASS，94.1%**，manifest fuzz **102,639 次／11.141s PASS**。
2. 主任务复核原行协议并将真实 `DigestLegacyReportRow` 接入 AEAD／VerifyStream
   组合测试，保留独立 literal golden。完整包三轮
   `go test ./internal/integrity/backupmanifest -count=3 -cover -timeout=30s`
   首次 **3.605s PASS，94.7%**；原行单元停止编辑后主任务最终完整复验
   **3.405s PASS，94.7%**，终态退出 0，同一会话 vet 退出 0、lint 返回 0 issues。
3. v1 固定摘要 `0fbbd751a365f53c7cb9c3e3763fa176d5d2ed1e43f88189993e9a0d3bfc80b2`，
   v2 固定摘要 `3a58455cac5a12f3c36333279db2e5e200dfe726adbf99c3a1da6477a2ded1a6`，
   均未重写；v3 使用独立明确字段字节测试。
4. 覆盖原行 NULL→空值、相同壁钟的不同 UTC offset、相差一纳秒，均实际改变
   RowSHA256 及 manifest 身份，不能用旧外部摘要读取。
5. 对已合法加密的归档，实际 VerifyStream 拒绝修改／漏掉 observed 文件、给空文件
   填字节、额外条目、错 kind、重复条目及完整内容后截断／多余 EOF；不能只靠 AEAD
   有效判定文件清单完整。测试数据库 payload 为明确合成字节，不冒充实际数据库恢复。

## 后续仍须完成

同一实际只读事务的原行 SQL 适配器、现代／历史报告完整分类清单、受批准的旧路径
安全映射和真实文件复制、隔离恢复索引、逐项恢复校验、完整协调器与 CLI／HTTP／Web。
原始 NULL/正文/时间必须从数据库精确取得，禁止把本单元的 synthetic fixture 当成
真实历史来源证据。未知历史表示需保留并明确兼容限制，不通过删除或重签消除问题。
