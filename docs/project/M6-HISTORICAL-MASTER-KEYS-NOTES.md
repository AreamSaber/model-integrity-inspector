# 历史主密钥文件加载与启动接线

2026-09-08。备份恢复的必要子能力，依据ADR-0004、TECH19.5以及M6-BACKUP-IMPLEMENTATION-NOTES.md第6节第4条；不是自动轮换、备份或恢复完成，不改变正式审核状态。

## 实际实现

- `secret.LoadKeyFiles(active, []KeyFileReference)` 验证全部显式版本/路径后加载，原 `LoadKeyFile` 委托同一实现，继续兼容单文件入口。版本区分大小写、不可重复、必须包含active；总文件1～64是启动资源上限，不是可删历史密钥的许可。
- 每个版本沿用原生逐路径no-follow、受限ACL/mode、普通单链接文件、精确32原始字节校验，读取前后验证同一句柄。文件关闭失败也失败关闭；不接受inline/base64、不扫描目录、不创建或重写任何钥匙。
- 任一失败不返回部分ring，包括有效active先读成功但随后历史文件损坏。33字节读取scratch、独立32字节raw结果、累计masters在失败/完成时clear。派生KeyRing不保留raw master；不宣称清零标准库展开密钥、栈/OS/调用方副本。
- `KeyFileReference` 的fmt/JSON/YAML/slog均拒绝或固定脱敏；完整Config也保持禁止序列化，不输出路径/DSN/令牌。
- YAML新增可选 `integrity.security.previous_master_keys: [{version, file}]`。路径相对配置文件，未知字段/空路径/非法或重复版本拒绝；当前key的原环境覆盖仍有效，但与历史版本碰撞不能静默覆盖。旧配置不要求新增该字段。
- app在创建数据/报告路径前调用多文件加载器；一个ring继续贯穿审计、Secret、Manifest、响应证据及Worker能力。新写入只使用当前版本，读取旧数据使用显式历史版本。不修改旧密文/AAD/审计事件，不暴露新明文HTTP入口。

## 实际验证

1. 首次新增loader测试在API尚不存在时编译失败；仅为缺能力编译检查，不称为生产缺陷红绿复现。实现后新loader专项单轮0.111s通过。
2. 固定Go下纯KeyRingFile/KeyFile三轮0.435s、配置边界/历史路径/原配置回归三轮0.268s通过。包括63个previous加active合法、64个previous超限；旧/新版本AuditMAC与旧credentials精确AAD解密；新credentials使用active；active先成功、历史随后坏文件；缺失文件无partial ring；完整Config/单引用嵌套JSON/YAML/fmt/slog无canary；合法环境覆盖保留历史列表、碰撞/未知字段/inline key拒绝。
3. root `go test ./internal/app -run '^TestApplicationHistoricalKeysPreserveAuditAcrossRotation$' -count=3 -timeout=2m` 在显式配置真实PG DSN时三轮PASS4.584s。每轮SQLite/PostgreSQL各实际初始化生成旧审计→关闭应用→生成独立新私有key→只有新key启动拒绝→加回历史文件启动成功→真实HTTP登录追加新签名事件→全链验证通过→查询实际链头为v2。只处理新分配临时目录/PG schema，不修改现有用户数据库。该结果不包含后续并行维护门禁单元的验证。
4. 独立agent只读复核未确认新的P1/P2；Windows纯loader/native测试三轮0.485s、纯配置三轮0.197s。普通symlink因OS权限被原测试明确skip，hardlink和强制junction/ACL/命名空间用例实际运行，不冒称普通symlink或Linux原生通过。
5. root最终纯crypto/既有用途/golden/keyfile组合三轮1.174s通过，contracts/secret/app组合lint0。

## 未完成的边界

加载所有**配置中**的版本不证明已提供数据库/所有历史归档**实际引用**的全部版本；完整恢复仍必须从可信快照inventory核对并验证Secret、响应/派生证据、报告、schema和完整审计。当前测试分别证明历史审计真实启动和纯层历史Secret解密，不是实际TLS Worker在轮换后消费旧Secret的端到端证据。没有自动rewrap调度、历史key删除许可、CLI恢复激活或生产轮换操作。

主密钥及含私有路径的完整运行配置不得装进归档；安全配置模板另由恢复协调器闭集生成。后续privatefile/crypto/维护门禁/快照/恢复仍分别开发验证，整个SYS-008/M6-05保持进行中。
