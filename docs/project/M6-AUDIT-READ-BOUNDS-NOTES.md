# 审计读取的数据库侧字节边界

2026-09-08。范围：旧审计 append 读链头、tail/full 验证、审计列表及初始组织锚点；不改变审计 canonicalization、已有 HMAC 字节、签名密钥、锁序、分页条数或历史迁移。它是完整备份/恢复校验的前置安全修正，不是同一快照 inventory 或恢复完成。

## 实际反例

- `TestAuditReadsBoundFieldsBeforeMaterialization` 在真实 SQLite/PostgreSQL 中修改测试拥有的签名事件，使用 ORM 查询后观察器量取实际载入字符串字节数，不是替换查询结果。旧 tail/full/list 会先载入 1 MiB TEXT，再由部分读侧拒绝；旧 ListAudit 还会直接返回损坏记录。UTF-8 64 字符/192 字节同样超过原 128 字节限制。
- 链头 event_hash/key_version 在 verifier 与 append 两条路径都会先载入 1 MiB，实际反例确认。
- 初始组织锚点 2 MiB value_json 的实际 SELECT+解析累计 Go 分配为 SQLite 4,207,696 字节、PostgreSQL 8,445,816 字节，之后才解析失败；写入夹具和大输入分配排除在观察区间外。
- 初轮包2.615s实际失败；其中 PG 的 object_type/object_id 两列参与 btree，1 MiB夹具先被索引元组上限拒绝，不能算这些列的生产红测。仅将这两列夹具改为129字节（原限制128），对应全部读路径后续实际红测0.561s确认。其余九列保持1 MiB。

## 修正

- 新 `auditEventReadColumns` / `auditHeadReadColumns` 使用固定列名及数据库侧**编码字节**长度。事件超限时投影为非法换行哨兵，绝不截断或替换成可能重新匹配旧 MAC 的合法空串；链头必填的 hash/key version 超限则投影为空并由原必填校验拒绝。源表不修改。
- 原 tail/full 的签名验证、链头共享/独占锁、500条分页及最终链锚点比较不变；每个事件和链头均在 database/sql 构造字符串前有界。
- `initialAuditOrganization` 仅读取最多20字节的原 int64 十进制表示，再保留正整数解析；异常返回原固定错误，不输出数据库内容。
- ListAudit 继续按组织、sequence和原100条上限读取，但现在对每条返回事件验证原 HMAC；失败返回空结果及固定错误，不能返回部分页。逐事件认证**不证明**该分页完整、无删除或等于全链校验。
- 不声称其它所有 system_settings、审计成员枚举或所有数据库读取都已限额；未改当前独立维护/状态投影，也未引入可供业务任意 SQL 调用的能力。

## 当前验证

- 修后新事件/链头/初始锚点专项，真实双库三轮6.629s PASS。
- 扩大旧审计、并发追加、篡改/删除/缺链头、身份失败回滚、匿名登录、会话及维护审计读取，双库三轮38.479s PASS。
- 当前组合下，另一个时钟单元的真实TLS捕获双库三轮5.617s、完整Worker双库单轮168.803s通过。该证据包含两单元的当前工作树，不冒充独立某个旧提交的结果。
- 精确128/1024字节正向、UTF-8精确字节、合法空摘要MAC重放反例及 operational/worker audit 扩大，真实双库三轮12.750s PASS；API Audit/Initialize 单轮0.737s PASS（未显式选择PG，不声称该API命令覆盖双库）。
- 完整仓储双库单轮 `go test ./internal/integrity/repository -count=1 -timeout=15m` 已实际终态 **548.761s PASS**，包含自然lease expiry，不排除测试。最终完整Worker双库单轮 **176.908s PASS**，此前CI相关三父项双库三轮 **70.435s PASS**。
- 完整API与app当前组合已终态：默认API SQLite **51.110s**、显式PG API **96.826s**，app两个命令 **59.061s/58.968s** 均PASS（app自身eachDatabase涵盖双库，不将重复运行误计新增平台）。仓储及组合lint0。上述均包含本地snapshot/audit，不代表已推送提交或其CI。

Git/CI身份和后续证据以持续开发台账为准。当前不作全产品通过或正式审核批准声明。
