# M6 备份清单 v2：多租户保留工件身份

## 范围与真实数据依据

本单元完整阅读 backupmanifest 全包，以及 PRD §9.0 / §15.1 / §15.3 /
§19 的多组织、备份恢复及冻结版本要求，TECH-SPEC §8.1、§13.4–13.6、
§19.2–19.6 的不可变模板、租户隔离、完整审计和备份要求。

`migrations/common/000001_foundation.up.sql` 的规则包、模板包表分别具有
正数 `id` 全表主键和 `UNIQUE (organization_id, version)`。因此不同组织
可合法保留相同版本、不同内容/哈希。v1 的全局 `(category, version)` 键
无法表达该状态；把版本拼成“组织/版本”、替换哈希，或拒绝这种合法库存
均不能满足完整、多组织备份范围。

本次只扩展清单格式和测试，不访问数据库，不修改仓储/库存采集、PG 工具、
应用协调器、恢复流程或 Git。格式接收的组织来自清单现有 audit anchors / jobs
完整对应集合；只有上层对真实数据库快照的核对，才能证明其确实是全组织集合。

## 显式版本与兼容性

- `Version` 保持 `mii.backup-manifest.v1`；新增显式 `VersionV2`，值为
  `mii.backup-manifest.v2`。不存在默认/静默升级或 `latest` 别名。
- `Encode` 依据调用方明确设置的 `SchemaVersion` 校验和编码；`Decode`
  只接受声明为 v1/v2 的规范文档，仍必须有外部独立的期望 BackupID 和 SHA-256。
- Artifact 新增 `Scope`、`OrganizationID`、`ID`，对应 JSON `scope`、
  `organization_id`、`id`，均 `omitempty`。旧 v1 必须为各字段零值，原
  category/version/file 字段及次序不变。v1 wire 中出现这些新字段，即使
  是 `null`、空字符串或显式 0，也因严格规范比较而拒绝。
- 独立完整 v1 JSON literal 与历史固定哈希
  `0fbbd751a365f53c7cb9c3e3763fa176d5d2ed1e43f88189993e9a0d3bfc80b2`
  保持不变。仅将旧 fixture 的 Artifact Go 字面量改为命名字段以适应新增字段，
  没有修改其数据、期望结果或旧 decoder 约束。
  完整 literal 是本轮按修改前的 fixture/字段次序手工构造的 independent
  legacy-protocol literal，不是仓库原有历史 golden 文件，也没有宣称运行了
  旧二进制。另以只读 `git show HEAD` 完整核对旧 manifest.go/manifest_test.go，
  确认旧协议及固定哈希来源；没有从新 Encode 输出反向生成期望 literal。

## v2 身份协议

| 工件类别 | scope | organization_id | id | 版本唯一键 |
| --- | --- | --- | --- | --- |
| rule / template | `organization` | 必须为清单已有正数组织 | 必须为原表正数行 ID | category + organization_id + 原 version |
| tokenizer / scoring | `installed` | Go 值必须为 0；wire 必须省略 | Go 值必须为 0；wire 必须省略 | category + 原 version |

导出常量为 `ArtifactScopeOrganization`、`ArtifactScopeInstalled`。不接受
缺失或未知 scope、跨类别 scope、孤儿组织、同组织版本冲突，以及同 category
下任何原行 ID 重用——包括跨组织、跨版本重用。rule 和 template 是不同表，
二者合法相同数字 ID 不冲突；installed 工件不虚构数据库行 ID。

组织工件的 scope/org/id 三项均须存在，不能是 null、0、负数、字符串化数字
或小数。installed 的 org/id 则必须省略：显式 0/null 也不是规范 wire。
原有重复 JSON key、大小写别名、字段遗漏、额外字段、重排、转义及尾随数据
拒绝机制不变。

工件规范排序为 category → organization_id → 原 version → 原 id。版本字符串
和文件哈希原样保留，不以租户前缀改写，不把相同版本不同字节归并。entry_id
仍必须是整个归档内唯一的受限标识符，不是路径；四种工件仍使用既有 archive
kind `rule`，category 和租户身份由已锚定的清单明确绑定。

保留原来的四类**全局**库存要求，但不要求每个组织都有四类，也不为没有保留
包的组织补造条目。清单应列出所有已保留项，不只当前版本；本格式本身不证明
上层已扫描全部表、完整版本集合或安装制品目录。

## 安全与资源边界未放宽

v2 仍只支持 `audit_history=complete`；没有由此次版本升级引入 sealed segments。
组织 audit/job 对应、已排空的 Running/DispatchedAttempts、未决/不确定历史、
迁移连续性、数据库快照方法、报告来源/内容/文件哈希、外置密钥版本及安全
文件标识符等原校验继续执行。

保留 16 MiB 清单、65,536 个总归档项、16,384 个组织、4,096 个迁移、64 个
密钥版本、128 字符原工件版本，以及包含清单自身字节的 1 TiB 总明文预算。
既有 preflight 在 typed slices 分配前数项；v2 不绕过该路径。超限拒绝，
不截断/截页伪装完整库存。新增身份索引只处理已通过数量上限的工件。

`Encode` 的 lists 仍为 owned copies，排序不改调用方切片；并发只读同一输入
可生成确定结果，禁止调用方在编码期间并发写输入。返回的解码对象、输出字节
及 Entries 不共享可变列表。VerifyStream 仍拥有独立文件计划，验证精确一次
完整集合、真实 EOF、字节长度和哈希，错误保持 sticky 且借用能力最终失效。

任何组织、行 ID、原版本或 File 绑定变化都会改变完整清单 SHA-256，不能通过
原独立锚点的 Decode。若调用方把篡改清单自身计算的哈希重新当成“期望值”，
则不构成来源认证；该旧限制没有被版本或结构校验消除。

## 实测证据

仓库固定 Go 1.26.7，Windows 原生，无数据库/付费上游访问：

- 真实红→绿：仅新增可表示字段后，跨组织同版本不同字节测试单轮 0.101 秒
  FAIL（旧验证器 `MI_BACKUP_MANIFEST_INVALID`）；实现 v2 身份约束后通过。
- 最终完整包 `go test ./internal/integrity/backupmanifest -count=3 -cover`：
  PASS，3.074 秒，包级语句覆盖 93.5%。包括所有旧 v1 tests；前一完整三轮
  亦为 PASS，3.053 秒。
- v1 完整 literal 和历史哈希不变；独立 v2 精确字段/省略/次序 golden 哈希为
  `3a58455cac5a12f3c36333279db2e5e200dfe726adbf99c3a1da6477a2ded1a6`。
  此值另以 PowerShell/.NET SHA-256 对独立 literal 计算确认，不依赖生产 encoder。
- 跨组织同版本不同字节无损往返、跨表同数字 ID、空组织库存、同行复用、同租户
  冲突、非法 scope、孤儿组织、跨版本字段、null/0/缺失/重复 key/别名等均覆盖。
- 16 个并发只读编码与独立结果修改，最大 signed-int64 原 ID、128 字符版本，
  真正 65,536 个总归档项完整往返、上限加一拒绝、真实 16 MiB wire 超限和
  1 TiB 清单开销边界均实际运行，没有降低产品 cap 代替验证。
- v1/v2 均组合真实 `secret` AEAD archive 与生产 `VerifyStream`：有效归档
  通过；完整且认证正确但载荷/类别/集合不一致的归档拒绝。v2 跨组织规则文件
  字节调包也拒绝；外层尾部损坏/截断不会因全部明文 entry 已成功就变成成功。
- 新增 v2 VerifyStream 回归包含逆序、缺失组织工件、重复、未知文件、短/长
  字节、篡改身份清单、吞消费错误、callback 错误、取消及借用能力关闭。
- Windows vet/lint 为 0 issues；Linux amd64 CGO=0 build/vet/lint 为 0 issues。
  这是 Linux 交叉构建/静态检查，不是 Linux 原生执行或 race detector 通过。
- 包含 v1/v2 seed 的真实 `FuzzManifestDecode` 有界运行（5 秒预算、两个 worker）
  PASS，实际 6.137 秒、3,417 次执行。没有持久化失败 corpus 或生成生产文件。

本检查点只声明格式与验证能力，**不声明全库存采集、备份协调器、恢复发布、
实际数据库恢复演练或 M6 已完成/已批准**。上层必须显式选择 v2、按原数据库
身份映射所有保留包，并继续完成快照一致性、授权、审计和恢复对照。
