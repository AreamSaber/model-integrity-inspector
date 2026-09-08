# M6-05 备份 manifest 与文件清单

2026-09-08。生产纯组件 `internal/integrity/backupmanifest` 已实现并通过本地专项；不是数据库快照、系统备份服务或恢复完成。依据 M6-BACKUP-IMPLEMENTATION-NOTES 第 4～6 节，不改变 SYS-008 或正式审核状态。

## 格式与信任边界

`mii.backup-manifest.v1` 的闭集字段绑定 backup ID、开始/快照 UTC 微秒、应用版本/真实源码提交标识、数据库类型/版本/快照方法与文件长度/hash、连续完整迁移版本/名称/checksum、ready 报告的组织/Run/分析修订/报告修订/格式/schema/内容与来源hash/文件hash、各保留 rule/template/tokenizer/scoring 版本及工件、引用的 key version、每组织审计 count/end hash/key/canonicalization、每组织 Job 状态摘要及安全配置模板文件。

- Encode 复制所有 slice 后排序，拒绝重复、引用矛盾、缺类别或超限，不修改调用者列表、不截断备份。无报告时显式空数组，组织审计与 Job 汇总一一对应。存在 running Job 或 DISPATCHED Attempt 拒绝生成可发布清单，保留 pending 与 UNCERTAIN 历史，不改写为完成。
- Decode 必须带外部预期 backup ID/hash，先校验长度与hash，再流式 Token 预检，最后 typed decode、完整结构验证和逐字节 canonical 比较。重复/大小写别名字段、未知字段、缺字段、null、转义、乱序、浮点、尾随 JSON/空白都不能被归一化为成功。
- 预检在 Report 等结构体数组分配前限制根数组数量、reports+artifacts 共享文件额度、对象深度/字段数、字符串/数字长度。只建立有界解析栈，不先构建完整 generic JSON 树。
- Entries 给出独立拥有的准确 entry kind/ID/字节数/hash 列表，包含 manifest 本身。manifest 不包含自身hash：编码后才计算该hash，避免自引用。Encode 与 Entries 均将 manifest 字节计入归档总明文预算。
- entry ID 是不含路径的 ASCII 标识，不得直接作为恢复路径。版本标签与 entry ID 分离：artifact 版本对齐现有 128 字符元数据契约，key version 保持 secret 的 64 字符限制。报告枚举覆盖原计划 JSON/HTML/PDF/CSV；这不代表 PDF/CSV 生成已实现。
- 自动 JSON/YAML/fmt/slog 不得泄漏完整 Manifest 或审计锚点，序列化必须显式 Encode。组件没有 Config、DSN、SQL、任意路径、主密钥或自由正文容器；但这不能替代协调器对真实配置模板内容的闭集生成和检查。

资源上限：manifest 16 MiB；所有归档 entry 合计最多 65,536（含固定 database/config/manifest 三项）；组织最多 16,384；迁移最多 4,096；key version 最多 64；归档总明文最多 1 TiB，含manifest。它们是显式资源拒绝策略，不是已验收的数据库/生产卷容量。合法清单的 typed 内存与元数据规模成比例，不随数据库文件字节数增长。

## 真实失败与修复证据

1. 独立复核用 196,638 字节 JSON 放入 65,537 个空 Report 对象，原 Decode 虽最终 ErrLimit，却先累计分配约 57 MB（独立三次 57,008,000 / 56,965,496 / 56,965,432 字节）。root 同一问题正式回归得到 **57,013,664 字节**，实际失败。
2. root 同批真实红测还包括：Encode 未将 manifest 自身计入 1 TiB 总额、真实空审计头的合法 key version 被误拒；该组包 **0.275s FAIL**。修复后全部三项通过，不修改资源上限、不删反例。
3. 独立真实 `templates.Registry.Add/Get` 接受 66 字节合法模板版本，原 manifest 将 artifact 与 key 共用 64 字符规则导致 Encode 失败（独立包 **0.234s FAIL**）。现在二者分别校验，正式测试又覆盖真实 Registry 的 66/128 字节成功、129 字节 artifact 和 65 字节 key 拒绝。
4. 独立原反例原样三轮复跑 **0.242s PASS**：超量数组分配降为 1,576 / 1,592 / 1,576 字节且仍 ErrLimit；66 字节真实模板版本可备份。完整复读四份生产文件后未确认其他 P1/P2。这不是正式 OPS/SEC 批准。

## 测试与组合证据

固定 Go 1.26.7，在 Windows 执行，无数据库测试或修改；没有 Linux/native race 结论。

- 格式 golden SHA256 `0fbbd751a365f53c7cb9c3e3763fa176d5d2ed1e43f88189993e9a0d3bfc80b2` 对应明确的 synthetic fixture；验证排序、输入列表不变、解码独立性、空报告和两个驱动/四种报告描述，不是假称真实双库/PDF输出。
- 结构反例覆盖缺迁移、版本/格式不兼容、缺历史 key、组织或文件重复/跨类别碰撞、审计/Job 对应、状态/整数/总容量、绝对路径/穿越/ADS/大小写、非规范 JSON 与泄漏保护。
- 真实 `secret.BackupSealer/Opener` 组合包含清单、数据库、配置、报告和四类工件的 synthetic payload。所有五个场景都具有真实合法 AEAD framing：只有完整匹配的场景符合清单；被认证但内容被换、文件缺失、额外文件或 kind 错误仍须拒绝。此处校验消费器是测试代码，生产协调器尚未实现，不能说系统恢复入口已经执行这些核验。
- 完整新包三轮 **0.165s PASS，92.7%**；最终 contracts 与新包三轮分别 **0.504s / 0.157s PASS**。lint 最初发现三项布尔写法及一处测试精确 sentinel 豁免位置问题，均已修正；最终 `golangci-lint run --allow-parallel-runners ./internal/integrity/backupmanifest/...` **0 issues**。
- `go test ./internal/integrity/backupmanifest -run '^$' -fuzz '^FuzzManifestDecode$' -fuzztime=10s -parallel=2`：实际 **11.106s PASS**，5/5 baseline、266 executions、2 new interesting（共7）；低次数有限 fuzz 不是完整解析安全证明。单输入超过256 KiB明确跳过，16 MiB及数组上限另有确定性测试。未伪称更大的执行次数。

首次新增 crypto 组合测试因 Seal callback 少写 context 参数编译失败，修正签名后才运行测试；这只是测试实现错误，不是生产缺陷红绿证据。

## 尚需接入的完整能力

Encode/Decode 只证明输入事实的结构与承诺一致，**不证明事实来自数据库、列表完整、历史密钥齐全或审计HMAC有效**。协调器必须从同一真实一致快照提取和验证全部事实；外部预期hash不能取自同一个不可信归档。合法旧备份整体替换仍需独立保管的可信锚点检测。

v1 显式 `audit_history=complete`：若数据库存在已密封/删除的审计分段，后续协调器必须拒绝，直到实现包含分段/永久锚点的新完整格式，不能以此跳过原有清理/恢复要求。主密钥不入归档；所有实际引用版本必须另外提供。

仍缺维护协调器接线、SQLite online backup、PG同快照dump/inventory、真实报告/规则文件复制及hash复核、安全配置模板、备份ready/授权下载与审计、隔离恢复/激活、CLI/HTTP/UI，以及干净双库恢复/RTO/RPO演练。M6-05/SYS-008 保持进行中。
