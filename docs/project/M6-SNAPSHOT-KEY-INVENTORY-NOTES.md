# M6-05：同一只读快照的历史主密钥版本引用清单

2026-09-10。独立私有仓储单元，不是完整备份、密钥可用性验证、解密/MAC 认证、隔离恢复或启用授权。正式审核仍待全量开发完成后统一进行。未修改既有迁移、写入器、Secret/Generator、manifest 或其他清单；PostgreSQL 外层错误接线由 root 独立负责。

## 原要求及真实来源

PRD SYS-008 要求配置/数据备份和恢复校验；TECH SPEC 19.5 与 M6-05 要求主密钥单独提供，恢复时核验 Secret 可解密、schema、报告和 Job。仅保存当前 active key 或几个 DISTINCT 值不足以覆盖真实依赖。

本单元沿原始 migrations 1/8/9/12/16/17/18、实际 `target.go`、`audit.go`、`baseline_repository.go`、`execution_evidence.go`、`execution_display.go`、`execution_derived.go`、`run_estimate.go`、`domain/execution.go` 以及 Secret envelope/evidence/display/derived-source、Generator manifest/replay 核对。具体规则：

| 保存来源 | 所需版本与历史边界 |
| --- | --- |
| `integrity_secrets` | 完整 envelope 的列 `key_version` 必须等于 `encrypted_data_key` 内部版本；保留原 wrap JSON，核验五个精确字段、版本 1、AES-256-GCM、12 字节 nonce/48 字节封装 DEK。历史 soft-delete 若仍保留完整 envelope，仍收录。 |
| Secret 完整擦除 tombstone | 实际 `DeleteTarget` 将 DEK/ciphertext/nonce 置为非 NULL 空字节，fingerprint/last_four 清空，保留 deleted_at。仅这种完整状态免去其 Secret root；部分清除无效。 |
| `integrity_audit_logs` | 全部旧事件 `key_version`，不只当前 head/tail。 |
| `integrity_audit_chain_heads` | 所有非空链头版本，包括未有事件的链头。既有验证器接受 event_count=0、event_hash=''、无事件的空 key 头，此时不凭空增加 root；非空事件却空 key 无效。链认证由既有审计清单另行负责。 |
| `integrity_audit_segments` | 非空显式 Unsupported，绝不冒称已取得归档段认证/密钥闭包。 |
| `integrity_baselines` | 所有有签名行 `approval_key_version`，包括 draft/approved/retired 及过期行；migration12 的两字段同时 NULL 精确保留为 legacy unsigned，单 NULL 无效。 |
| `integrity_response_evidence` | 全部尚未物理清除的 envelope，包括过期行。 |
| `integrity_display_evidence` | captured 的 root；合法 unavailable 状态须完整空 envelope，不收录不存在的 root。 |
| `integrity_attempt_derived` | S1 purpose MAC 的 `key_version`，即使 S2 正文已删除仍必须保留。 |
| `integrity_runs` | 原 `config_snapshot.plan.manifest.key_version`，覆盖全部 Run；原 manifest SHA-256 同时绑定 SQL 列和 plan 中的 hash，不重新生成或补签。 |
| `integrity_run_estimates` | 原 `snapshot_json.plan.manifest.key_version`，包括过期未清除草稿，不被在线读取的 TTL 过滤。 |

`PayloadKeyVersion` 是 payload 的不可变 AAD 标签，不是成功 Rewrap 后仍需要的旧 master。真实外部包测试通过 KeyRing.Encrypt/Rewrap、实际持久化、仅安装新版本的 KeyRing 解密确认，不把它加入 required union。Fingerprint 同样没有被误当作另一个需要旧 root 的解密入口。最终归档加密器使用的 active root 必须由最终协调器显式 union，本 SQL 单元不猜配置或 active 版本。

历史估算格式不是由当前 writer 推断：只读 `git log`/`git show` 核验该表和 writer 同在 `5b84e45` 引入，原 `estimateSnapshot` 已要求 `len(plan.Manifest)>0`，原 `DecodeRunEstimate` 同样拒绝缺失；从该提交至当前的差异未删除该要求，migration9 无旧行回填。因此 estimates 缺 manifest 为 Invalid。Run 的合法 migration17→18 `{"legacy_fixture":true}` 则真实保留为未验证，不混淆二者。

## 私有接口与有限资源

`Store.snapshotKeyInventory(ctx, tx)` 返回私有 `snapshotKeyInventory`：排序去重的 `versions`、九种可支持来源的精确 `observed` 行数、`legacyUnsignedBaselines` / `legacyUnverifiedRuns` / `destroyedSecrets` 计数和分类。分类零值 `snapshotKeyUnverified`；无已知旧缺口为 `snapshotKeyCurrentReferences`；合法未验证历史为 `snapshotKeyLegacyIncomplete`。后者保留原历史事实，不表示已经获得全部历史密钥闭包或恢复资格。fmt/slog 固定脱敏，JSON/YAML 禁止。

- 实际 `*sql.Tx`、同 dialect、有 deadline、`NewDB` 清除调用者查询污染；不读取 Store pool，不开启/结束 caller 事务，不锁链头，不按 active org/target/status/TTL 过滤。SQLite 仍须由外层在 BeginTx 前验证物理 native RO，query_only 只是补充。
- 各来源 `(organization_id, identity)` keyset 每页 100 条有界元数据，完整 SQL COUNT 与已读数闭合。重复主键、边界重复、NULL/非正主键不能被 DISTINCT/GROUPBY/游标丢掉。组织、Run、Sample、Attempt 的相关 envelope 引用在同快照校验实际存在及组织归属。
- 各种 text/blob/integer 在 SQL CASE 内先检查 SQLite 原始类型与字节长度；大 config 不进入 100 行页面。每次仅额外读取一份最大 8 MiB snapshot 或 1024 字节 DEK wrapper，处理后不在结果保留正文。manifest 子对象上限 2 MiB；不读取 S2 ciphertext/derived payload 正文。
- 版本数量限制对全来源 union 生效，最多 64，与当前 backupmanifest 根密钥集合上限一致；不以 64 限制数据行总数。私有测试入口只能收紧该上限。
- JSON 先做完整 token 扫描，拒绝重复键、大小写重复、关键路径单独错大小写、追加 document、非法 UTF-8 和超深/超多对象键，再精确提取既有路径；不使用数据库 JSON 转换来掩盖歧义。大小写等价采用与 encoding/json 一致的 Unicode SimpleFold，逐 rune 取循环最小代表，覆盖 s/ſ、k/K、Σ/ς，不做 O(字段数²) 全量比较。原 manifest 字节 hash 不变，未知 generator_version 当前显式 Unsupported。
- 所有失败、晚行损坏、全 union 超限、底层 SQL 故障或取消都返回完全零候选；错误是闭集 sentinel，不传播 SQL/字段值/外部错误文字。无异步任务或逃逸快照。

封装 DEK 的无歧义空白/字段重排原本可被真实 `secret.unwrap` 解密，不额外要求原字节等于今日 `json.Marshal` 输出。最初草稿有这个过严检查，新增纯红测 **0.094s FAIL** 后改成精确五字段/类型/重复-case 校验；不改原字节或实际加密/AAD。manifest 的原字节 hash 约束保持不变。

## 真实测试记录

- 初次双库新测试 **3.213s FAIL**：新测试错误地把 legacy Run 插入 derived 行、修改 migration18 immutable source；另外测试 page hook 错用 GORM 表名，跨迁移 SELECT * 触发 PG cached-plan 结果类型改变。均改测试为实际 derived CreateRun/Start/Reserve/Finish 流程、观察实际 SQL、固定字段读取，未改变任何生产约束、超时或旧夹具。
- 修正并扩充前全部新测试一次双库 **4.261s PASS**；新增各来源损坏、真实 crypto/generator 桥接后全部一次双库 **18.382s PASS**，terminal 89307 / exit 0。
- 包含跨来源 union 紧限额后，全部 `go test ./internal/integrity/repository -run '^TestSnapshotKeyInventory' -count=3 -timeout=5m` 双库 **53.211s PASS**，terminal 82694 / exit 0；随后释放 General DB 给其他单元。
- 覆盖九类当前来源各自独有 old key、旧审计全行、三种 baseline 状态和过期、真实 S1 完成后 S2 删除、真实 schema17→21 未改写历史、完整/部分擦除、旧 soft-delete、101 组织与禁用组织、100/101 页边界重复、独立连接提交同视图不漂移、owned 结果、64/65 union、缺失/NULL/超长 SQL 字段、每来源离线无约束副本故障、不同对象/组织孤儿、nested JSON/hash/case/未知版本、过晚查询错误和取消、底层事务类型/截止期/已关闭校验。
- Crypto/Generator 测试通过 test-only external-package 桥使用真实包，产品不新增公开入口/循环依赖。真实 KeyRing 新钥匙可解密实际保存的 Rewrap 记录而不能解密原旧记录；真实 Generator 签名/Verify/ExecutionPlan 的原 manifest 同时经过真实 SaveRunEstimate/CreateRun 并被观察。
- envelope 原字节兼容修正后的纯格式/strict JSON/解析取消测试三轮 **0.146s PASS**；完整 Windows repository lint **0 issues**。
- root 独立复核发现 Unicode ToLower 不等于完整 SimpleFold、合法空 audit head 被过严拒绝；新增纯 Unicode / 真实双库空头测试 **0.732s FAIL**，并先确认既有 `verifyAuditSnapshot` 对相同真实空头原本成功。两处已修，不改变已有审计代码或原始行；非空标签仍纳入，空头坏 hash、负 count、非空事件却空 key 均拒绝。
- 所有最终生产/测试修改后的全部 `TestSnapshotKeyInventory` 实际 SQLite/PostgreSQL **三轮 64.732s PASS**，terminal **21096 / exit 0**。包含真实重新包装后非规范空白 JSON 仍能被 new-only KeyRing 解密且 inventory 保留原字节，以及空头原验证器对照和四组 Unicode 别名。最终 Windows 完整 repository vet/lint 均退出 0、lint 0 issues。General 已明确释放给 root，无本单元 DB 测试残留；Backup 未操作。
- 最终 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 的 repository 交叉 vet/lint 同样退出 0、0 issues；这是交叉静态检查，不是原生 Linux 或 race 测试。

## 尚未完成的边界

本单元仅发现受支持格式中明确保存的 root 引用，不验证所提供主密钥是否存在/匹配，也不解密数据库全部 Secret/S2、不验证全量 baseline/probe/derived MAC。当前非空 audit segment、foundation 非空 `sample_attempts.response_content_enc` / `gateway_evidence.signature` 没有已实现的 versioned codec，显式 Unsupported，不能遗漏后宣称成功。未知历史 Generator codec、legacy Run 缺 manifest、legacy unsigned baseline 的完整隔离保存/验证策略仍是最终备份恢复协议必需工作，不是最终永久排除这些历史的许可。

最终协调器仍须 union 自己的归档加密 key、校验外部匹配的钥匙文件、组合其他清单/原生数据库导出/实际文件与配置归档，完成隔离恢复、恢复后全量认证、CLI/HTTP/UI 和干净环境演练。这里的 Windows 双库非 race 结果不代替原生 Linux/race、远端 CI 或完整产品测试。
