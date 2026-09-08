# M6-05 / SYS-008 备份恢复实施边界与切片

更新：2026-09-08。状态：调研及实施设计完成；生产流式私有文件组件已有 Windows 测试证据，见第 9 节。备份、恢复、维护门禁尚未实现，未执行备份恢复演练，正式审核待统一进行。本记录不改变原始需求、验收条件或已有批准记录。

## 1. 原始范围与不可缩减条件

| 事实源 | 明确要求 |
| --- | --- |
| `模型真实性检测系统-PRD-V1.0.md:263`，SYS-008 | 系统内导出配置与数据备份，并提供恢复校验，P0。不能只交付一条数据库导出命令。 |
| PRD 第 15.1 节第 13 项（`:644`） | 干净测试环境恢复后验证目标、任务、报告与审计。 |
| PRD 第 15.3 节（`:669`） | 备份内的密钥同样保持加密。 |
| `模型真实性检测系统-TECH-SPEC-V1.0.md:1595`，19.5 | PostgreSQL 数据库备份、报告归档、manifest；SQLite 暂停新 Job 或进入维护模式后使用 online backup API；包含规则版本、配置模板，不含明文主密钥；操作者单独提供匹配主密钥；恢复验证 schema、报告哈希、Secret 可解密性和 Job 状态。 |
| TECH SPEC `:1298`，13.6；`:1763`，AC-23 | 恢复后完整审计链验证通过之前不能开放敏感写；目标、密钥密文、任务、报告、审计一致。 |
| `模型真实性检测系统-开发计划与审核表-V1.0.md:197`，M6-05 | 两种数据库的脚本、报告归档、manifest、恢复工具；依赖单机及 Compose 交付。 |
| 同上 `:218`，M7-06；`:275`，OPS-03 | 升级、回滚、灾备真实演练，记录实际 RTO/RPO，不虚构接受或批准。 |

同时遵守已批准 ADR-0002（双库、迁移与非破坏性恢复）、ADR-0004（用途隔离、主密钥分开保管）、ADR-0005（独立单机/Compose）、ADR-0006（恢复全链验证、外部锚点与审计保留）。密封审计分段尚未实现，未来增加分段清理时必须把分段 manifest 与永久锚点加入备份，不可忽略已清理历史。

## 2. 当前代码事实

调研时 SYS-008 的需求矩阵仍为 `not_started`，台账 M6-05、OPS-03 未开始。OpenAPI `/system/backups`、`/system/backups/{id}` 和下载路径明确为 `contract-only`（`docs/api/openapi-v1.json:10510` 起）；真实路由尚未注册。系统状态明确返回 `backup_restore_receipts_unavailable`（`internal/identity/system_status.go:168`）。

可复用基础与限制：

| 现有能力 | 精确位置 | 复用方式及不能推导的结论 |
| --- | --- | --- |
| CGO-free SQLite、WAL、FULL synchronous、受控 DSN、单连接 | `internal/integrity/repository/store.go:51`、`:123` | 可以在仓储内部获取 `sql.Conn.Raw` 执行驱动 backup API。单连接仅约束本进程，不能证明其他实例或新任务已暂停；不能复制裸 `.db` 代替备份 WAL。 |
| 数据库 Job 与跨进程 SQLite consumer lease | `internal/integrity/repository/job_queue.go:38`、`:129`；`job_transaction.go:80` | 已有 generation fencing、领取/续租/提交事务；缺少全局维护门禁。PG 可有多个消费者，停止一个本地 Runner 不等于暂停全系统。 |
| 不可变、组织隔离、独立文件哈希的报告存储 | `internal/integrity/reportstorage/store.go:36`、`:47`、`:116`、`:184` | 按 DB 快照内 ready 报告的 `(org, hash, format, size)` 构造 Reference 并 Read；不能把目录遍历结果当报告事实源。当前单文件上限 16 MiB，仅 JSON/HTML。 |
| 报告先写文件，后由 Job 完成事务发布 DB 引用 | `internal/integrity/worker/report_generate.go:58`；`internal/integrity/repository/report_records.go:94` | 快照看到 ready 时应已有完整文件；文件写完但 DB 回滚可留下 orphan，不应导出为业务报告。未来清理必须尊重备份 pin/维护门禁。 |
| 全链验证与只读 schema 版本检查 | `internal/integrity/repository/audit_health.go:12`；`audit.go:195`；`migrate.go:127` | 恢复后可复用算法。但当前 full verifier 逐组织另开事务，PG 锁链头 SHARE；它不是 pg_dump 同一快照的 inventory API。CheckSchema 检查迁移历史，不单独证明所有物理表/约束或数据完整性。 |
| 启动前校验密钥、迁移、全链和内置规则 | `internal/app/app.go:65`、`:114`、`:121`、`:125` | 正常 prepare 会执行迁移/同步内置包；不得用它替代只读恢复预检，也不能让待验证恢复库先启动 Worker。 |
| 受限外置主密钥与多版本纯 KeyRing | `internal/integrity/secret/keyfile.go:24`；`envelope.go:68` | LoadKeyFile 只加载一个版本；KeyRing 支持多个版本但实际配置未提供多文件 ring。必须检查所有实际引用版本，不能把当前 key 能加载等同历史 Secret/审计可验证。 |
| Worker-only 明文消费边界 | `internal/integrity/secret/envelope.go:373`；`service.go:152` | 恢复校验应增加仅返回成功/分类失败的内部验证能力，复用解密实现并立即 Destroy；不能给运维/HTTP 增加通用明文 getter，不能假扮 Worker 导出凭证。 |
| 私有、no-follow、no-replace 原生文件边界 | `tests/replay/localfile/file.go:55`、`:126`；`file_windows.go:61`、`:168`、`:222` | 是可复用算法与回归证据，不是生产依赖。需要抽取/新增生产流式文件包并保留原测试语义，不能生产 import `tests/replay`。当前 24 MiB 整块内存 API 不适合数据库备份。 |
| Windows 私有目录创建/句柄检查 | `internal/integrity/reportstorage/store_windows.go:22`、`:67` | 已有 NtCreateFile、OBJ_DONT_REPARSE、受限 DACL、句柄类型/链接检查。不是创建后 chmod，也不能先写敏感临时文件再收紧 ACL。 |
| 实际初始化、受控 TLS Worker、报告与双库集成 fixture | `internal/app/pipeline_test.go:150`；`artifacts_pipeline_test.go:22` | 可扩展到备份→新隔离环境恢复→真实登录/查询/下载/新受控调用，不用手工插几行表或空数据库冒充端到端。 |

CLI 目前只有 run、keygen、version（`cmd/mii/main.go:44`），没有 backup/restore。`app.Config` 明确禁止序列化（`internal/app/config.go:40`）；备份配置必须由闭集安全字段生成新模板，不可 serialize Config 或直接打包 `.env`、运行目录、DSN、setup token、主密钥路径内容。

## 3. 优先可实施切片：持久化维护与恢复隔离门禁

这是下一项有独立代码及双库证据的工作单元，但不是 M6-05 完成交付。

1. 新增版本化系统维护记录和备份操作记录：闭集模式至少区分正常、备份冻结、恢复隔离；具备 owner/generation、截止时间、操作状态、审计主体及固定错误码。迁移编号由集成时最新迁移链分配，不预占并行 agent 的编号。
2. 门禁检查与新任务创建/领取必须在同一数据库事务内，固定锁顺序在前。PG 可用共享门禁锁保障普通短事务并行、独占切换模式；SQLite 使用已存在的短 BEGIN IMMEDIATE 语义。覆盖外部创建 Run、预检、报告与通用 enqueue；不能只在 HTTP 层检查一次。
3. 进入备份冻结后停止新业务任务提交和新 Claim；在途 Worker 保持真实续租并允许必要结算、内部依赖 Job 入库，否则会人为产生不一致。待在途请求结束、结算完成后快照；新生成的 pending 后续 Job 可保留，但不能继续被领取。不得把 expired lease、取消请求已发出或本地 Ready=false 当成外部调用已终止。
4. drain 超时/取消必须明确失败并通过相同 owner/generation 退出冻结；不得伪造完成、重试不确定付费调用或放宽原有 lease/budget/cancel 规则。实现允许纯恢复协调而不发起新上游请求，保证失联/过期 Job 能以原有保守规则达到可解释状态。
5. 独立操作协调器持有备份租约，不应把唯一的备份 Job 放入同时被全局冻结的业务 Claim 队列。PG 多 Server 竞争只允许一个有效 owner；失租者不得发布 ready 或开放下载。恢复过期 owner 时先增 generation，防旧进程迟到提交；私有文件 orphan 不代表可下载成品。
6. 恢复隔离不随普通备份 lease 超时自动变回正常。新环境在显式完成校验/激活前拒绝任何出站 Worker 和敏感业务写；保留登录、状态、授权历史与报告读取，以便真实启动检查。
7. 系统备份是跨组织敏感操作：真实 system admin、活跃会话、非强制改密、CSRF/Origin、明确审计原因，仓储在变更/发布/下载前复核；组织管理员不能通过伪造 `system.backup` grant 获得全库。定义明确的系统级操作审计落点，不假定现 `auditUserOrganizations` 只覆盖操作者所属组织就已记录所有跨组织语义。

该单元必须证明：两个真实连接/实例并发的创建与冻结互斥、PG 多消费者被拦截、已入场结算不死锁、内部后续任务不丢失、取消/超时/旧 generation 无法误解冻、审计失败整笔回滚、恢复隔离重启后仍禁止 Worker、正常读不受无谓阻断。

## 4. 数据库快照与报告/审计绑定

### SQLite

项目已固定的 modernc.org/sqlite v1.58.0 提供以下原生能力，不需要安装外部 sqlite3：

- `C:/Users/Camellic/go/pkg/mod/modernc.org/sqlite@v1.58.0/conn.go:1208`：连接方法 `NewBackup(dstUri)`。
- 同模块 `backup.go:29`、`:42`：`Step(n)`、`Finish()`；通过 `sql.Conn.Raw` 内部接口断言访问。Step 的 true 表示仍需继续，false 且无错才完成。

在私有 staging 目录中预建受限目的文件，执行有限页步进并检查 context/容量/总时限；只分类识别 BUSY/LOCKED 做有界退避，始终 Finish，不能 `Step(-1)` 后声称可及时取消。驱动按路径重新打开目标，必须处理私有目录固定句柄、路径替换与文件身份复核；不能复用会拒绝任何共享打开的文件句柄而制造 Windows sharing violation。

完成后关闭目的连接，确认持久化并以只读模式打开副本。对该副本生成 schema、报告列表、密钥版本、Job 清单与审计链锚点；读取 live DB 的稍后状态不是同一快照。执行 SQLite integrity_check、foreign_key_check、迁移链及业务一致性检查。在线备份使用专用连接时不得从仓储默认 WAL/write pragmas 静默扩大只读副本权限。

SQLite 官方明确支持分步 online backup 和源端并发，详情见 [SQLite Backup API](https://www.sqlite.org/backup.html)。本项目另需完成维护策略和跨存储绑定，单独调用该 API 不满足全部要求。

### PostgreSQL

协调器保持一个 REPEATABLE READ READ ONLY 事务，取得 `pg_export_snapshot()`；在同一事务内生成有界分页的报告引用、版本清单、Job 信息和完整审计锚点。受控 `pg_dump --format=custom --snapshot=<该快照>` 使用相同快照，父事务在 dump 结束前不可提交。`--snapshot` 同步能力见 [PostgreSQL 18 pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html)。

- 新增仓储内部快照能力，抽取现 full audit 算法为接收受控事务的内部实现；不向业务层暴露 GORM/通用 SQL。不要对 READ ONLY 事务执行当前 verifier 的 SHARE 行锁。
- 仅备份本产品的明确数据库/schema；拒绝未知 schema、扩展或对象而不是静默遗漏。PG schema 名不能当任意 shell/glob 字符串。当前本地测试常用隔离 schema，正式恢复演练必须包含全新数据库形态，不能只证明测试 schema 复制。
- `exec.CommandContext` 固定绝对可信可执行文件和参数数组；无 shell。认证使用受限临时 pgpass/service 文件或受控环境，禁止 DSN/password 放 argv、日志、receipt；清理继承的 PGSERVICE、PGOPTIONS 等非显式输入，保留所需 TLS 验证策略。
- stdout 写私有 dump 文件/受控流，不把 stderr 原文传播到 API/log（可能含连接、SQL 或值）。总字节/时限/子进程树退出有界，取消必须实际等待进程停止；验证 Windows 和 Linux 行为。

### 同一备份的 manifest

manifest 至少绑定：格式版本、backup id、创建/快照时间、数据库类型/版本、应用版本/源码提交、完整迁移版本/名称/校验和、DB 文件长度/哈希、所有 ready 报告的组织/报告/Run/修订/格式/长度/文件哈希、规则/模板/tokenizer/评分版本及工件哈希、所有实际引用 key version、每组织审计 count/end hash/key version/canonicalization version、Job 状态摘要、安全配置模板哈希。

只复制快照引用的 ready 报告，通过 reportstorage.Read 独立验证，文件缺失/篡改即整笔失败。固定排序、去重、有界计数、严格枚举及整数溢出检查；禁止 entry 中的绝对路径、`..`、链接、ADS、设备、重复大小写名称及非闭集文件类别。不要归档完整 report/data 目录或 live master key。

审计时间线必须真实：备份开始事件先提交并绑定到快照锚点；文件成品发布后再向源库追加完成事件及 durable receipt。完成事件不可能已存在于更早冻结的数据库副本，不得虚构这种自引用证明。可独立保管的 manifest 锚点用于发现整库回退；库内自身有效 HMAC 链不能单独发现完整回退。

## 5. 加密、私有文件与原子发布

原需求强制 Secret 在备份中继续加密、主密钥另存；本方案建议外层归档也做认证加密，避免备份暴露账号、业务元数据与可能存在的 S2 数据。新增独立 HKDF purpose 的 backup manifest/包装密钥，不复用 AuditMAC/probe/evidence purpose，不导出 raw key。

- 每次备份使用随机 DEK 和唯一 nonce；用匹配主密钥的独立用途 wrapping key 包裹 DEK。版本化分块 AEAD 绑定 backup id、entry、chunk ordinal、最终长度和结束标记；拒绝重复/乱序/截断/尾随内容。每块有界，不能把全数据库读入 RAM 或仅用未认证 SHA-256 当防篡改。
- master key、包装/审计派生 key、DSN、setup token、原 `.env` 不进归档；manifest 只列 key version，不列可恢复明文。归档解密不意味着可以输出 Secret，Secret 仍按原 envelope 校验。
- 生产流式私有文件能力沿用既有原生 no-follow、restricted ACL、同目录 staging、sync、no-replace publication；测试必须覆盖现有目的文件不变、junction/symlink/hardlink/UNC/ADS、父目录替换、宽 ACL、写失败/磁盘满、取消后只清理自己创建的临时文件。
- 普通 `os.Rename` 在不同平台的覆盖语义不能作为 no-replace 保证；Windows 可沿用既有 `NtSetInformationFile` ReplaceIfExists=false 模式。Unix 使用已验证原生不替换发布并同步目录。Windows 没有可移植 directory fsync，不宣称无条件抗断电保证。
- 文件系统与 DB 不是一个事务：先私有完整成品，再仓储最终鉴权/fence/audit + ready receipt。DB 失败时文件可留受限 orphan，下载只认有效 DB receipt。不得因清理错误删除已发布目的文件。
- 下载前重新校验长度/hash/格式/当前权限并审计，完成后只释放匹配授权对象；HTTP 不能接受操作者任意路径/命令。中途撤权、取消和晚到响应遵循项目现有敏感导出边界。

## 6. 只恢复至新隔离环境

建议入口：`mii backup`、`mii backup verify`、`mii restore`，以及系统内备份创建/状态/下载 UI。HTTP 不开放“覆盖当前库”的恢复接口。具体 CLI 名可在实施时统一，但不能只有 CLI 而遗漏 SYS-008 系统内能力。

恢复必须明确指定新目录和独立主密钥配置；拒绝现有目的文件/目录、源数据目录、报告目录、密钥目录及路径别名。PG 必须恢复到新建的专用数据库及新报告目录，拒绝当前 live database，不能用 `--clean`/`DROP` 清空活库。只读预检检查环境标识；缺少创建新数据库权限时给闭集错误，不请求或使用任意超管凭证。

顺序：

1. 校验输入权限、有限头、归档格式与匹配 key；先认证/解密至不可见私有 staging，验证所有 entries/manifest，再执行任何数据库内容。
2. SQLite 使用已验证完整数据库副本；PG `pg_restore --single-transaction --exit-on-error --no-owner --no-acl` 到新空库，使用非超级用户的专用恢复角色，不使用 `--clean`。PostgreSQL 官方指出恢复会执行源库定义的代码，因此仅接受本产品可信来源、已认证备份，不能把“签了 hash”描述为任意 dump 沙箱；见 [pg_restore 安全与事务说明](https://www.postgresql.org/docs/18/app-pgrestore.html)。
3. 只读验证迁移链/版本兼容、结构和外键、报告引用/文件哈希、原始发布结果/报告内容哈希、全部 Secret envelope AAD/解密性、保留的证据密文及用途版本、全审计链与外部锚点、Job 对象组织/状态/fence/未确定 Attempt。批次有界，不输出任何解密内容。
4. 当前 LoadKeyFile 的单版本限制需要补充实际多文件 key ring 配置/加载；缺任一保留数据所需旧版本必须失败。不能自动猜版本、重新加密历史、把当前 key 套在旧数据上或以 Secret 表为空回避这项测试。
5. 恢复副本保留不可自动解除的隔离状态；验证并出具分类结果之后才发布新目录。报告和 DB 的隔离发布若不能同一原子操作完成，以受限 restore receipt/activation marker 为启动门槛，任何中间失败不可启动成正常实例。
6. 显式处理复制的旧 sessions、consumer leases 与进行中任务，保留历史事实，不篡改为 completed。应在新库以审计事务使旧会话失效并记录恢复身份；不得自动重发不确定外部调用。离线校验结果与激活后的新审计事件分别记录，不能比较它们为完全相同的 DB 文件。
7. 实际启动隔离后的真实应用（含嵌入前端），验证登录、健康、历史、报告下载、无 Worker 出站；明确激活后再用受控 TLS fixture 执行一项新任务验证密钥可用。正式生产激活/数据切换由操作者另行授权。

## 7. 双库和异常路径证据计划

建议 `internal/app/backup_restore_test.go` 扩展既有真实 TLS pipeline，两种数据库分别运行，不能一条测试只检查接口返回 200。

| 类别 | 必须断言 |
| --- | --- |
| 正常端到端 | 真实初始化/用户组织/目标加密凭证/预检/检测/发布结果/JSON+HTML报告/审计→系统内备份→新目录/新PG库恢复→真实应用启动→重新登录→历史及报告字节一致→受控新调用成功；源库仍可用、未覆盖。 |
| 并发一致性 | snapshot 前后 barrier 插入不同报告/审计/目标；备份只含快照可见集合，DB、文件、链头吻合；新 Job/Claim 与 freeze 互斥，在途结算不丢失。 |
| 密钥与安全 | 错误主密钥、缺旧 key version、被修改 wrapped DEK/AAD/报告/审计头/旧合法整库替换失败；归档与 stdout/stderr/log canary 扫描无明文 API Key/自定义 Header/master/DSN；其他组织管理员无权创建/下载。 |
| 归档解析 | 乱序、重复、截断、尾随、超限、整数溢出、路径穿越、Windows 大小写/ADS/设备名、链接、压缩炸弹（如启用压缩）失败且无外部写入。 |
| 故障/取消 | 复制中取消、SQLite BUSY/LOCKED、pg_dump/restore 非零退出/挂起、磁盘满、ACL 拒绝、失租、audit insert 失败、ready 前 DB 失败；没有可下载半成品、没有 live DB 修改，旧 generation 不能发布/解冻。 |
| 恢复中断 | 目的已存在、源等于目的/别名、schema 不兼容、新PG库权限不足、restore 中断、缺报告、验证后启动失败；隔离标记保留、无 Worker 请求、可据 exact receipt 重试/清理。 |
| 容量与部署 | 超过现 replay 24 MiB 的真实数据库流式备份、峰值内存、耗时、文件数/上限可解释；单机与 Compose 干净环境均演练并记录实际 RTO/RPO。 |

阶段产物及台账应分别记录：维护门禁完成、备份格式/crypto完成、SQLite快照完成、PG快照完成、恢复验证完成、CLI完成、HTTP/UI完成、真实双库演练完成。它们均不等同 TL/OPS/SEC/QA 正式批准。

## 8. 当前工具与外部边界

初始只读调研阶段仅运行版本及代码读取命令，实际结果：

- `.tools/postgresql-18.6-3/pgsql/bin/pg_dump.exe --version` → PostgreSQL 18.6。
- 同目录 `pg_restore.exe --version`、`psql.exe --version` → PostgreSQL 18.6。
- 同目录可见 `pg_basebackup`、`pg_verifybackup`，但物理集群备份不是当前建议垂直切片，不能用这些工具名字当备份证据。
- PATH 可发现 Windows `tar.exe`；PATH 未发现 `sqlite3` 或 `docker`，不推断机器任何其他位置都未安装。SQLite 无需 sqlite3 CLI；归档优先 Go 原生流式实现，不依赖外部 tar 解包。
- Compose 仍需真实容器环境验证；初始只读调研未安装依赖、未创建数据库、未读取/输出 DSN 或密钥、未修改其他文件、未 Git 提交。

下一步推荐实现第 3 节持久化门禁，同时可独立开发生产流式私有文件/归档 crypto 与格式验证；待门禁及安全文件基础稳定，再接 SQLite/PG 快照、恢复和系统 UI。不能将本设计文档或数据库 SQL 文件标记成可恢复交付。

## 9. 生产流式私有文件组件 checkpoint（2026-09-08）

实现范围仅新增 `internal/integrity/privatefile/**`，没有修改现有 reportstorage、replay、Worker、Repository、Secret 或依赖。维护门禁/备份业务并未接入此组件，SYS-008 不能因此标为完成。

- API：`Read(ctx, absolutePath, Limits, func(context.Context, io.Reader) error) (Receipt, error)`；`WriteNew` 对应 Writer。显式 Limits 含总字节和期限，硬上限 1 TiB/24h；它们是资源策略，不是已验收数据库容量。读/写均 64 KiB 内部分块、增量 SHA-256，无整文件载入 RAM；只向可信 callback 暂借 Reader/Writer，不暴露 Close/路径/原生句柄。
- 读要求完整消费并复核同一句柄的 identity/size/mtime/EOF、文件权限和父目录身份。读中已经消费的字节不能撤回，调用者必须在操作成功后才发布结果；认证归档、期望 hash 和数据库快照仍由后续上层实现。
- callback 吞掉 limit/cancel/I/O 错误不能变成成功；callback 结束或 panic 后能力原子失效，进行中的单次内核 I/O 不可抢占，仍需可信 callback 配合 context。
- 写采用创建即受限的随机同目录 staging、Sync、原生原子 no-replace。Windows 用 NtSetInformationFile 且 ReplaceIfExists=false，Linux 要求 renameat2(RENAME_NOREPLACE)，不支持即失败而不退化覆盖。
- Receipt 仅有 Size/SHA256/Published。发布前失败只尝试清理自己创建的 staging；发布后的 sync/close/cancel/父目录替换错误保留 Published=true 并不删除成品。清理失败可留下受限 orphan，不声称任意错误都等于完全无输出。
- Windows 实际句柄要求固定磁盘上的 NTFS+持久 ACL，拒绝 UNC/ADS/设备/短名/subst/reparse 路径，安全 trustee 仅 current user/SYSTEM/受信 Administrators。Linux 接受已列本地文件系统，overlay/FUSE/NFS/CIFS/未知类型拒绝；这不是 OS 禁网保证，也不抵御拥有相同 UID/root/管理员和本机代码控制权的对手。

已执行证据：

1. `go test ./internal/integrity/privatefile -count=3`：最终 Windows 三轮 **1.129s PASS**，14 个顶层测试；真实 32 MiB+17 字节写/读及独立 hash、累计分配量上限（非整文件）、8 并发仅一成品、精确 no-replace、读限额/不完整、期限/取消/吞错、返回后能力失效、panic 后清理、hardlink、mandatory native junction、宽 ACL/发布前 ACL 变宽、固定句柄防改写/rename、实际已分配 8.3 别名拒绝、发布后取消/close 错误保留成品。32 MiB 仅为组件流式证据，不是大库/生产卷容量验收。
2. `golangci-lint run --allow-parallel-runners ./internal/integrity/privatefile/...`：Windows **0 issues**。并行 runner 标志只避免和同仓其他 agent 的 linter 锁冲突，不改变检查项。
3. `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ... ./internal/integrity/privatefile`：**编译通过**；同环境 Linux lint **0 issues**。生成的交叉编译测试二进制在系统临时目录；本轮未执行它，不能当作 Linux 原生通过。
4. 新增 Linux 专用测试：真实 symlink/FIFO/宽模式、父目录替换前后/固定引用、源文件增长截断、staging 被替换不删他人 entry、发布后 directory fsync 失败。待真实 Linux CI 运行；不因本机 Windows 无法执行而 Skip。
5. Docker 的 `RUN go test ./...` 可能位于 overlay：Linux 测试检查实际文件系统；若默认临时目录被生产策略拒绝，则在经 Statfs 验证的 tmpfs `/dev/shm` 中创建专属 0700 目录运行同一测试，顺序运行且逐案例清理，适配默认 64 MiB shm。无安全本地测试卷则失败；保留独立 overlay 拒绝断言。不修改 Dockerfile/CI，也不据此宣称 overlay 或部署备份卷通过验收。

2026-09-08 主任务与派生 S1 agent 的独立代码复核共同确认并修复一项 P2：Windows 父目录 ACL 的敏感权限掩码漏掉 `FILE_DELETE_CHILD`（原生位 `0x40`）。文件自身 private DACL 不足以阻止拥有父目录 delete-child 权限的其他 trustee 删除/重命名文件；这一权限语义见 [Microsoft DeleteFile 文档](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefile)。修复只把该位纳入既有敏感掩码，没有扩大允许 trustee 或修改 Linux 策略。

- 先新增真实 Windows ACL 反例 `TestWindowsParentDeleteChildOnlyPermissionRejected`，父目录 ACL 为 current user / SYSTEM FullControl，加 Everyone **仅 `0x40`**，未混入 FR/FW/DELETE 等原本已检查的位。原码实测红：WriteNew 返回 Published=true / nil，Read 进入 callback / nil，目录出现新成品。
- 修复后同一用例要求 Read / WriteNew 均 ErrPermissions、Read callback 不可触达、没有新成品或 staging，恢复测试目录 ACL 后原有输入内容仍逐字节一致。未使用另一个真实账号删除任何文件；所有操作只涉及 Go 创建的合成临时目录。
- `go test ./internal/integrity/privatefile -count=3 -cover`：最终 Windows 三轮 **0.919s PASS**，覆盖率 **81.3%**；`golangci-lint run ./internal/integrity/privatefile/...`：**0 issues**。固定 x/sys/windows 未导出 FILE_DELETE_CHILD 名称，所以使用带 Windows 原生含义注释的 `0x00000040` 常量，不添加依赖。
- 本轮已完整读取该包全部生产文件、测试和 README，取消、限额、吞错、路径/句柄、发布后错误 receipt 与 staging 清理未再确认其他 P1/P2。Linux 文件只做源代码审查，未执行 Linux 测试；不能将已有 cross-compile 或 Windows 通过改写为 Linux 原生证据，也不是正式 OPS/SEC 审核批准。

后续仍需 root 代码复核、真实 Linux CI、维护门禁、双库快照/认证归档/manifest/恢复隔离与校验、CLI/HTTP/UI 和真实端到端恢复演练。组件详细契约见 `internal/integrity/privatefile/README.md`。本 agent 未 Git 提交或推送。

### Windows CI 临时目录短名别名：测试夹具修复（2026-09-08）

主任务提供 CI `34181012515` 的症状：Windows privatefile 多项正常 WriteNew 在 `0.00s` 返回 `MI_PRIVATE_FILE_UNSAFE`，同次 Linux package/image 已成功。这里没有把 `ErrUnsafe` 误判成另一个分类 `ErrFilesystem`，也没有放宽生产 NTFS、ACL 或路径别名策略。

先在本地新增真实 Windows 回归 `TestWindowsTempDirectoryShortBaseUsesCanonicalFixture`：对测试自建长目录执行 `GetShortPathName`，实际观察 `short_alias_allocated=true`；设置 TMP/TEMP 为该短基路径，并清空 GOTMPDIR 防止绕开本场景；独立 child 首次调用 `privateDir`/`TempDir`。原 fixture 实测红：`canonical_match matched=false`，普通写 `stage=write_new unsafe=true`，用例耗时 `0.00s`，命令 exit 1 / 包耗时 `0.259s`。测试输出只有闭集阶段和布尔值，不包含用户目录、原路径或凭证。

修复仅涉及 Windows 测试：`newTestDirectory` 把**自己本次 `t.TempDir()` 创建的目录**交给 test-only `canonicalTestDirectory`。后者用实际无删除共享的目录句柄获取 `canonicalName`，验证目录/非 reparse 属性，再独立打开规范长名称，比较 VolumeSerialNumber 与 FileIndexHigh/Low 确認同一目录后返回。它不接受或修复生产调用者输入，没有修改任何 production 文件、CI 配置或 Git 状态。

回归同时验证：正常规范长路径写/读成功；同一目录下直接使用原短基路径的 Read/WriteNew 均 `ErrUnsafe`，未新增成品；原有文件级 8.3 别名拒绝和 junction/ACL/no-replace 反例保留。卷未分配短名时记录 `short_alias_allocated=false` 并继续规范夹具检查，不冒称该次已执行真实 8.3 拒绝；本地三轮均实际分配了短名。

- `go test ./internal/integrity/privatefile -count=3 -v -cover`：Windows 全包三轮 **1.004s PASS**，**81.3%**，含真实 32 MiB 流、并发 no-replace、取消/回执、ACL/delete-child、junction、原短文件名反例和新增短 TMP/TEMP 基路径反例。
- `golangci-lint run ./internal/integrity/privatefile/...`：**0 issues**。
- 本地已复现同症状并证明夹具修复有效，**不等于已证明上述远端 CI 的唯一根因**；需主任务提交后由下一 Windows CI 确認是否还有其他问题。本单元不修改 Linux 代码，不把本地 Windows 结果当作新的 Linux 执行证据，也不是完整备份恢复验收。

本轮冻结文件：`internal/integrity/privatefile/file_windows_test.go`、新增 `tempdir_windows_test.go`、该包 README、本文档；管理自然到期修复的三个文件继续保持冻结。未 Git 提交或推送。
