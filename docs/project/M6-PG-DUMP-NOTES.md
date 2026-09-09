# M6-05 固定 PostgreSQL dump 工具与流式收据

开发单元已实现并有本机 Windows 真实工具证据；不是 SYS-008 备份恢复入口、完整恢复协调器或正式审核通过。Linux 原生结果须由新增 CI 独立确认。

## 工具边界

`internal/integrity/pgbackup/dump.go` 只运行受信操作者指定的绝对普通文件，不搜索 PATH、不经过 shell。每次先有界执行 `--version`，必须为 PostgreSQL **18.6**（允许有界发行版后缀）；随后固定 custom/uncompressed/UTF8/non-parallel 参数，明确选择完整专有数据库或精确大小写 schema。没有允许任意附加参数的入口。Snapshot 仅允许有界三段大写十六进制 token，schema 不接受模式元字符。

连接是可信应用适配器提供的显式结构，不是一般 DSN 解析器；用户名、数据库、单一 host、端口、密码、TLS/CA/客户端身份、CRL 和 channel binding 都经过限制。适配器必须确保它与导出快照的源 Store 为相同数据库、认证和 TLS 策略；本组件不能仅凭字段形状证明这个前提。密码只进入显式子进程环境，不进入 argv、错误或日志；同用户/root 的进程检查不是本边界能够隔离的威胁。

工具和连接环境完整替换，仅保留明确的语言/SystemRoot和PG参数；不继承 PATH、HOME、APPDATA、PGSERVICE、PGOPTIONS、PGPASSFILE、preload 或 OpenSSL 配置。没有 TLS opportunistic fallback；根信任和客户端身份必须显式配置。默认 CRL 通过空设备显式隔离，严格 CRL 预检和真实 TLS 握手证据见 [TLS 单元](M6-PG-TLS-NOTES.md)。路径来自可信操作者且执行期间必须保持稳定，本层不宣称取得了可防同用户替换的文件能力。

`ApplicationName` 仅允许内部协调器提供 `mii-backup-` 加128位随机nonce的32位小写hex；不允许用户自定义名称或从父进程继承。该名称便于协调器跟踪会话，不是权限凭证。

## 输出与错误

- 原生执行器拥有本地进程/后代生命周期，详见 [原生进程边界](M6-PG-PROCESS-NOTES.md)。本地进程结束不等于数据库服务端会话结束，后者由 repository 会话协调器负责。
- stdout 采用有界流，累计实际写入字节、SHA-256和PGDMP头；最大支持1TiB，调用者须给出更具体容量和最大24小时的context deadline。本机回归实际使用64MiB上限和26MiB逻辑载荷。
- 任意stderr内容（包括exit0警告）、非零退出、错误版本、取消、容量溢出、短写、writer错误或panic均不能产生成功收据；错误为闭集值，不保存原始stderr或writer错误文本。失败后调用者必须丢弃所有部分输出。
- 成功收据仅证明此次固定工具进程和输出流已完成，不是认证归档或恢复批准。仍须等待源快照事务最终成功、私有输出关闭/同步/复核、完整清单/权限/维护门禁及归档认证后才能发布。
- writer 必须是可信且能及时返回的存储回调；不能保证中断任意卡在用户Go代码或底层存储的writer。没有把内部函数直接暴露为HTTP命令执行接口。

## 实际验证

root 用显式的 pinned 工具环境执行完整 pgbackup 包，`-tags pgbackup_integration -count=3 -timeout=3m`，**22.307s PASS**：原生进程、显式连接/参数/隐私、CRL纯层、真实TLS/撤销/默认CRL隔离全覆盖。对应tagged vet/lint均0；此结果不是Linux原生或全产品测试。

repository 的真实三个顶层测试三轮 **16.690s PASS**：

1. 导出只读快照后，由不同连接追加审计并更改/插入数据；真实26MiB+全库dump、独立文件SHA、pg_restore进全新库，核对迁移账本、26行/26MiB/逐行原数据和同快照整链审计锚点，同时确认源库独立晚提交确已存在。
2. 精确大小写schema匹配只包含指定对象；真实限额、写失败、错密码和已结束exporter的失效token均返回失败且零收据。失效token测试发生在源库仍存在时，不靠删除数据库制造连接失败。
3. 实际观察到服务端Lock等待后取消，要求本地与精确服务端会话清理，原2秒断言不变；fixture锁只在确认后释放。快照外层保留sticky取消错误，不能吞错后成功。

早期相同测试发生过DROP检查点超时和“只杀本地客户端、未清理服务端”的真实失败；不得用正文通过掩盖失败。夹具已调整为完成全部源断言后先释放源测试库，再创建恢复库，原10秒清理期限/fsync/数据量不变，见 [清理诊断与红绿证据](M6-PG-DUMP-FIXTURE-NOTES.md)。后续控制连接恢复和身份边界修改须另记最终组合结果，不由上述旧运行追认。

尚未完成：全产品业务/文件/配置inventory、认证归档发布、隔离恢复/激活、CLI/HTTP/UI、独立Linux原生CI及完整灾备演练。M6-05与Goal仍进行中。

### 最终本地组合复核

扩大为审计/快照/所有 Dump 组合三轮曾真实失败（161.907s），定位在共享 General
cluster 的 DROP 检查点等待。改用独立固定 Backup cluster 后，root 以两套独立
DSN、相同测试选择/次数/5分钟总上限重跑：**108.814s PASS**。各 DROP 仍10秒、
取消仍2秒，fsync及synchronous_commit均实际确认on，原断言全部保留。

命令：`go test -tags pgbackup_integration ./internal/integrity/repository -run '^(TestPostgresSnapshot|TestSnapshotAudit|TestAuditSnapshot|TestPostgresDump)' -count=3 -v -timeout=5m`。
包含真实非超级用户双会话隔离、身份/权限拒绝、吞错失败记忆、一次受限控制
连接恢复及外层闭集错误保留。Backup复查无fixture数据库残留；异写URL指向
同一实际cluster的负控仍拒绝。Windows及Linux目标tagged vet/lint均0；
Linux目标静态检查不等于原生运行。root另重跑完整pgbackup tagged三轮
**22.959s PASS**，包括真实TLS、CRL和原生进程测试。
