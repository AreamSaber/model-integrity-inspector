# M6-05 PostgreSQL 导出 TLS / CRL 策略与证据

日期：2026-09-09。开发切片，不是 M6-05 完成或 TL / OPS / SEC 批准。

## 确认的问题与实现边界

PostgreSQL `REL_18_6` 的 [fe-secure-openssl.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/interfaces/libpq/fe-secure-openssl.c) 表明：system roots 分支没有执行 CRL 加载；普通 CA 文件分支加载 CRL 失败后清空 OpenSSL 错误并继续。只传入 `PGSSLCRL`、检查路径存在或拒绝 stderr 都不能证明显式撤销策略生效。

同版本 [fe-connect.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/interfaces/libpq/fe-connect.c) 的 `pqGetHomeDirectory` 在 Unix 上可由 `getpwuid_r` 得到账户目录，Windows 使用 `SHGetFolderPath(CSIDL_APPDATA)`。因此移除 HOME / APPDATA 环境变量不等于隔离默认 `root.crl`。

本模块提供私有 `validateCRL(c Connection) bool`，已接入 `validConnection`。无显式 CRL 时不增加验证义务；子进程环境明确使用 `PGSSLCRL=os.DevNull`，由固定版本真实 TLS 测试验证该哨兵阻止默认选择。有 CRL 时：

- 拒绝 `RootCertificate=system`；不能把显式 CRL 静默降级为系统根证书验证。
- CA 文件和 CRL 文件分别最多 4 MiB，读取使用有限 reader，并检查实际大小、mtime 和关闭错误；每种材料最多 32 个 PEM block。不接受 DER-only CRL、PEM 前后垃圾、混合类型或 PEM headers。当前文件型 libpq/OpenSSL 加载路径使用 PEM；不借由 Go 支持 DER 就宣称子进程同样支持。
- 仅接受完整、直接发行者 CRL。每个配置 CA 必须有恰好一份 CRL；CA 具备 CA/basic constraints、CertSign/CRLSign、SKI，且当前有效。每份 CRL 必须 issuer / AKI 匹配、验签成功、时间有效、CRL number 非负且有限。
- 拒绝重复或歧义 issuer、重复撤销 serial、无效时间/serial/reason，以及 delta、IDP（含分区/间接语义）、freshestCRL 和未实现扩展。完整直接 CRL 支持仅 keyIdentifier 形式的 AKI、CRL number，以及条目 reason code，要求已知扩展的完整规范 ASN.1，不接受解析器可能忽略的尾随内容；不是任意 PKI 策略解释器。Number / serial 限制为非负 DER INTEGER 的 20 octets（最多159 value bits），而非忽略符号填充字节的160 bits。
- 证书链的所有 CRL 发行者需出现在显式 CA bundle 中。单个叶证书发行者的 CRL **不能**证明完整链。即使配置预检通过，真实 libpq 的 CRL_CHECK_ALL、服务器证书身份/链验证仍必须成功；未提供的中间发行者不能靠此预检自动补全。

操作者/协调器负责可信的 TLS 材料位置及在整个子进程期间不变；本 bool 预检不授予文件 capability、不防拥有相同 UID / 管理员或运行代码控制权的对手。系统根+CRL、交叉签名歧义、分区/间接/delta CRL 属于明确不支持而拒绝的输入，不能在未来 DSN 适配层丢弃后继续连接。

## 测试设计

默认纯测试 `TestTLSCRL*` 使用运行时生成的 ECDSA CA 与签名 CRL，验证直接/多级发行者、缺链、错误签名、时间、扩展、serial、PEM、文件及精确容量边界。不把写入任意字符串的假 `.pem` 文件当有效 CRL。

`tls_integration_test.go` 受 `//go:build pgbackup_integration` 约束，入口 `TestPGBackupTLS*`；显式执行该 tag 时缺少 `MII_TEST_PG_DUMP` 或工具不符合 18.6 必须失败，不 Skip。

集成测试使用自建回环 TCP 端口，处理 PostgreSQL SSLRequest 后进行真正的 TLS 握手。只有收到了经过 TLS 的有界 PostgreSQL StartupMessage，才认为固定 pg_dump/libpq 接受该服务器证书；仅服务器握手函数返回成功不够。端点不会完成数据库认证或执行 SQL，Dump 必须失败且没有备份 receipt：这些测试证明 TLS 策略，**不证明 pg_dump 成功或恢复成功**。

计划/代码覆盖：无显式 CRL 的哨兵、有效空 CRL、撤销叶证书、撤销中间 CA、缺少发行者 CRL、坏 CRL 被原生 libpq 忽略的真实负控以及产品预检拒绝、system roots+CRL 预检拒绝。Linux 用子进程专属临时 HOME 放置撤销列表，对比移除/保留哨兵；不修改真实用户目录或父进程 HOME。Windows 不修改真实 APPDATA/Profile 文件，只证明显式哨兵的真实握手与策略，并保留默认目录行为的源码证据，不声称执行了真实用户默认文件负控。

## 当前执行证据

- 纯策略最终三轮：`go test ./internal/integrity/pgbackup -run '^TestTLSCRL' -count=3`，**0.761s PASS**。包括真实签名的重复 CRL number 反例，以及 Go parser 后的已知扩展 ASN.1 完整消费检查。
- 首次真实工具测试失败在版本探测之前：最小环境下 pg_dump 没有 stdout / stderr。普通终端固定工具 `--version` 确认为 18.6；独立隐藏原生进程对照使用相同最小环境，退出码 **0xC0000135 / DLL_NOT_FOUND**。随后主任务授权由原生进程 agent 为固定工具目录补齐经过来源、签名、架构及哈希验证的 app-local VCRUNTIME140.dll；本 TLS 单元没有恢复整个继承 PATH、复制未知 DLL 或放宽版本校验。依赖配置记录由该单元维护，不能把最初失败写成版本本身不符。
- 固定工具依赖补齐后，`go test ./internal/integrity/pgbackup -tags pgbackup_integration -run '^TestPGBackupTLS' -count=3 -v`，**Windows 原生三轮 3.495s PASS**。真实验证无 CRL 哨兵、有效 CRL、撤销叶证书、完整发行者链及撤销中间 CA；证实坏 CRL 直接交给 pinned libpq 时仍到达 StartupMessage，而产品预检阻断；system roots+CRL、缺发行者 CRL 在连接前拒绝。所有测试始终要求 TLS-only 端点不会生成备份 receipt。
- 缺工具负控：清空仅测试子进程的 `MII_TEST_PG_DUMP`，同 tag 实际 **exit 1 / 0.382s**，没有 Skip。错误工具负控：明确指向同目录真实 pg_restore 18.6，版本探测实际 **exit 1 / 0.455s**（stdout 30 bytes、stderr 0、grammar=false）；不把同版本的另一个工具误判为 pg_dump。负控驱动检查了预期失败码。
- 带 `pgbackup_integration` 的 Windows vet、包级 lint **0 issues**。最终 Linux tagged 测试二进制交叉编译、vet、lint **0 issues**；制品 `.tools/pgbackup-tls-linux.test` 仅编译，未在本机执行。真实 Linux 的临时 HOME/default root.crl 对照与执行器行为仍等待新增 CI 原生 job，不能追认默认 CI 或本地 Windows 成功为 Linux 成功。

复现（Windows，canonical 路径，固定工具已补齐）：

```powershell
$env:MII_TEST_PG_DUMP='D:\Tokens-Test\Tokens-Test\.tools\postgresql-18.6-3\pgsql\bin\pg_dump.exe'
.tools/go/bin/go.exe test ./internal/integrity/pgbackup -tags pgbackup_integration -run '^TestPGBackupTLS' -count=3 -v
```

本切片不修改现有 PostgreSQL 数据库、真实用户 TLS 文件、正式审核记录或 Git 状态。完整导出、新库恢复、同快照 inventory、DSN/TLS 配置适配、系统管理入口及全产品验收仍由主线持续完成。
