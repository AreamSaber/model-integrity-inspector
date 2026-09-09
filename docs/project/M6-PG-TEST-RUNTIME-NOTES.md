# M6-05 Windows 本地 PostgreSQL 测试运行库

开发配置已实现；正式审核待 V1.0 统一审核。本配置不是生产运行库分发方案，不标志完整备份恢复开发完成。

## 实际问题与修复范围

固定 EDB PostgreSQL 18.6-3 `pg_dump.exe` / `pg_restore.exe` 在不继承 PATH 的最小环境中启动失败，原生退出码 `0xC0000135`（DLL_NOT_FOUND）。本机 System32 没有 VCRUNTIME140.dll；平时终端能运行，是因为 ambient PATH 恰好包含 Codex 已安装原生依赖的运行库目录。

PE 导入表确认 `pg_dump.exe`、liblz4.dll、libcrypto-3-x64.dll 依赖 VCRUNTIME140.dll。添加 WINDIR 不能解决；显式提供所定位运行库目录时，最小环境能输出 exact 18.6。没有因此放宽产品进程执行器的环境隔离。

新增脚本只把操作者明确指定、已经安装且通过真实性检查的 DLL 放到本工作区固定的 `.tools/postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll`。不下载 DLL，不修改 System32、注册表、机器或用户 PATH，不启动 / 重启 / 连接 PostgreSQL 服务。

## 实际来源

本次显式使用的已安装依赖：

- 来源：`C:/Users/Camellic/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/libheif/libheif/bin/vcruntime140.dll`。
- 大小：178,616 字节；PE machine：x64（0x8664），PE32+ DLL。
- 文件版本：`14.51.36247.0`。
- SHA-256：`d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7`。
- Windows Authenticode：`Valid`，签名主体为 `Microsoft Windows Software Compatibility Publisher` / `Microsoft Corporation`。
- 签名证书 thumbprint：`2650247AC56048BC7928663C02733D25898A1D6E`（记录实际观察，不作为绕过系统证书验证的替代）。

SHA-256 是对该已安装、签名验证通过文件的本地观察 pin，不冒充厂商发布的独立校验和。

```powershell
./scripts/prepare-pg-test-runtime.ps1 -RuntimeLibrary 'C:/Users/Camellic/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/libheif/libheif/bin/vcruntime140.dll'
./scripts/tests/test-pg-test-runtime.ps1 -RuntimeLibrary 'C:/Users/Camellic/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/libheif/libheif/bin/vcruntime140.dll'
```

## 真实检查与失败处理

- 参数必须显式给出本地绝对路径；拒绝 UNC/device 路径、ADS、控制字符、错误文件名、非普通文件、reparse 和多个硬链接。文件大小有 4 MiB 上限。
- 验证 PE header / x64 / DLL 标志 / 版本，实际调用 Windows Authenticode 并确认微软 signer，最后核对字节 pin；没有签名 mock 或失败后降级。
- 从卷根逐级打开 source / target 祖先目录，检查实际 handle 非 reparse，并持有到复制与核验结束。目录使用 LIST_DIRECTORY | READ_ATTRIBUTES、共享 READ/WRITE 但不共享 DELETE。实测曾发现 metadata-only READ_ATTRIBUTES 不能防止 rename；增加 LIST_DIRECTORY 后，真实 rename 回归由红转绿。
- 源文件在校验与复制期间保持禁止写入 / 删除的只读 handle。固定目标用 CreateNew 创建；已存在时仅允许同 hash、同 pinned 签名与版本的复用，拒绝覆盖不同文件。复制后再次验证目标字节和签名。
- 同时实际执行固定 pg_dump / pg_restore 的 `--version`：隐藏进程、stdin EOF、完整替换环境仅 LANG=C / LC_ALL=C / SystemRoot（无 PATH），stdout / stderr 各最多 256 字符，有界等待；必须 exit 0、stdout exact 18.6 单行、stderr 为空。
- 如复制 / 版本验证失败，不把残留标记成功，不自动覆盖或删除已有 DLL。操作者需要先检查失败原因；没有 `-Force` 绕过入口。
- 实际来源、hash、版本、签名及两个工具结果保存于 ignored `.tools/postgresql-18.6-3/local-runtime-provenance.json`。已有不同 provenance 不覆盖；相同记录可复用。

初次真实执行成功（`reused=False`），后续入口复用保持 DLL hash、creation time、last-write time 不变。回归共有 15 项，覆盖真正 unsigned DLL、x86 machine、错误名称、超长 / 损坏文件、relative / ADS、目标越界及前缀假冒、source / target junction、不同既存目标、目录 rename 锁定和真实版本探测；不操作数据库。

## 许可证与正式部署边界

微软官方说明 app-local DLL 部署在技术上可行，但 Visual C++ 文件再分发受许可证限制，且更推荐正式 redistributable 作为部署前置，以便统一维护安全更新。此次操作只是复用本机已经安装的依赖配置本地开发测试，不构成取得产品再分发授权；DLL 和 provenance 均不得提交 Git 或打入候选 / 发布制品。[微软官方部署与许可证说明](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)

生产 Windows 部署仍须明确官方 Visual C++ runtime 前置条件、安装授权与更新维护责任；该外部授权不能伪造为完成。
