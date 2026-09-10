# M6-05：可实际加载的安全备份配置模板

2026-09-10。依据 PRD SYS-008、TECH SPEC 19.5、已批准 ADR-0004/0005，以及
实际 `internal/app/config.go` 和 `secret/keyring_files.go`。本单元实现配置载体，
不等于完整备份、匹配密钥认证、恢复隔离、启动授权或正式审核通过。

## 真实配置来源与安全投影

新增私有 `newBackupConfigurationTemplate(ctx, Config)` 从已验证的内存配置
构造新模板；不读取原配置文件、`.env`、环境变量、密钥文件或任何业务数据库。
Config 本身仍禁止格式化泄漏及 JSON/YAML 序列化。

只保留实际部署角色（all/server/worker）、数据库类型及 active/previous 的
密钥版本标签。active 不参与历史排序；历史版本独立排序，原 slice 不改动。
版本沿用现有严格规则、大小写语义和最多64份（active+previous）的上限。

| 字段 | 生成内容或处理方式 |
| --- | --- |
| enabled / queue / key source | true / database / file，现有实际支持的后端 |
| role / database provider | 来自合法源配置；SQLite 仍只能 all |
| listen / public origin | 固定 `127.0.0.1:8080` / `https://restore.invalid` |
| allow_insecure_loopback | 固定 false，不继承开发 HTTP 例外 |
| DB / reports 路径 | 固定 `./data/mii.db` / `./reports` |
| active key 路径 | 固定 `./keys/master.key`，不由版本拼路径 |
| previous key 路径 | 按排序后的标签生成 `./keys/previous-0001.key` 等编号 |
| DSN / setup env 名 | 固定 `MII_DATABASE_DSN` / `MII_SETUP_TOKEN`，无变量值 |
| 源 DSN / setup token / 文件路径 / origin / listen | 全部不复制 |
| Build 身份 | 不复制到配置；最终归档 manifest 必须另行绑定实际构建身份 |

这是一份显式需要重新配置环境的迁移模板，不是原环境配置的可直接启用副本。
操作者必须另行提供新数据库凭证、匹配的各版本密钥、适用的 HTTPS origin 和部署
路径；不能在恢复校验/隔离门禁之前调用正常 app.prepare（它会迁移、初始化及
启动 Worker）。模板的 role 或 enabled 值没有解除门禁的权限，后续协调器必须
独立强制隔离、只读验证、显式激活。

配置版本列表也不是数据库实际密钥依赖清单。最终协调器还必须结合快照观察的
历史引用和实际 archive sealer 版本，验证所有必需主密钥以及 Secret/S1/S2/审计等
认证；不能用此模板跳过缺失历史版本、自动重签或声称密钥已可解密。

## 格式与验证

- 固定 `# mii.backup-config-template.v1` 头，规范 YAML，总输入/输出≤64 KiB。
- 复用真实 fileConfig 的字段结构。`KeyFileReference.MarshalYAML` 继续拒绝输出，
  编码先处理不含旧 key 元素的安全字段树，再用仅含标签/生成路径的私有 wire
  元素填入序列；绝不削弱原类型的保护，也不直接序列化原 operator references。
- 验证先匹配独立期望 SHA-256，再只解析有界 YAML 语法树；拒绝 alias/anchor、
  超深（16）/超节点（2048）/超长 scalar（256），不展开引用构造类型对象。
- 随后使用实际 fileConfig + KnownFields，在零值上解码，不调用 defaults 或
  environment 填字段；只提取允许保留的四类标量，重新构造全部固定字段并比较
  整个规范字节。缺省/NULL/重复/大小写别名/unknown/自定义tag/额外文档/尾注释/
  字段重排/路径/env 名/安全布尔改变均不能通过自重算 hash 绕过检查。
- 私有载体只有显式 Bytes（自有副本）与 SHA256；值和指针的 fmt/slog 固定
  脱敏，隐式 JSON/YAML 均失败。ctx nil/入口取消/构造和验证中途取消无候选。
- 自提交的 hash 仅证明一致性，不证明来源；必须由最终已认证 manifest 和外部
  锚点约束，且整个归档末尾认证完成之前不得发布已读到的配置候选。

原 SPEC19.1 中尚未接入实际 LoadConfig 的 worker/network/storage/defaults
设置不能被写成貌似能加载的字段。那些原要求仍在全 Goal 范围中，后续实现时须
同步实际配置、模板协议/测试与升级兼容；当前载体不把它们宣称为已实现。

## 真实验证

- 新配置专项首次三轮 **0.547s PASS**。最终新旧配置（含历史 key 配置）组合
  三轮 **0.643s PASS**，新配置专项另三轮 **0.606s PASS**，单轮 **0.294s PASS**。
- 在合成新目录真正写出生成模板并调用实际 LoadConfig，覆盖 SQLite/all 及
  PostgreSQL/all/server/worker，明确注入合成新 DSN；无 DSN 的 PG 模板失败。
  校验全部重定位路径、active与排序历史的对应关系，以及没有创建 DB/key/report
  文件。这里验证的是配置加载器，不冒称 PostgreSQL 连接或数据库恢复测试。
- 0..63 historical +1 active 全部 round trip，65份拒绝；源路径/口令/DSN/
  endpoint/Build canary 不在输出；原 slice 及 Bytes 返回值修改不影响载体。
- 30余种自重算hash的坏模板、错误独立hash及真实 context 取消边界通过。
- 真实 KeyRing/BackupSealer/BackupOpener 的 AEAD 组合：有效配置往返，合法认证
  但不安全的模板仍拒绝；错误 key、归档尾截断及尾追加失败。测试使用明确的合成
  scope，不伪称已经生成全数据库 manifest 或实现生产恢复协调器。
- Fuzz **5,636 executions /6.308s PASS**。本地 app vet/lint 退出0、0 issues；
  Linux amd64 CGO0 交叉 vet/lint 同样退出0，不能当原生Linux/真实容器运行。
- 新配置测试的包级覆盖是整个 app 包的45.6%，不能标为模板覆盖率；生产模板的
  verify 函数覆盖98.0%，constructor90.0%，编码器83.3%。未用覆盖率代替行为证据。
- 固定 SQLite/all、active=v3、previous=v1/v2 的 v1 载体 **689 bytes**，SHA-256
  `6fefae6c170bf5f1220d603ce76411a8151caed2f97d3177d8383874068086ec`。

开发中 lint 曾指出 EOF 分类及 nil Context 测试写法，已改 errors.Is 和明确空
context 变量，未跳过规则。一次未引用的 PowerShell cover 参数未产生预期输出，
之后使用完整引用参数实际生成并读取 `.tools/backup-config-coverage.out`；不把
失败的覆盖率读取当成成功证据。

独立只读复核未发现P1/P2，纯专项三轮0.434s通过；指出末尾异常测试未锁定“已读到
合法配置后失败”的阶段证据。已补两个尾异常场景的 tentative 真实字节一致与零
archive receipt 断言，不能仅凭任何提前失败通过该测试。该项是测试证据加强，
不是冒称发现并修复了生产认证漏洞。
最终包含该加强的全部新旧配置组合三轮 **0.754s PASS**，app vet/lint退出0、
0 issues。三份代码文件及本notes作为独立单元提交，不混入在途Windows HTTP诊断。

后续必须将真实模板文件加入公共条目/字节预算及 manifest.ConfigTemplate，接
安全归档/隔离恢复/CLI/HTTP/Web/干净环境演练；M6-05 仍进行中，正式审核待统一。
