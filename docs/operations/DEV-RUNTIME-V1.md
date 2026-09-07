# V1 持续开发运行入口

当前是功能持续集成版本，不是完整 V1/发布候选。初始化、登录、会话、组织读取和角色目录已接入实际数据库；检测执行、报告及完整管理仍在开发。`all`/`worker` 的执行组件尚未接通时 `/ready` 明确返回 503，不能用页面可访问冒充整体就绪。

## Windows 本地隔离启动

使用冻结的 Go 1.26.7 / Node 24.19.0 / pnpm 11.19.0。构建脚本先构建 React，再把产物通过 `webassets` 标签嵌入 Go：

```powershell
./scripts/build.ps1
./artifacts/mii.exe keygen --config ./config/config.example.yaml
./artifacts/mii.exe run --config ./config/config.example.yaml
```

`keygen` 只用于第一次生成：已存在文件会报错，绝不覆盖。原始主密钥恰好 32 字节，Windows 必须为受限 ACL 的普通文件；Unix 必须 owner/root 所有、0400/0600，拒绝链接。备份时主密钥与数据库分开保管。启动前必须安全加载主密钥，再创建 SQLite、执行迁移、完整验证所有组织的审计链。损坏/缺失密钥不能自动替换。

访问 `http://127.0.0.1:8080`，完成首个组织和管理员初始化后单独登录。普通后端 `go test` 不依赖已生成前端；未带 `webassets` 的二进制对前端请求明确返回“未构建”，发布/打包脚本必须带标签，不能交付该测试变体。

## 配置与远程部署边界

`--config` / `MII_CONFIG` 可指定 YAML；未指定则使用 loopback SQLite 默认值。文件最多 64 KiB，只允许一个 YAML 文档，未知字段/未实现的 adapter 配置直接拒绝。路径相对配置文件，未指定配置文件时相对工作目录。不会执行环境变量插值或模板。

可覆盖：`APP_ROLE`、`MII_ADDR`、`MII_PUBLIC_ORIGIN`、`MII_ALLOW_INSECURE_LOOPBACK`、`MII_DATABASE_DRIVER`、`MII_DATABASE_PATH`、`MII_MASTER_KEY_FILE`、`MII_MASTER_KEY_VERSION`。数据库 DSN、初始化令牌只从 `dsn_env` / `setup_token_env` 指定的环境变量读取，不允许在普通 YAML 中存放值。默认名称分别为 `MII_DATABASE_DSN` / `MII_SETUP_TOKEN`。

SQLite 只允许 `APP_ROLE=all`。PostgreSQL 允许 server/worker/all；server/all 执行带锁迁移，worker 只检查版本，不能自动迁移。原有迁移不可编辑，每次变更新增迁移。

远程使用 HTTPS 反向代理、明确的 `public_origin` 和 `allow_insecure_loopback: false`。管理 HTTP 不自带 TLS 终结器；禁止把本地测试配置直接暴露公网。反向代理应保留 Origin，应用不信任 `X-Forwarded-For` 以绕过首次引导或 IP 限速。首次初始化要求用户输入与 `MII_SETUP_TOKEN` 匹配的至少 32 字符随机引导令牌，初始化后入口永久关闭。引导令牌不会保存到数据库，只保留运行期 hash；可在初始化后移除环境变量并重启。

新增 YAML 依赖固定 `go.yaml.in/yaml/v3 v3.0.5`，使用仍接收安全修复的稳定 v3，不采用当前 v4 RC。维护状态依据 [YAML 官方维护说明](https://github.com/yaml/go-yaml#version-intentions)；版本与校验和固定于 go.mod/go.sum。

## 已执行验证和限制

- SQLite 与真实 PostgreSQL 18.6：初始化、登录失败/成功审计、密码哈希、会话/CSRF、改密撤销、租户隔离以及 HTTP 失败路径测试。
- 应用：真实 HTTP 初始化 → 停止 → 重启读取原数据 → 完整审计验证。
- 浏览器：隔离 loopback18080 的 Go 嵌入前端，初始化页显示、后端初始化、真实浏览器登录/组织/角色读取/退出；控制台无错误或 CSP 警告。390×844 视口 DOM 无横向溢出。
- 纯注释以分号结尾的迁移解析回归，防止 SQLite 对无 SQL 的 Exec 返回 nil 结果触发异常。
- Windows 密钥 ACL/junction/hardlink 回归通过；Unix 实际执行和 Go race 纳入 Linux CI，不能用交叉编译代替它们。

浏览器测试使用 `.tools/v1-smoke` 的独立合成账号/数据，不涉及真实上游或现有生产账号。实际 PostgreSQL 测试运行时也位于忽略目录；`scripts/test-postgres.ps1` 只管理带本项目标记且路径/PID 匹配的隔离进程，不安装系统服务。

CI 现增加固定 digest 的 PostgreSQL18.6 服务与双库 race 命令；远端结果必须等实际 workflow 完成后记录。Docker/完整 Compose/全链路检测仍未在本地完成，不能据此声明交付通过。
