# V1 持续开发运行入口

当前是功能持续集成版本，不是完整V1/发布候选。初始化、登录、会话、用户/组织/成员管理、模型档案、目标、预检、检测执行、开发分析、结果、人工复核、组织基线及 JSON/HTML 报告页面已接入实际数据库和应用。可信基线评分、规则发布、其余页面及运维交付仍在开发。`all`/`worker` 只有真正取得消费者租约且首次心跳成功才就绪，停止或丢失消费者后不再就绪。`/ready` 还检查DB、schema与审计；运行组件就绪不代表整个V1开发完成。

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

可覆盖：`APP_ROLE`、`MII_ADDR`、`MII_PUBLIC_ORIGIN`、`MII_ALLOW_INSECURE_LOOPBACK`、`MII_DATABASE_DRIVER`、`MII_DATABASE_PATH`、`MII_MASTER_KEY_FILE`、`MII_MASTER_KEY_VERSION`、`MII_REPORT_PATH`。数据库 DSN、初始化令牌只从 `dsn_env` / `setup_token_env` 指定的环境变量读取，不允许在普通 YAML 中存放值。默认名称分别为 `MII_DATABASE_DSN` / `MII_SETUP_TOKEN`。

历史主密钥可在 `integrity.security.previous_master_keys` 中显式提供 `{version, file}` 列表；当前写入仍只用 `master_key_version` / `master_key_file`。旧配置无需改动。历史路径同样相对配置文件，必须满足原有受限ACL/权限、普通单链接文件及恰好32字节检查；列表没有环境插值、inline key或自动目录扫描。全部文件成功加载后才创建数据/报告目录，任一失败不回退为只有当前钥匙。版本区分大小写且不可重复（包括与环境覆盖后的当前版本重复）；当前加历史最多64个文件，是启动资源上限，不能为满足此上限删除数据仍需要的历史版本。

这只是多版本加载能力，不是已完成自动轮换或恢复校验。不要仅因新钥匙启动成功就移除旧文件：审计、Secret、响应证据及备份归档可能仍引用旧版本，完整恢复工具必须核对实际引用并执行解密/全链验证。主密钥文件及该带私有路径的运行配置不得原样放进备份，备份配置模板必须由闭集安全字段另外生成。

SQLite 只允许 `APP_ROLE=all`。PostgreSQL 允许 server/worker/all；server/all 执行带锁迁移，worker 只检查版本，不能自动迁移。原有迁移不可编辑，每次变更新增迁移。

远程使用 HTTPS 反向代理、明确的 `public_origin` 和 `allow_insecure_loopback: false`。管理 HTTP 不自带 TLS 终结器；禁止把本地测试配置直接暴露公网。反向代理应保留 Origin，应用不信任 `X-Forwarded-For` 以绕过首次引导或 IP 限速。首次初始化要求用户输入与 `MII_SETUP_TOKEN` 匹配的至少 32 字符随机引导令牌，初始化后入口永久关闭。引导令牌不会保存到数据库，只保留运行期 hash；可在初始化后移除环境变量并重启。

新增 YAML 依赖固定 `go.yaml.in/yaml/v3 v3.0.5`，使用仍接收安全修复的稳定 v3，不采用当前 v4 RC。维护状态依据 [YAML 官方维护说明](https://github.com/yaml/go-yaml#version-intentions)；版本与校验和固定于 go.mod/go.sum。

## 已执行验证和限制

- SQLite 与真实 PostgreSQL 18.6：初始化、登录失败/成功审计、密码哈希、会话/CSRF、改密撤销、租户隔离以及 HTTP 失败路径测试。
- 应用：真实 HTTP 初始化 → 停止 → 重启读取原数据 → 完整审计验证。
- 浏览器：隔离 loopback18080 的 Go 嵌入前端，初始化页显示、后端初始化、真实浏览器登录/组织/角色读取/退出；控制台无错误或 CSP 警告。390×844 视口 DOM 无横向溢出。
- 纯注释以分号结尾的迁移解析回归，防止 SQLite 对无 SQL 的 Exec 返回 nil 结果触发异常。
- Windows 密钥 ACL/junction/hardlink 回归通过；Unix 实际执行和 Go race 纳入 Linux CI，不能用交叉编译代替它们。
- 445d502远端CI run34081671291全绿：质量（含Linux双库race）、Windows/Linux打包、镜像扫描、依赖扫描与required；后续未提交功能不冒用该结果。

## 异步预检

以目标当前`version`调用`POST /api/v1/targets/{id}/precheck`，请求体`{"version":1}`，需要组织头、会话、CSRF和`target.precheck`权限。可提供`Idempotency-Key`（1～128字符，ASCII字母数字及`._:-`），同一组织相同键和相同目标版本返回同一记录；不兼容重用返回409。HTTP只原子创建数据库任务并返回202，不同步访问上游。

返回中的`id`/`job_id`/`target_id`均为字符串。通过`GET /api/v1/targets/{id}/prechecks/{precheckId}`轮询该条记录，或GET单数`/precheck`读取最新记录。没有记录时404，不返回虚构的通过结果。每个预检最多3次实际HTTP请求（含一次auto参数回退），每次请求声明16输出Token上限、响应上限64KiB、总执行上限60秒；这些客户端限制不能保证上游遵守参数或免除已发生的费用。未接通消费者时保持queued。真实上游可能计费，不属于免费连通性Ping；开发回归只使用受控TLS Mock。

预检只保存固定能力检查名、状态、错误码和计数，不保存上游正文/响应头。取消、目标禁用、配置/密钥版本变化或失租时停止继续外呼；已发出但结果未知的请求按不确定处理，不重复作为成功证据。预检通过仅代表连接/协议能力，不构成模型真实性结论。

浏览器测试使用 `.tools/v1-smoke` 的独立合成账号/数据，不涉及真实上游或现有生产账号。实际 PostgreSQL 测试运行时也位于忽略目录；`scripts/test-postgres.ps1` 只管理带本项目标记且路径/PID 匹配的隔离进程，不安装系统服务。

CI 现增加固定 digest 的 PostgreSQL18.6 服务与双库 race 命令；远端结果必须等实际 workflow 完成后记录。Docker/完整 Compose/全链路检测仍未在本地完成，不能据此声明交付通过。

## Run 开发链路与当前限制

目标列表可主动打开“配置检测”。`GET /api/v1/auth/permissions`返回当前组织/用户的实际持久权限；不从系统管理员标记推断跨租户授权。

`POST /api/v1/runs/estimate`接受当前目标版本、检测包及受限选项。在同版本预检通过后生成签名Manifest并保存10分钟、仅当前创建者可读的草稿；不创建Job，不解密凭证，不访问上游。Quick/Standard/Deep开发包分别为18/60/120逻辑样本，受预算/档案限制时按完整探针组缩减，明确partial。输入Token是保守预算估算；重试需要另外占用预算。自定义包必须指定探针种类、语言、重复次数，阶梯需递增档位；当前最多150逻辑样本。基线/early_stop/观察模式仍待M5，当前不得传入未实现选项。

`POST /api/v1/runs`只接受`estimate_id`、`manifest_hash`、`confirm_cost:true`，确认原冻结配置，不能在确认时改价格/目标/请求。目标、密钥、预检和模型档案版本及有效权限在创建事务中复验。一个草稿只有一个永久执行身份；未知POST结果可手动重试原body恢复同一Run，不自动重新估算或创建第二次执行。

已知双侧价格而未填金额时，普通默认冻结`min(管理员金额上限, 2_000_000微单位)`；底层策略对已知价格始终强制管理员金额上限，不能用null关闭保护。最终冻结配置超过60请求、50,000 Token或2,000,000微单位，以及deep包，需要`run.high-cost`；custom另需`run.custom`。管理员进一步收紧后按实际可执行预算授权。价格未知或仅有单侧价格时金额为null，明确**金额未受限，仅受请求/Token/时间预算约束**；不能设置金额预算，不能冒称免费或金额有界。

无完整模型limits时采用context4096/output1024的保守开发假设并提示，不冒称供应商声明；可信运行时Tokenizer不由模型档案的quality声明替代。配置引用和声明值纳入签名Manifest，旧Run不会随当前目录改价而重估。

RunPlan/SampleExecute Worker已经接入SafeHTTP、流式/非流式Adapter、实际Token计算及每次Do前的独立预算预留。S2响应使用purpose-separated密钥及org/run/sample/attempt/request-hash AAD加密，与Attempt/Job/样本同事务提交；封装上限1MiB，超限不保留伪完整响应。失租、取消或目标轮换停止外呼；DISPATCHED未知结果按UNCERTAIN恢复，不重发猜测成功。

连续最终样本的认证失败2次、模型不存在2次、协议失败5次触发熔断，停止新请求、取消在途网络、保留已收到的有效证据。成功/其他类别打断连续，重试不重复计数；同Run行锁分配完成序号。**2/2/5是未校准开发运行策略，不是正式算法判定阈值**。旧数据迁移只采用完成时间/id确定性回填顺序。

过期草稿按每批最多100条清理并原子记审计，确认后的Run自己保留签名执行快照与owner/hash回执。创建新草稿前也清理该用户过期记录，因此不依赖Worker在线来避免持续堆积。Worker通过同一个消费者执行周期清理；不打开第二个SQLite消费者。已删除的未确认草稿返回404；过期但尚未清理的草稿返回409。TTL清理是自动生命周期行为，不表示创建者进行人工审核或删除操作。响应证据的完整组织保留策略和清理仍待M6，目前固定开发保留期30天，不宣称完整生命周期已交付。

RunAnalysis 现已接入真实处理器：读取受租约保护的冻结执行快照和最终 Attempt，验证 Manifest、模板、tokenizer 与响应 AAD，生成 S1 特征、四维风险、开发置信度和 Finding。结果 revision 1、Finding、Run 终态、Job 完成与审计在同一事务发布；失租或审计失败全部回滚。失效/过期证据不补造正文或正常分；无有效证据时为 insufficient/D。永久失败的分析 Job 收敛为 FAILED，保留原执行计数和诊断码。

启动会验证内置开发规则 `1.0.0-dev.1` 的冻结 SHA-256、模板内容哈希与 tokenizer 字节，并核对实际特征、评分、行为、结构和生成器版本。首次初始化和新组织创建在同一事务写入组织专属规则/模板记录；旧组织由 server/all 启动时按 100 个组织一批补登记，每个组织独立事务、幂等且带审计。worker-only 不补登记。相同版本不同字节会失败，不覆盖已有记录，不重新启用已退役版本。

该登记只表示 **development / 未校准**：规则无 PublishedAt、无回放指标或人工批准，公开模板标记 public；自动补登记的审计主体表示生命周期归属，不表示该用户审核了算法。评分最高 C（有效性不足为 D），置信度未校准上限74、partial上限59。成对比较四项 BH 是探索性统计，不是独立盲验收或可信基线证据。

创建估算和确认的数据库事务复验当前包版本、哈希和实际 JSON 字节。部署变更导致新草稿规则/评分不受支持时返回 `MI_RUN_ESTIMATE_STALE`；已确认草稿仍能恢复原 Run 回执，不创建第二次执行。当前只支持此开发版本的新任务，历史版本解析、重分析及正式规则发布仍待 M5。

结果/历史 API 和页面已接通，**运行时确认现按实际 readiness 开放**，不再无条件返回 `MI_EXECUTION_NOT_READY`。all 模式要求消费者就绪；PostgreSQL server 模式在数据库/schema/审计就绪后可以入队，离线 Worker 不会凭空执行。原有权限、费用确认、版本、签名和包内容准入仍必须通过。该能力可能产生上游费用，开发与浏览器验证仅使用受控 TLS Mock，没有调用真实付费接口。

`internal/app/pipeline_test.go` 使用真实应用初始化、登录、目标、TLS 预检、报价、确认、Worker 执行及分析发布，再经 HTTP 读取历史、固定修订结果、统计、样本/Attempt 和 Finding，SQLite 与独立 PostgreSQL schema 均通过。上游替换仅发生在不可由 YAML/HTTP 设置的私有测试网络注入，实际分析处理器和数据库路径没有替换。可运行 `go test -tags webassets ./internal/app -run TestApplicationActualTLSFromInitializationThroughPublishedEvidence -count=1`；未配置隔离 PG DSN 时会明确跳过 PG，而不算双库通过。

2026-09-07 实际浏览器使用该测试的短期 hold 模式：真实登录→已有历史→revision 1 总览→Token→行为→S1 Finding/Attempt→退出均通过，未出现控制台错误或 CSP 警告；390×844 窄屏总览无整页横向溢出，测试结束已恢复视口并清理应用临时数据库。此浏览器轮次从已由测试完成的检测读取结果，不冒称浏览器点击了全套创建/确认流程。报告和实际多作业并发容量仍需后续完成。

## 历史与固定修订证据

`GET /api/v1/runs` 支持目标、状态、检测包、当前模型/渠道、风险、日期与文本筛选，按 created_at/id 倒序，签名游标绑定用户、组织及过滤条件。当前目标名称/模型不是历史快照，目标删除后保留原 target_id，页面明确区分。分页锚点不随可变状态或筛选字段变化而失效。

结果路径 `/runs/{id}/result` 固定 `analysis_revision`（当前仅 1），无该修订返回404；默认只需 run.read。`include=statistics` 及 `/findings`、`/samples`、`/samples/{sampleId}` 额外要求 evidence.read。所有读取在一致数据库快照内复验持久会话及角色权限；SQLite 使用只读 DEFERRED 事务，不为轮询申请写锁；PG 使用 REPEATABLE READ。SQL 先限制文本字节和行数，再严格解析闭集 S1 投影，拒绝无效修订、版本、样本分母、引用或结构。正文、请求变量、凭证与密文均不进入这些接口。

页面提供四维风险、置信度、C/D、未校准/公开开发模板声明、全量档位统计、仅当前样本页的散点、探索性成对 BH、最终 Attempt 与非独立重试。缺失指标为 null，不记作0。切换组织/用户/Run 清空旧状态；重新读取不会重新调用上游或修改分析。完整两任务对比、可信基线评分和重分析尚未实现；组织基线与报告后端见下文。

这些结构/交叉字段检查不能替代密码学对象认证：具有任意数据库写权限的人如一致地重写文档及关联列，不保证由只读结果接口检出。正常发布路径受 Job fencing/不可覆盖事务和审计约束，审计 MAC 保护的是审计事件，不能宣称同时认证了整个结果正文；更强对象封印需单独实现。

两任务对比：从历史选择两条已有结果，或进入“任务对比”输入两个不同Run ID。页面每次固定读取一次权限、两份Run和两份revision1结果，核对身份、冻结版本、终态与样本计数，任一失败不保留半边。展示四维/综合风险、置信指数、分母、等级和版本的描述性右减左；缺失保持null。目标/检测包/Manifest或版本不同必须提示限制，同版本也不证明可归因行为。它不是趋势统计、显著性检验、可信基线或两Run差异报告导出。

## 组织总览统计

真实后端 `GET /api/v1/overview?days=7|30` 在同一个授权只读快照中汇总组织当前目标及日历窗Run；需要run.read和target.read。窗口遵循组织UTC/IANA时区，今日是partial，按Run创建时间划分而非Attempt/完成时间。风险按检测包/四个冻结版本分层，未知成本和不可估风险不当零值；已删目标的历史Run仍参与窗口。

窗口Run和当前目标各10000、16 cohort、256KiB响应以及2秒context均为开发保护，超限/超时/坏时区/坏摘要明确报错，不返回截断或假空数据。聚合准入每进程2、每组织1；不证明生产容量。当前只支持已实现的开发revision 1。真实双库应用Quick18+Custom9到总览三轮61.209s通过。

`#/overview` 已接真实权限读取及总览GET，无自动检测、监控、导出或重试。2026-09-07真实SQLite浏览器验证了当前目标1、窗口Run2、quick/custom两个冻结分层、未知费用null、7/30日边界、手动刷新、历史跳转及退出，无console错误；hold121.660s含交互等待，不是性能结果。全前端27文件623测试及typecheck/lint/build通过，root专项105测试再通过。该次截图仅检查正常宽屏；未新增窄屏或活动任务撤权的浏览器验收。

## 单目标趋势统计

`GET /api/v1/runs/trends` 必须提供 `target_id`，复用历史的状态、检测包、当前模型/渠道、风险、日期和文本筛选。需要当前 `run.read`；同一授权只读快照读取最多100条Run及各自Attempt统计，另1条仅判断是否还有下一页，不汇总它。签名游标不能跨用户、组织、目标、筛选或历史接口使用。已删除目标保留历史ID；该授权组织内不存在的目标返回空页，不泄露其他组织是否存在同ID。

每行保留revision1的原风险、置信指数及分母；调用成功率严格为“已确认成功Attempt / 全部已派发Attempt × 100”。失败、未知和在途分开，未知不冒充失败，也不从分母删除。重试计作另一次调用，不是独立逻辑样本；独立预检不是Run Attempt。延迟的均值/最小/最大值只用实际完成且记录了duration的Attempt（包括已结束失败），明确有效样本数；没有观测返回null，真实0ms允许，不把恢复UNCERTAIN的占位0当测量。它不是P95、服务器内部推理耗时或未来成功概率。

响应固定标识 `scope=run_page`、统计basis、`development=true/calibrated=false`；当前页不是目标全历史聚合。数据库损坏的计数、未知状态、跨Run样本引用、超限或无效延迟拒绝503，不能退回空成功。每Run聚合内部有3001行探测上限，超过3000拒绝；不读取正文、请求、密文或大分析文档。尚无Attempt保留清理，因此当前要求实际Attempt数等于Run请求计数，未来清理必须明确处理统计存续语义。

`internal/app/trends_pipeline_test.go` 在实际Quick18与Custom9的独立TLS检测后核对两Run、18/9调用分母、观测延迟、签名分页与筛选，并确保不把预检混入统计。SQLite/PostgreSQL三轮35.911s通过；这是完整测试耗时，不是性能验收。

前端“目标趋势”或历史每行的目标链接已接真实接口。未选目标不请求；每次显式读取先验证权限，再取固定25条一页，允许UTC精确到秒的时间/状态/检测包筛选；纳秒创建时间排序不会被浏览器毫秒精度误合并。跨页复验锚点，重复/循环游标停止，不自动扫全史。切换组织/用户/目标或离开页面取消读取，失败清空数据及游标；没有数据不显示虚假0。

2026-09-07实际SQLite浏览器hold157.706s通过（包含人工操作等待）：空目标入口→真实历史目标链接→Quick18/Custom9两条的21/27/C和41/49/C、18/18及9/9成功分母和实际延迟→UTC起止与custom筛选→queued空页→恢复/刷新→固定原修订下钻→退出。无console错误/CSP警告；日期控件把09:31:00规范显示为09:31，提交正确保留09:31:00Z。全前端25文件548tests、typecheck/lint/build通过；本轮未做新视口/截图布局验收，也未进行活动任务浏览器撤权故障注入。

## 实时进度

`GET /api/v1/runs/{id}/events` 已由真实数据库状态驱动。首次连接和重连都发送当前快照，事件 ID 为 `<Run ID>:<记录版本>`，只传公开 Run 统计；租约/样本正文、Manifest内容、凭证和任意上游诊断不进入事件。无变化时只查询窄版本，不反复读取执行快照。每2秒重新验证会话/账号/组织成员/权限；撤销会话、重置密码、禁用账号或成员后关闭流，已发送数据不能追回。

每个处理器/进程最多64连接、每个用户4连接；这不是跨副本配额，部署入口还需相应连接限制。单连接5分钟、心跳10秒、每轮DB和写操作各1秒期限。前端 RunProgress 已接入有界 fetch SSE：最大12次连接/1小时，断线和终态只读核对原Run；终态事件在最终GET返回前不会显示完成或结果入口。超过自动跟踪上限可由用户主动恢复；不会通过重连创建新检测。反向代理应为该路径禁缓冲，尊重 `X-Accel-Buffering: no`，不能按普通短请求超时关闭合法流。真实 HTTP SSE 的撤权/重连/容量测试和组件回归已执行；活动 Run 的浏览器 SSE 故障注入仍待后续整体 E2E。

## 人工复核（独立于机器结果）

`GET/POST /api/v1/runs/{id}/reviews` 按组织、Run、固定 `analysis_revision=1` 隔离。读取需要 `run.read`；追加还需 `review.write`、当前会话/CSRF，事务中再次复验。POST 必须带 16～128 个 ASCII 字母数字及 `._:-` 组成的 `Idempotency-Key`；body 为 `analysis_revision`、`conclusion`、`explanation`，非首次追加还须 `previous_review_id` 等于最新已读记录 ID。结论只有 `confirmed/false_positive/watch/not_applicable`；说明非空、UTF-8 最多4096字节，不允许不可见格式字符或控制字符（换行/制表符除外）。所有严格 JSON 写接口同时拒绝孤立 Unicode surrogate 转义，不静默替换后保存。

新复核、原请求哈希收据及审计同事务提交。原 key/body 重试恢复原记录，即使别人已追加较新记录；同 key 改内容或 latest-ID 过时返回409。复核只能追加，不能覆盖/删除，也不修改原机器风险、置信度或结果修订。授权前的收据恢复不能绕过撤权。说明只在授权 DTO 中作为纯文本展示；内部输入、记录和公开 DTO 的 fmt/slog 均脱敏。不要把密钥或请求/响应原文填入说明。

前端在未知 POST 结果时仅允许显式使用同 body/key 恢复，禁止自动重试为新提交；切换账号/组织/Run 清空页面说明和提交身份。2026-09-07 真实浏览器已验证追加包含 `<script>` 字样的合成说明、刷新后持久读取及纯文本转义，机器风险21/置信27/C保持不变；记录只是隔离测试组织的业务判断，不是正式软件审核批准。

## 组织基线参考

已接 `GET/POST /baselines`、`GET/PATCH /baselines/{id}`、`POST /baselines/{id}/approve` 与 `/retire`（均在 `/api/v1` 下）。创建从真实已发布结果及经验证的签名 Manifest 冻结来源、模型、协议、参数/样本/结果 hash 和各版本；缺省修订1，显式其他修订拒绝。`source=official|historical` 和 `region` 都只是组织声明，返回 `organization_declared_unverified`，系统不替组织证明供应商来源或真实执行区域。

仅草稿可改名称/有效期；有效期须未来且不超过365天。批准/退役使用版本CAS、业务说明和相应持久权限，审计与更新原子提交。批准必须显式确认开发限制，风险≥40还须业务复核说明；无足够有效证据不能批准。新独立 HKDF 用途签名固定来源、元数据和审批/退休说明；旧无签名记录不视为可信。批准后不可就地改来源/有效期，应新建参考；退役保留原审核人/时间，过期不再可用。

审批含义固定 `organization_reviewed_reference_only`，当前始终 `development=true/calibrated=false/eligible_for_scoring=false`。内部适用性比较只描述模型、协议、参数、版本、区域声明及成对变量是否匹配，不能被调用者转换成可信 D 维评分、A/B 等级或独立校准证据。可信对照采样与评分仍待实现。

## 异步 S1 报告与文件目录

`POST /api/v1/runs/{id}/reports` body 为 `format=json|html`、`analysis_revision=1`，必带16～128字符 `Idempotency-Key`；当前 `include_restricted_content` 只能省略或 false。同事务检查 `report.export/run.read/evidence.read` 并写入报告版本、固定时间、重试收据及数据库 Job。HTTP 不同步生成文件、不发起上游请求。通过 `GET /api/v1/reports/{reportId}` 精确轮询，或 Run 下的同名 GET 有界分页；返回 queued/generating 不等于文件已经可下载。

真实 Worker 在一致授权快照读取全部 S1 样本和重试链，冻结一次报告输入后生成不可变 JSON/HTML；重试不重新取当前分数或生成时间。受理后退出创建者会话不取消已接受作业，但生成前和最终发布时仍核验账号/成员/三项权限。文件先按独立内容地址落盘，再通过 Job fencing 将 ready/hash/size、审计、作业完成一并提交；数据库回滚或失租可留下不可下载的孤立文件，不宣称文件系统和数据库是同一原子事务。最终发布因固定权限拒绝而回滚时，用原有效租约原子记录报告失败、Job失败和审计，随后可继续消费其他合法任务；真实数据库、审计或失租故障仍停止消费者，不能伪装成普通权限失败。其他永久失败 Job 由维护流程投影为报告失败，保留原结果。

下载 `GET /api/v1/reports/{reportId}/download` 重新核验当前用户三项权限；先校验文件长度及独立 SHA-256，再记下载审计。只根据数据库身份构造受限文件名，没有用户路径参数。响应为 attachment、nosniff、HTML sandbox CSP，带 `X-Report-Content-Hash` 和 `X-Report-File-Hash`。每服务实例最多4个在途下载，最长60秒、写期限2秒，慢传输每秒复验权限。已发送字节不能在撤权后追回。

配置 `integrity.reports.path`（默认 `./reports`）或 `MII_REPORT_PATH`；加载时解析为绝对路径。只创建末级目录，父目录须已存在。拒绝卷根、路径链接/reparse、宽权限目录、非普通文件及硬链接；Windows 新目录为当前主体/SYSTEM 的限制 ACL，Unix 目录0700/文件0600。已有过宽目录启动失败，不自动改动操作者权限。server 和 worker 必须使用同一私有存储及兼容服务身份；完整 Compose 权限初始化和备份/孤立文件清理仍待运维交付。应用关闭时释放持有的目录句柄。

内容规范 `mii.report.canonical-json.v1` 的 hash 不含 `content_hash` 字段，最终 JSON/HTML 文件各有独立 hash；精确规范见 `internal/integrity/report/README.md`。报告当前只包含 S1，`review=null/review_state=not_included` 表示未封存人工复核，不表示该 Run 没有历史复核；不伪造批准。JSON/HTML 不覆盖旧版本；PDF/CSV、人工复核快照和完整差异版本链仍待开发。

报告入口：结果与报告→选定Run修订→“报告”。页面先读取当前三项权限和有界列表；只有选择格式并明确确认后才创建，未知POST结果保留同一提交标识供手动恢复，不自动重建。仅对选中报告按精确ID有界轮询（每2秒，最多150次/5分钟）；列表其余行是最近读取快照。切换账号/组织/Run/修订或离开页面取消读取、清空内存，但不取消服务端已受理Job。

下载前页面重新验权和读取报告，独立校验安全响应头、UTF-8、长度（最多16MiB）及文件SHA-256，最多60秒；仅校验成功后请求浏览器保存Blob，不嵌入或执行HTML。浏览器是否实际落盘取决于下载设置，不虚报保存完成。反向代理必须保留报告安全头、Content-Length及原始字节，不为该attachment路径压缩或改写编码；客户端明确拒绝非identity Content-Encoding。

实际应用测试现覆盖初始化→真实受控 TLS 检测→人工复核→基线草稿/审批/退役→JSON/HTML异步生成/下载，并核验哈希、同 key 字节相同、机器结果不变和审计链。2026-09-07隔离真实浏览器还验证新JSON报告修订2生成、JSON/HTML文件校验及保存请求、刷新后旧报告保留、机器21/27/C不变、退出，无console错误；测试hold200.877s包含浏览器等待，不是运行性能。上述通过不代替完整浏览器配置执行、部署、算法校准与发布验收。
