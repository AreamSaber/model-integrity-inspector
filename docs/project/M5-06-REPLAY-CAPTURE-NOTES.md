# M5-06 B1：离线捕获回放最小实施方案

状态：获准实施设计，2026-09-07。第一子单元已实现 `tests/replay` 严格 codec、私有 verifiedCapture、真实离线 parser→features→Runtime 及合成单元回归；真实 Worker/TLS 捕获、CLI、捕获数据集、准确率回执或发布准入尚未交付。A1 文件未改。本文仅规划两个受控 TLS 开发案例，不代表校准、独立盲验收、真实供应商渠道或人工批准。

## 1. 推荐边界

分离两个进程/阶段，避免把“离线”误写成捕获阶段也没有网络：

1. **开发捕获控制端**：临时 SQLite、真实初始化/身份/目标/Run/Worker 工作流、仅回环受控 TLS mock。只使用合成密钥与正文；不连接外部模型、不付费。实际执行后，在真实分析 Job lease 下取得已经关闭的 Run、全部 Attempt、持久化 final pointer，并验证最终响应的精确 AAD。
2. **离线检测端**：只读捕获包、规则 artifact 和外置开发校验材料。`generator.Verify/ExecutionPlan → Adapter.Call(recorded Doer) → features.NewEvidence/Builder.Build → bundle.Runtime.Analyze`。不打开数据库、不创建 Job、不持有生产密钥、不访问网络、不加载标签/场景配置。

生产 Worker、仓储、HTTP、CLI `cmd/mii` 不导入 `tests/replay`。不增加 `Trusted=true`、任意 normalized response 上传、无 lease 的 AnalysisSource 构造器或发布接口。离线输出只是本次回放的 S1 预测，不调用 `PublishRunAnalysis`。

## 2. 已有可复用能力与真实缺口

| 已有代码 | B1 用法与限制 |
| --- | --- |
| `probe/generator.Verify/ExecutionPlan` | 校验真实冻结 Manifest 的 HMAC、组织、模板/词表哈希、请求与顺序；不得重新 Generate 来替换原随机 nonce/seed。 |
| `adapter/openaichat.Adapter.Call` | 使用真实 BuildRequest 和 HTTP/SSE parser；注入只读录制 Doer，`prepare=nil`。不能直接信任存储的 Content/finish/Usage。 |
| `repository.JobQueue.LoadRunAnalysis/AnalysisSource.Use` | 捕获控制端必须从真实分析 lease 取得闭合快照，禁止虚构 finalAttempt。它不是通用导出 API。 |
| `secret.KeyRing.WithResponseEvidence` | 捕获时按持久化组织/Run/样本/Attempt/request hash 精确 AAD 解密。不会把 key/ciphertext 导入检测端。 |
| `analysis/features.NewEvidence/Builder.Build` | 接受受信内部组合的输入，检查绑定与重试终态，重新本地计数/结构/行为提取；该纯包自身不认证数据库来源。 |
| A1 `bundle.Resolver/Runtime.Analyze` | 执行所选受支持参数并核对真实 Batch artifact hashes；候选 artifact 不会获得校准或 A/B 能力。 |
| `tests/mock-upstream` | 可运行真实 TLS HTTP/SSE、控制终止方式。默认 Tokens 是合成片段，不是 tokenizer 的真实 token，不能据此声明 exact。 |
| `tests/datasets` | 保留控制端标签/分区隔离原则；旧 Input 含 normalized response 和输入自报的 tokenizer quality/count，**不作为 B1 捕获真实性边界**。 |

缺口是录制格式、受信捕获封装、离线 Doer、受限来源映射、CLI 与回归。目前没有任意生产 Run 的 S2 安全导出器，也没有逐 read/实际 watchdog 超时的录制钩子。

## 3. 最小文件与接口范围

建议第一轮只新增：

- `tests/replay/capture.go`：严格 typed capture DTO、资源上限、canonical/hash/签名校验；私有 `verifiedCapture`。
- `tests/replay/replay.go`、`transport.go`：离线解析、请求绑定、受限来源映射和 Runtime 执行。不得 import datasets 标签类型或 mock 控制器。
- `tests/replay/cmd/replay/main.go`：只读本地输入的离线 CLI。
- `tests/replay/*_test.go`：边界、parser 差异、重复运行和重算 tokenizer 回归。
- `tests/replay/capturefixture/*_test.go`：独立控制端，复用真实 Worker/API 与 TLS mock；不编入检测 CLI。
- `tests/replay/README.md` 与公开的两个合成开发捕获；只有经 S2/S3 扫描后才考虑提交捕获正文。

核心已落盘接口（CLI/真实控制端仍待下一子单元）：

```go
// verifiedCapture 不导出，只有严格校验函数能构造。
func New(cfg Config) (*Engine, error)
func (e *Engine) Replay(ctx context.Context, input io.Reader) (Prediction, error)
// Config 内的开发 Manifest verifier/捕获公钥由本地部署组合注入，
// 不从 input 中选择任意公钥、密钥、算法、文件路径或 runtime 实现。
```

`features` 已有接口足够，不必增加公开 Input getter 或修改 A1。数据库记录→封闭 capture DTO→features 绑定的映射可以留在测试工具中；不复制结构、行为或评分算法。

`worker.classifyExecutionResponse` 和 `analysisInput` 当前为私有函数。B1 使用**实际 Worker 已写入、捕获签名覆盖**的状态，而不是自行实现完整 Worker 状态机；重解析的协议投影必须与原 AAD 响应一致。若后续要求支持没有真实 Worker 来源的通用录制或全错误分类，另开 checkpoint 抽取无 I/O 的共享分类函数并做 Worker 差异回归；不能仅把私有函数导出当权限能力。

## 4. 捕获时取得真实 finalAttempt

控制端建立临时真实 Store、身份会话、组织权限、密钥与目标，正常确认一个受限 Run。使用 `NewRunHandlers` 执行采样，不手动 INSERT 完成行，也不把预分配合成 ID 称为持久化 Attempt。

控制端可包装测试 Runner 的既有 `JobRunAnalyze` handler：

1. 收到真实 `Execution` 后调用 `Queue.LoadRunAnalysis(ctx, lease)`。
2. 在 `source.Use` 中将已核验的 Run、完整 Samples/Attempts 投影到有界捕获 journal；`FinalAttemptID` 原样读取，必须等于该样本最后一次 Attempt，禁止 best-of-retry。
3. 使用 fixture KeyRing 按权威记录组成 AAD，解密最终证据；记录协议投影摘要与有界观测时间，不在日志中格式化 AnalysisData 或正文。
4. 在同一测试 handler 中调用原 analysis handler，正常完成分析/审计；捕获失败则本次开发捕获失败，不能导出半份“通过”文件。
5. 外层捕获签名覆盖完整 journal、Manifest hash、字节对象 hash、版本、scope、最终指针和时间。签名前确认预期样本/Attempt 数量齐全。

只依赖现有有 fence 的读取方法；无需新增仓储导出 API。Job lease 在第一次 `Use` 后若失效，正常 analysis handler/完成事务仍会失败，控制端必须废弃未封存捕获。

外层签名建议 Ed25519；开发捕获私钥只在控制端，离线检测端持有固定开发公钥。Manifest 本身目前是 HMAC：检测端还需外置、仅用于本次合成 fixture 的 Manifest 校验 key，不得导出真实应用 master key。此 key 明确是开发材料，不代表生产来源认证。捕获文件不能自带可替换信任根；公钥/Manifest key 的指纹由命令配置及输出记录。公开 fixture 即使可被仓库作者重造，也只能证明开发可重复性，不是独立第三方见证。

## 5. v1 捕获数据形状

外层严格 JSON，schema 固定为拟定的 `mii.replay-capture.v1`；所有未知字段、重复 key（含大小写别名）、非 canonical 表示、尾随数据、无效 UTF-8、负数/溢出/超界在进入 parser 前失败。二进制 payload 使用有界 base64，不能把非法 UTF-8 响应先替换为 Unicode 再解析。

| 分组 | 允许内容 |
| --- | --- |
| identity | 随机不含类别的 case ID；固定 schema/捕获器实现标识；实际 org/run ID；捕获包内容 hash 与外层签名。 |
| artifacts | 原始 canonical Manifest 字节及 hash；生成器/模板/词表版本与 hash；捕获时规则版本。回放所选候选 runtime 的 hash 在 CLI 配置/输出另记。 |
| run | execution_closed_at；原冻结 Manifest 可重建的 plan 不另提供可冲突副本。 |
| samples | 实际 ID、probe ID、ordinal/execution ordinal、pair ID、attempt count、final attempt ID、完成时间、持久化有效性。 |
| attempts | 实际 ID/job ID/number、状态、开始/结束时间、闭集错误码、request hash 与原 pre-auth wire payload/hash；完整重试链。 |
| observed response | HTTP status；允许名称的 header 值数组；实际 body 字节对象/hash；EOF/终结方式；原 AAD 证据的协议投影摘要；限定观测时间。 |

**禁止字段**：输入自报 local tokens、exact/compatible/heuristic、NormalizedResponse、risk/score/confidence/grade、normal/complete 结论、calibrated/trusted、expected label、split/lineage、场景名、故障概率/seed、控制器实际 cap、Authorization/Cookie/Set-Cookie、密钥、任意路径/URL 下载指令。

持久化有效性是签名覆盖的 Worker 观察，不是 detector 接受的自由判断。它必须与 scope、真实 final pointer 及重新解析的协议状态一致；不一致整例失败，不能“修正”为更有利的有效样本。

header 保留同名多值，不预先合并为单值。只保留 parser 真正使用的 Content-Type、Retry-After、X-Request-Id、Request-Id、Openai-Processing-Ms。Content-Type 的重复值必须仍能被真实 parser 拒绝。

协议摘要使用明确版本化的 typed canonical 投影：真实 parser 的内容、Usage、模型回显、finish、HTTP/Content-Type、parse/end 状态、警告、响应 hash/字节数、chunk 数及事件 sequence/type/bytes；**排除测时字段**。摘要不代替字节重解析。Worker 追加的本地 tokenizer 警告分开处理，不能伪装成上游 parser 字段；首批已知词表模型无此附加警告。

## 6. 真实字节与时间：B1 有意限制支持面

无生产录制钩子的最小捕获器，可包装受控 TLS mock 的 `ResponseWriter`，原样转发 `WriteHeader/Write/Flush` 并限量记录。该记录是**mock 实际发出的 HTTP 实体字节**，不是 TLS packet，也不是 client `Read` 边界。

第一版只接收以下受控、可验证情形：

- HTTP 200 非流式响应到 EOF；或 SSE 正常 terminal `[DONE]` 恰为最后事件；或 SSE 干净 EOF、缺 `[DONE]` 的 partial。
- 不压缩、不重定向、不追加 `[DONE]` 后数据、不发生 read/size/timeout 错误，不混入 HTTP retry 场景。
- 每次请求串行且 wire hash 唯一；与实际 Attempt 对应必须无歧义。对应缺失/重复直接失败。第一版每个样本一次真实 Attempt，另以篡改回归验证不得删重试/改 final pointer。
- 重解析获得的 body hash/字节数和协议投影，必须等于捕获时从实际 AAD 响应得到的值。server emission 与 client 消费不一致则拒绝，不声称完整捕获。

离线 Doer 不用 `http.Client`，`Do` 只核对 method/path/canonical body/request hash/调用次数后返回内存 response；不存在 fallback 网络调用。endpoint 仅参加冻结请求校验，绝不 DNS 或 Dial。无 auth prepare，不能通过 replay CLI 指定任意 endpoint 重发。

计时须明确双来源：

- body、finish、Usage、parse 状态、终止、事件类型/顺序/字节数均由真实 parser 重新得到。
- duration/first-byte/first-token/事件 arrival 与 interval 来自捕获时精确 AAD 证据，外层签名覆盖，范围与相对关系严格验证。只有协议投影完全一致后，才将该**capture-observed**时间附回解析结果用于特征；不是本次离线机器的网络性能。
- `Config.Now` 可使离线 parser 的临时测时确定，但真实 `context.WithTimeout/time.AfterFunc` watchdog 并没有虚拟化。因此 B1 不回放实际 first-event/idle/total timeout，不通过 sleep 伪造，也不把 elapsed=0 宣称成真实 RTT。
- 重复回放相同捕获文件应得到逐字一致预测。重新捕获一次真实 TLS 会产生新 ID/时间/hash，不要求与上一次捕获字节相同。

将来若需要任意 read error、`[DONE]` 后预取、多次重试或 watchdog 因果重演，需要单独授权捕获 adapter 输入侧 read 分段/错误、trace/clock 事件以及可注入计时器；server-side 字节日志不足以支持这些主张。

## 7. 检测端执行顺序

1. 在总字节预算内读取；严格解码、长度检查、hash/签名验证；检查支持的实现/fixture 公钥及 Manifest 校验材料，不自动寻找其他文件。
2. `generator.Verify` 验证原 Manifest，`ExecutionPlan` 重建；核对全部数据库身份/顺序/重试/final 绑定及时间，最终构造私有 verifiedCapture。
3. 对每个需解析的真实 final response，用 `Adapter.Call` 与拒绝网络的 Doer 执行真实 serializer/parser。核对原 wire payload 和 hash，核对从原 AAD 证据取得的协议摘要。
4. 校验并绑定 capture-observed 时间；构造 `NewEvidence` 与 `features.Input`。不直接把捕获 JSON unmarshal 成 features.Input，不设置内部 tokenrisk/behavior/scoring 输入。
5. `Builder.Build` 再次验证冻结 Manifest/绑定。`CountOutput` 从真实重新解析的 Content 按 reported→requested→standard 选择当前冻结的本地词表；unknown 只能按现有算法降级。输入不存在 count/quality 可供信任。
6. `Resolver.Resolve` 校验 artifact/hash，`Runtime.Analyze` 执行。Manifest 的原规则版本保持不变；回放输出另标原版本与所选 candidate ref，不伪装原 Run 已用新参数执行。
7. 输出 typed S1 prediction 与来源摘要，记录 included/excluded、partial/insufficient、限制、实际规则/模板/词表 hash 和 `timing_source=capture_observed`。不输出正文/请求/密钥/任意原始 JSON。

## 8. 固定资源上限（初始提案）

这些是工具输入拒绝上限，不得静默截断后继续给“正常”结论：

- 单 capture JSON 24 MiB；所有 decoded body 总量 8 MiB；总 wire request 数据 4 MiB；Manifest 2 MiB，与 generator/feature builder 实际限制一致。
- 每 Run ≤150 个逻辑样本；完整 Attempt ≤450，且每样本 ≤冻结 `MaxRetries+1`、当前最高 3。首批支持的真实捕获只含一次成功/partial Attempt。
- 单 request ≤1 MiB；单 raw response ≤1 MiB；单 SSE event ≤1 MiB；final feature Evidence 单条 ≤1 MiB。feature builder 的 8 MiB 整批限制实际合计 Manifest + wire payload + 编码 Evidence，不是三者各有 8 MiB；代码继续服从该更严限制。
- header 名称固定 5 种，每种 ≤4 值，每值 ≤512 bytes，header 总量 ≤12 KiB；保留重复并由 parser 作语义判定。
- 原始 body 分段元数据（若后续加入）≤4096 段/response，不允许无限零长 read；当前不接受任意分段程序。
- 时间固定 UTC、正序，Attempt ≤180 秒；Run ≤冻结预算；duration/TTFB/TTFT/事件间隔均有界且彼此一致。禁止 NaN/Inf、未来睡眠指令。
- 输出 ≤4 MiB；context 支持取消与总运行期限；不足内存/超时/错误只能返回闭集错误码及 opaque case ID，不回显输入片段。

具体上限以实施时验证当前 canonical Manifest 大小后冻结；不通过扩大 feature 核心资源预算满足某个过大的 fixture。

## 9. CLI 与无网络证明

拟定用法（尚未实现）：

```text
replay --capture <local-file> --rule <local-artifact> --rule-sha256 <sha256>
       --capture-key-id <configured-dev-key> --manifest-key-file <synthetic-key-file>
       --output <new-local-file>
```

不接 URL/stdin 自动引用、目录递归/解压、远程模型、labels 参数、capture 内自带路径或可执行脚本。输出默认不覆盖已有文件，先完整计算/校验再原子写入；日志不含 body 或 key。捕获控制端是另一个 test command，不在 replay CLI 内提供 `--live`。

构建后的 CLI 在禁网环境运行；生产依赖中 tokenizer 词表已内嵌，解析与评分不需在线下载。新增 import guard：检测端禁止 mock/datasets 控制器包和 `net.Dial`/`http.DefaultClient` 等真实请求路径。另以输入 `https://unresolvable.invalid`、关闭 TLS mock 后回放和禁止网络的运行环境验证，不以单一字符串扫描当完整安全证明。

## 10. 两个开发案例与测试判据

控制端先冻结两种开发配置，case ID 随机且不含类别。检测进程看不到配置/控制 seed/标签文件；测试断言由控制端持有。不能根据 detector 结果反推一个“正确标签”再计算准确率。

1. **完整对照**：同一个冻结受限计划覆盖真实 JSON 与 SSE，已知本地词表模型，模板相符的合成响应。自定义 mock Responder 的 Usage 由真实 tokenizer 重算；不使用默认片段数量冒充 token 数。
2. **终止差异**：同样计划与模型，只有 stream 的 terminal `[DONE]` 被控制端省略，body 干净 EOF；非流式保持原行为。应由真实 parser 得到 partial/`STREAM_EOF_BEFORE_DONE`，特征标警告/替代解释，不以此强制整体高风险或“作弊”。

此选择先验证真正 parser→features→Runtime 链，不依赖造一个≥70分阳性。既有标准 60 样本固定 256 cap 的 Token=41 开发现象仍保留，不调参凑阈值；可在后续捕获扩展加入，不能把此例当固定 cap ≥95%准入证明。

必须测试：

- 捕获后关掉 TLS server，重复离线回放输出/hash完全一致；builtin 与旧纯核输出一致，candidate 输出准确标自身 ref，均 development、未校准、C/D。
- 实际 Worker 选定的 final pointer 与重放绑定一致；交换 org/run/sample/attempt/request/hash、改顺序/数量、删重试、改最终指针均拒绝。
- 修改 payload/header/EOF/协议摘要/计时/签名、未知实现/词表/模板/schema、重复 JSON、尾随数据、巨型 base64/UTF-8、重复 header 均有明确失败或真实 parser 负例。
- 捕获 JSON 注入 `tokenizer_quality=exact/local_count/risk/labels/trusted` 一律拒绝；改变真实内容后重新合法捕获会重新计数；已知和未知模型的独立 parser/features 差异测试保留真实精度/降级。
- 记录的 Usage 与重新计算 local count 分离；故意错误 Usage 只能产生算法所定义差异，不能修改本地 count。不得把缺失 Usage 当 0。
- 动态 nonce/普通上游正文可出现类似 label 字样但只是 S2观察；禁止 privileged labels 字段和控制器 import，S1 输出不泄露 nonce/body/key。
- server-side emitted bytes 与实际 AAD 响应消费 hash不一致、真实超时、trailing bytes、非受支持重试等返回 unsupported/integrity 错误，不降格成“正常通过”。

## 11. 交付分界

B1 完成最多意味着：两个真实受控 TLS 开发捕获，实际最终 Attempt 绑定，离线真实解析/重计数/评分，严格输入边界、无网络依赖与确定性回归。

仍未完成：任意生产证据授权导出、全网络故障/超时回放、独立校准与 held-out 标签、QA 签名 metric receipt、95/90/85/≤5%与100%证据覆盖的正式判定、规则包发布/灰度/退役、运行时冻结/读取接线。开发 capture 签名不是 QA 通过回执，A1 RuntimeRef 不是发布能力。

## 12. B1-3 CLI 与开发文件导出边界（获准实施范围）

本子单元只新增 `tests/replay/cmd/replay/**`、`tests/replay/localfile/**`，不修改 B1-1 核心或生产代码。真实控制端已可在内存中完成 capture；在其 review 冻结解除前，不修改 `capturefixture` 进行导出接线。

- 参数固定为 `--capture`、`--rule`、`--rule-sha256`、`--capture-public-key-file`、`--manifest-key-file`、`--output`、`--timeout`（1–120 秒）。路径必须是用户显式指定的本地常规文件，不从 capture 取路径；没有 stdin、HTTP、URL、标签目录或 `--live` 模式。
- 信任根由本地显式配置文件提供：封闭开发 Ed25519 公钥 schema（包含固定用途与 key ID）；封闭开发 Manifest HMAC schema（独立随机 key、明确 `ProbeMAC` 用途与开发版本）。这些不是正式 QA 信任根。拒绝裸 32-byte master key、生产 KeyRing 格式、capture 内自带公钥。合法 schema 不能证明材料来源；独立 key 必须由受控导出器新生成。
- 当前真实 fixture 的 compiler 使用其合成 KeyRing；后续获准导出时改接**单独新生成**的开发 Manifest signer，AES/Audit fixture master 不写入任何导出文件。导出前扫描 decoded Manifest、wire payload、body 和 header 真内容中的控制端密钥/口令，不能只对外层 base64 JSON 做字符串搜索。
- 文件安全遵循现有 keyfile 的句柄模式：Windows 使用 drive-root-relative `NtCreateFile`、`OBJ_DONT_REPARSE`、regular/nlink 校验与受限 ACL；Unix 逐目录 `openat(O_NOFOLLOW)`，最终文件使用 `O_NONBLOCK` 后验证 regular/nlink/owner/0400或0600。拒绝 URL/UNC/device/ADS、任一 symlink/junction/reparse、hardlink>1，以及别名路径。读取前后校验同一打开句柄与长度；不接受任意阻塞 Reader。
- 保留 core 的 24/2/1 MiB 等有限输入界限，信任材料文件另设小上限。CLI 对常规文件完整有限读入后只向 Replay 传内存 Reader；取消与总运行期限在读、计算和输出阶段复验。不能宣称该措施可强行取消任何内核 I/O；不允许 pipe/device 是防止无限阻塞的主要边界。
- 完整计算、序列化与输出大小检查成功后，才在已经验证并持有句柄的私有输出目录内随机独占创建临时文件。创建瞬间即0600（Unix）或 owner+SYSTEM ACL（Windows）；写完、Sync 并再次检查取消后，Windows 使用句柄相对 `FileRenameInformation` 且 `ReplaceIfExists=false`，Unix 使用同目录 `linkat` no-replace 后回收临时项，原子发布最终名字。已有目标绝不覆盖；提交前失败/取消不留下半份最终输出。清理仅限本次创建且句柄/目录 identity 匹配的临时项，不删除任何已有目标。发布成功后的持久化错误属于提交结果不确定，可能保留完整最终文件，不能回滚删除它或声称没有输出。
- built CLI 测试须真实启动可执行文件，覆盖输入损坏/未知字段、键替换、取消/期限、目标已存在、目录/pipe/device/link/unsafe 权限、失败不泄漏路径或源正文。禁止网络的 OS 环境演练作为单独证据；不把 AST guard 或关闭 mock 等同于已做 OS 禁网，也不自行建立防火墙规则。
- B1-3 明确支持 Windows + Linux；其他平台 fail closed。Linux `Fstatfs` 只允许 ext/XFS/Btrfs/tmpfs/overlay/ramfs/F2FS，未知/NFS/CIFS/FUSE/pseudo-filesystem 拒绝。文件系统 magic（包括 overlay）只是输入边界，不能证明 backing storage 或整个进程已经 OS 禁网。Windows 本地真实执行测试与 Linux 交叉编译证据须分别记录，不混称双平台运行通过。

## 13. B1-4 Ubuntu CI 的 OS 网络隔离验证

本子单元使用 `linux && replay_netns` build tag 的独立测试，复用 B1-3 的真实 built CLI 和明确标为 synthetic 的开发 capture。普通套件不触发特权命名空间操作；现有 `quality` job 新增必跑的 `scripts/test-replay-netns.ps1` 步骤。required 依赖、原有检查、双库回归和阈值不变。测试/脚本没有“环境不支持则跳过”的通过路径；缺少 sudo、unshare、setpriv、namespace 能力或依赖缓存均使这个 CI 步骤失败。

1. 原 runner UID 必须非零。先由该 UID 在私有 0700 目录建立 0600 输入文件（独立开发 Manifest key，不是 master），完成实际 CLI 基准回放；所有编译、词表和规则准备在隔离前完成。宿主父进程启动随机端口的 loopback TCP 正控制，并先证明其可连接。
2. `sudo -n unshare --net` 只创建子进程的非持久网络命名空间，随后立即用 `setpriv` 降到原 UID/GID、清空 supplementary groups 与全部 capabilities、设置 `NoNewPrivs=1`。再用 `env -i` 启动已编译测试子进程；只传入本次测试的路径、父 namespace identity、数值 UID/GID 和正控制地址，不传 GITHUB token、DSN、master、capture 或 key 内容。没有用户命名空间、host firewall 修改、接口配置、持久 namespace 文件或系统参数变更。
3. 子进程实测 real/effective/saved/fs UID/GID 均一致且非零，CapInh/Prm/Eff/Bnd/Amb 全零、groups 清空；拒绝继承的 socket FD。验证 netns identity 不同、只有 DOWN 的 lo、没有可用 IPv4/IPv6 路由（内核 reject 路由不视为可用路由）。此后才尝试连接仍存活的父 loopback 服务和文档保留地址 IPv4/IPv6，要求明确即时不可达，不以 DNS 失败或超时等同断网。
4. 在同一无特权隔离子进程运行实际 CLI，S1 预测必须与正常环境基准逐字一致，文件 owner 仍为 runner、mode 0600。再执行损坏 capture、换 key、已有输出不变，并以启动前已取消的 context 确定性验证“不得启动 child”；这不是中途取消或 graceful SIGINT 的证明。同 netns 运行预编译 localfile 测试二进制，包含写完并 Sync 后、提交前由屏障触发的真正中途取消、并发 no-replace、链接/权限/本地文件系统边界。不得依赖 Start 后抢先 cancel 或 sleep 来假定子进程尚未执行完。
5. 父进程完成后再次验证原 namespace identity 和正控制仍连通，证明没有修改宿主网络。所有清理由本次 Go `t.TempDir` 生命周期和自身进程/句柄负责；没有跨 shell 删除。单 CLI、子测试、父命名空间进程和 CI 步骤均有有界期限。

常规返回会清理本次 TempDir；进程或 runner 被强制终止时可能留下本次私有目录，禁止上传这些输入/key，最终由隔离 runner 生命周期清理，不执行宽泛兜底删除。

该机制验证本 CLI 所用 IPv4/IPv6 网络路径的 OS 隔离，不宣称完整恶意代码 sandbox 或文件系统/所有 IPC 隔离。没有通过共享宿主 socket 代理外连的测试替代路径。

包装脚本仅在这一步禁用 Go proxy/sumdb，并拒绝隐式 GOFLAGS/child-mode 覆盖。它检查实际 `go test -json` 的精确 test run + test pass + package pass、禁止 skip/fail、要求 8 个闭集 proof stage 各出现一次；零测试、名字或 tag 配错、仅输出“成功”字符串不被接受。脚本内策略回归会在每次实际运行前执行；`-PolicyOnly` 只允许本地验证 framing，输出明确 `NOT_OS_EVIDENCE`，workflow 契约禁止将它替换真实步骤。公开日志仅输出闭集 S1 阶段码，不上传 S2 capture 或开发 key。

机制依据为上游 [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)、[unshare(1)](https://man7.org/linux/man-pages/man1/unshare.1.html) 与 [setpriv(1)](https://man7.org/linux/man-pages/man1/setpriv.1.html)。实现交付时本机只有 Windows，Linux namespace **尚未实际执行**；交叉编译/lint/策略测试不等于 OS 验证完成，必须由本提交后实际 Ubuntu CI 结果补足。即使 CI 通过，本子单元也只证明合成开发回放在该隔离环境下工作，不是生产导出、真实官方渠道、独立校准、QA 准入或规则发布能力；真实 Worker export 另行接入。

### B1-4 数字 socket 诊断 checkpoint（2026-09-07）

`da6db58` 的 CI `34111776546` 已通过身份、拓扑与父回环负控制，随后报 `FAILED_NETWORK_NOT_BLOCKED`，没有到达 `IP_EGRESS_BLOCKED`；旧日志没有 family/stage/errno，不能据此确定唯一根因。核对固定 Go 1.26.7 源码：`net/lookup.go` 的数字 literal 直接解析为地址；`net/ipsock_posix.go` 对显式 `tcp6` 直接选择 AF_INET6。此处没有调用 IPv6 capability probe 的证据，不能把失败归因为本地 IPv6 探测或 `no suitable address`。

测试改为直接构造固定数字 `SockaddrInet4/6`，以 `SOCK_NONBLOCK|SOCK_CLOEXEC` 调用 Linux socket/connect，不经过 DNS 或 Go 地址选择。连接立即失败时只接受 CONNECT 阶段的 ENETUNREACH/EHOSTUNREACH；只有 IPv4 父回环控制还接受 ECONNREFUSED，只有 IPv6 SOCKET 阶段接受 EAFNOSUPPORT。EINPROGRESS 本身不算断网，必须在原 500ms context 内经一次有界 poll 读取 SO_ERROR 并满足同一连接拒绝闭集。成功连接、SO_ERROR=0、超时/取消、EINTR、EACCES/EPERM、地址错误、poll/getsockopt/close 错误和未知 errno 全部失败，不重试或扩大允许错误。父回环 positive-before / negative-inside / positive-after、IPv4 与 IPv6 两项验证和 8 个 proof stage 保持不变。

新增失败诊断仅输出固定 `DIAG_FAMILY_*` / `DIAG_STAGE_*` / `DIAG_ERRNO_*` 标签；未知值映射 UNKNOWN/OTHER，子进程原始错误、路径和地址不会转发到公开日志。PowerShell 包装器另以闭集过滤这些标签，诊断不计入成功 proof。父测试实际执行前还运行无 socket syscall 的纯 seam 回归：数字地址范围、拒绝错误分类、nonblocking/CLOEXEC 参数、直接/异步成功拒绝、poll/getsockopt/close 失败、取消、关闭次数与不泄漏原错误；这些是策略回归，不是 OS 禁网证据。

本机 Windows 验证：Linux amd64 tagged test 交叉编译通过；同 tag 的 golangci-lint 为 0 issues；包装器 `-PolicyOnly` 与 PowerShell AST 解析通过；普通 Windows CLI 包测试通过。没有在本机执行 Linux tagged 回归或 namespace。此 checkpoint 仍须下一次真实 Ubuntu CI 确认，不能据交叉编译或纯策略通过宣布 B1-4 已完成或旧失败根因已修复。

### B1-4 IPv6 无源地址的拓扑组合证明（2026-09-08）

`e8a52a6` / CI `34179919964` 已实际给出 `IPV6 / CONNECT / EADDRNOTAVAIL`，identity、topology 和 loopback 三阶段成功，quality 最终失败。这个 errno 单独不能证明断网，也可能是端口资源问题；通用 `netnsExplicitlyBlocked` 仍拒绝它。Linux v6.8 的 [IPv6 路由查询代码](https://github.com/torvalds/linux/blob/v6.8/net/ipv6/ip6_output.c#L1040-L1082) 在最终路由错误之前尝试选源，[源地址选择代码](https://github.com/torvalds/linux/blob/v6.8/net/ipv6/addrconf.c#L1757-L1765) 在无候选源时返回该 errno。因此“空 netns 先报告无源地址”是与实际日志相符的解释，不是旧日志已经证明了完整内核调用轨迹。

修订要求实际每次数字 connect 前后均重新观察：仍为同一独立 namespace、唯一 lo 且 DOWN、该接口 Addrs 为空、`/proc/net/if_inet6` 为空、无可用 IPv4/IPv6 路由。proc 文件以 64 KiB 上限读取，读取/关闭失败、缺文件、异常内容、任何源地址或 namespace 改变均失败。只有这些真实观测生成的相同私有 receipt，才允许 AF_INET6 的同步 CONNECT 对固定文档地址返回 EADDRNOTAVAIL；SOCKET/SO_ERROR、IPv4、loopback、无 receipt、成功/超时/权限错误仍拒绝。未增加 bind/freebind 或接口配置来制造 errno。整个 CLI/负例/原子文件测试结束后再次验证拓扑，原非 root/capability/fd、正负控制、八阶段和必跑 CI 门禁不变。

新增纯策略反例覆盖源地址/异常表/超限、零 receipt、namespace 前后变化、错误 family/stage、异步结果和成功连接；这些在 mandatory parent test 内执行，不增添包装器可误计的测试成功事件。Windows 仅能执行普通 CLI/契约/包装策略，实际 Linux syscall 与 namespace 结果仍须新 CI 验证，不能用交叉编译冒称完成。

## 14. B1-5 真实受控捕获的私有文件导出与独立 CLI

本单元只改 `tests/replay/capturefixture/**` 的 `_test.go` 控制端与相关说明，不增加生产入口、公开测试来源 capability、Worker/repository/HTTP 旁路或新的 CLI 参数。

1. compiler 改接本次 `localfile.NewManifestSigner()` 新生成的独立 ProbeMAC 开发 key；实际冻结 Manifest 验证其版本为 `dev-replay-manifest-v1`，而不是 AES/Audit KeyRing 版本。应用 master 与捕获 Ed25519 私钥均不写文件。独立 Manifest key 只可通过现有明确开发用途 serializer 写到专用私有 trust 文件。
2. 私有 `settledExporter.write` 自己调用 `sealSettled`，读取真实已提交 Run、最终 Attempt、revision 1 publication、零 outstanding reservation，再验证实际审计链。不是先导出后检查，也不接 caller 的 `settled=true` 或任意算法结果 JSON。
3. 写入前扫描 decoded Manifest/wire/body/header 和将要导出的 trust/rule 文档。已知 canary 包含本次应用 master、上游口令、登录口令、捕获签名私钥及常见 raw/hex/base64 表示；Manifest key 必须只存在于专用文件、不得进入 capture、公钥文档或规则。扫描具有有限已知模式，不声称任意编码/未知密钥 DLP。
4. `WriteNew` 在本次私有目录依次提交公钥、Manifest key、固定规则、最后 capture；各文件采用原生句柄验证与原子 no-replace，并非四文件集合的原子事务。校验、取消、未提交或回滚失败时目录无文件；若已通过校验且后续某次文件提交失败，可能保留前面完整的私有输入，不能称自动事务回滚。只由本次 `TempDir` 生命周期清理，无宽泛删除或输入上传。
5. 停止真实 Worker、关闭实际 TLS server 后启动新构建的 CLI，以四文件作为输入；编译禁用 Go proxy/sumdb，CLI 子进程使用最小环境，不继承 DSN、GitHub 或应用配置。完整 prediction 与内存回放逐字一致，Analysis 与数据库 immutable publication 逐字一致。两种真实 TLS 开发场景均覆盖 SQLite/PostgreSQL；PG reservation-delay 原计时回归保留。更换独立 Manifest key 必须失败且不生成输出，重复 CLI 不覆盖已存在结果。
6. 未完成 publication、实际 publication/audit 事务回滚、取消、decoded body canary 的回归均调用同一导出入口并断言无文件。强制 completion 失败的测试保持 parent context 存活，确定等待 Runner 返回闭集 `ErrUnavailable` 后才清理；不能竞速 cancel 并要求被有意终止的 Worker 一律 graceful nil，正常场景仍要求 nil。nonce/S2 不进入 prediction，local tokenizer 仍真实重新计数，partial SSE 特征继续与实际 parser 一致；不为某类场景调整风险阈值。

真实源 CLI 与 §13 的 synthetic namespace 演练是两项不同证据：本单元关闭 TLS 不等于在 OS 禁网 namespace 跑真实源。文件目前只存在于私有临时测试目录；不提供生产导出、不上传输入、不反推标签、不生成校准/QA metric receipt，也不把 development C/D 升级为正式 A/B 或宣称 M5-06 已完成。
