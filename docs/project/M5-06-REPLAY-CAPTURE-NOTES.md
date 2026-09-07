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
