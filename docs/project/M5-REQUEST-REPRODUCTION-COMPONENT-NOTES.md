# REP-005 请求-only可信复现纯组件 checkpoint

2026-09-08。本单元是可复用纯组件，**不是 REP-005 端到端交付，也不是正式审核通过**。未修改数据库、组织策略、Worker、HTTP、UI、全局台账或 Git。

root 集成复核：生产代码、共享 helper diff 与两份完整专有测试均已阅读；独立执行两个完整纯包 `-count=3`，evidencedisplay 1.034s、secret 0.525s 通过，相关 lint 0 issues。将这八个文件作为独立组件提交；上述“未执行 Git”指子任务原始工作边界，不代表 root 集成提交未发生。

## 原要求与本次边界

- PRD §9.8 REP-005 要求输出无真实 Key 的请求复现模板；§11.1 将完整请求/响应和 Endpoint 私有参数列为 S2，并要求可配置不落库、导出审计。
- PRD §11.2 的响应正文默认 30 天、0～180 天与脱敏摘要默认 180 天不是完整请求 S2 的自动授权。本组件不暗设请求保留默认值或上限；由后续组织级全 scope 策略明确并执行。测试里的 1 天或 181 天只证明密码组件不偷用响应天数，不是政策批准。
- TECH §8.2 的复现明文变量不得进入普通日志；§13.4 的自定义提示仍为 S2、纯文本转义；§13.5～13.6 的组织范围、授权/保留/成功审计仍须在服务释放之前实现。
- 原前置与完整授权读取方案见 `M5-DISPLAY-READ-IMPLEMENTATION-NOTES.md`。本次仅完成其独立 request-only 格式与专用密码能力，不因响应 0 天而要求伪造一个响应。

## 已落盘 API

`internal/integrity/evidencedisplay/request_reproduction.go`：

1. `RequestReproductionSource{Request, Snapshot, ManifestHash}`；必须由可信 Worker 在真实 `Credentials.Use` 内传实际冻结请求、实际全部 Header 值及签名清单的 hash。请求与 snapshot 一致性检查不是签名验证；任意调用者捏造一套相互匹配数据不构成可信捕获。
2. `PrepareRequestReproduction(ctx, source, key, headers)` 返回 `*PreparedRequestReproduction`。输入没有 Response、Endpoint 或 Header 元数据字段，且不会制造空响应调用旧 `Prepare`。
3. `PreparedRequestReproduction.BindingHashes()` 仅返回 manifest/request digest；`WithCanonicalForSeal` 仅用于可信加密 codec；`Close` 清除自身字节。`OpenedRequestReproduction` 只提供 `WithCanonicalForReproduction` 和 `Close`。两种私有字段类型与旧 display 的 Prepared/Opened 均不能相互转换。
4. `DecodeAuthenticatedRequestReproduction` 仅严格解析，必须在专用 AEAD 验证之后调用；没有认证或授权能力，不能制造可重新 Seal 的 Prepared。

固定 envelope 只有 `version=1`、`policy=request-redaction-v1`、`request_hash`、`template_hash`、`request_json`、`request_changed`。`template_hash` 是脱敏后规范请求字节的 SHA-256；`request_hash` 是实际未脱敏 wire hash；changed 明确二者是否不同。Manifest hash 存于受保护准备元数据并进入 AAD，不混进请求模板。

`internal/integrity/secret/request_reproduction.go`：

- `RequestReproductionBinding{Scope EvidenceScope, ManifestHash, CapturedAtMicros, ExpiresAtMicros}`。
- `RequestReproductionRecord{Version, Policy, KeyVersion, Nonce, Ciphertext, PlaintextBytes, PayloadHash}`。
- `KeyRing.NewRequestReproductionCapabilities(now)` 产生仅复制专用 key 的 `RequestReproductionSealer` / `RequestReproductionOpener`，不持有 KeyRing、不提供 raw/display/credential 解密 getter。可信启动可注入时钟，HTTP 不能提供时钟。
- `Seal(ctx, binding, prepared)` 与 `Open(ctx, binding, record)`；普通错误闭集为 `MI_REQUEST_REPRODUCTION_UNAVAILABLE`，取消沿用 `MI_DISPLAY_CANCELLED`，不返回原始 I/O、输入或秘密。

AAD 的字段顺序固定为：version、purpose=`request-reproduction`、policy、scope（organization/run/logical_sample/attempt/request_hash）、manifest_hash、captured_at_micros、expires_at_micros、key_version、plaintext_bytes、payload_hash。Seal 要求 Prepared 的 manifest/request 与 binding 完全一致；Open 要求外部可信期望的全部绑定一致。捕获时间必须为正且不晚于当前，expiry 必须晚于当前且晚于 capture；没有默认请求保留天数。

## 最小复用与兼容性

- `evidencedisplay/prepare.go` 仅将原请求验证提取为 `validateRequestSource(request,snapshot)`、原响应验证为 `validateResponseSource(response)`；`requestForDisplay` 改接显式 request/snapshot。旧 display 的格式、字段、哈希、策略及算法不变。
- 两用途共享同一个真实 OpenAI Chat adapter `BuildRequest`，固定 `.invalid` Endpoint 和禁止网络的 Doer。实际 payload/model/stream/max-token 参数/hash 必须完全一致；不是复制 adapter 编码。
- 两用途共享现有 `dictionary`、全部 Header **值**（不只鉴权名称）、14 个有限变体的确定性最长优先替换、疑似秘密拒绝、编码膨胀预算及 2 秒 cooperative deadline。固定 schema/numeric 字段与已知秘密碰撞时整份拒绝，不修改数值或跳过该秘密。
- request-only decoder 采用闭合的 request 字段/嵌套字段 schema；已验证请求仍由原 adapter 生成。保留 RawMessage/int64 seed；不会先转为 JavaScript/float64 后重建数字。未知/重复字段、尾随 JSON、不匹配 hash/changed、非法嵌套、伪 endpoint/header 字段均拒绝。
- `secret/envelope.go` 仅新增第十 purpose `mii/v1/request-reproduction/<key_version>`。原九 purpose、原测试 golden 未更改；新增公开合成 master 的独立 .NET HMAC-SHA256 extract/expand golden。

## 安全限制（不得扩大宣传）

- 模板不采集真实 transport Endpoint/Header 名称等元数据；真实 Key/全部 Header 值按既有有限算法脱敏。它不是能识别任意文本秘密的分类器：自由文本可能包含未进入字典的敏感资料、任意 URL 或 Header 名称，仍是 S2。多重变换/未知秘密不能被称为绝对无秘密；本单元未放宽原策略也未增加这种保证。
- 所有 Source/Prepared/Opened/binding/record/capability 的 value/pointer `fmt`、JSON、`slog` 均禁止普通内容序列化。受控回调获得的独立借用字节在返回/错误/panic 时清零，不持锁调用；不能强制清除可信调用者主动复制的 Go string/字节，也不能强制打断任意 callback 或内核 I/O。
- request JSON 最大 1 MiB、受保护 envelope 最大 4 MiB、字典与源输入维持现有上限；大载荷测试证明此文字组件的边界，不是数据库容量验收。
- 只有纯数据，没有 shell 字符串拼接、脚本执行、自动重放或真实 Endpoint。后续服务若提供操作说明，Endpoint/API Key 只能由使用者本地替换；不能把文本注入 shell 或原样用 innerHTML 渲染。
- AEAD 完成后再次检查捕获/到期与 context，失败不释放 Opened/record；但这不是当前权限/策略检查，更不承诺能够撤回已经交给网络的字节。
- 该组件不认证 SQL receipt 或 signed manifest，不防有能力一致重写整库的管理员。真实采集、SQL receipt、scope/签名、组织隔离、最终 fresh 授权与审计的完整链由下一集成单元落实。

## 已运行的纯验证

使用当前固定 Go 1.26.7；**没有运行 DB 测试**。

1. `go test ./internal/integrity/evidencedisplay ./internal/integrity/secret -count=3 -cover`：PASS，分别 0.980s / 0.692s；包覆盖率 87.4% / 83.1%。包含原九-purpose golden 与原 display 的全部回归。
2. 新纯层：14 变体 / 全 32 Header 值、双 max-token 映射、int64 两端和 ±9007199254740993、与旧 display 请求逐字相等、输入不变、模型/stop 脱敏、无响应依赖、受保护输出/借用清零/panic/取消/类型不可转换、大小与替换膨胀限制、900 KiB 请求、闭合 codec 的嵌套未知/重复/null/数字损坏/尾随值反例。
3. 新专用 crypto：真实 `Credentials.Use` → Prepare → Seal → Open；全部 AAD 维度（含 manifest）和 envelope 篡改；实际 raw/display 双向跨用途拒绝；保持完全相同 request AAD/plaintext，仅换成每一个旧 purpose 的真实派生 key 仍拒绝；真实轮换 active=two 且保留 one 可读旧记录，移除 one 或同版本换 master 均拒绝。
4. 12 并发复用；初次/最终时钟回调发生取消、到期或 panic 均不释放结果；无效/零值能力拒绝。现环境 `CGO_ENABLED=0`，本轮未声称通过 race detector。
5. `go test ./internal/integrity/secret -run '^$' -fuzz '^FuzzRequestReproductionChangedTagFails$' -fuzztime=3s -parallel=1`：PASS，5,514 executions，47 new interesting inputs，3.170s。
6. 两包 `golangci-lint run`：`0 issues.`。

## 下一装配，不在本单元交付范围

明确独立请求 S2 组织策略/默认值与不落库配置；新增不可回填猜测的 request capture/receipt/expiry；在真实 dispatch 前、真实 Credentials.Use 内捕获并绑定已有 attempt 与 manifest；双库原子持久及取消/恢复语义；按策略物理清理及不可复活删除凭证；受 `evidence.body` 等权限与成功审计约束的 prepare → fresh grant → bounded release；最终 HTTP/UI 纯文本模板与 0 天响应下真实端到端验收。只有这些完成后才能标记 REP-005 已开发完成。
