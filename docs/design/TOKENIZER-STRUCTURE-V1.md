# M3-04 / M3-05：离线计数与结构特征

本模块落实 TECH-SPEC 8.5.3、8.5.4、9.1、9.5、9.6 和 PRD MTOK-003/004/005。输出是样本特征和质量标签，不是篡改结论。9.7 的行为评分和跨样本归因由独立聚合分析器负责。

## 固定实现和离线资产

Go 依赖精确固定 `github.com/tiktoken-go/tokenizer v0.8.1`、`github.com/dlclark/regexp2/v2 v2.5.1`，保持 Go 1.26.7 / CGO_ENABLED=0。前者的词表编译到二进制，不在运行时下载词表。模块版本/提交与 license 来自 [维护者仓库](https://github.com/tiktoken-go/tokenizer/tree/v0.8.1) 和 Go module proxy，`go.sum` 固定模块内容；MIT 通知保留在 `internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md`，发行包必须包含它。

`NewBuiltin()` 第一次调用时验证嵌入配置的规范 JSON 和固定 SHA-256，再从内嵌词表按 rank 顺序重构 `base64(token_bytes) + 空格 + rank + LF`，计算以下官方原始资产摘要。源定义和模型映射冻结自 [OpenAI tiktoken 0.14.0](https://github.com/openai/tiktoken/tree/0.14.0)，不依据模型档案自报的 `exact`。

| 资产 | 词条数 | SHA-256 |
|---|---:|---|
| cl100k_base | 100256 | `223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7` |
| o200k_base | 199998 | `446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d` |

上述摘要由 [官方编码定义](https://github.com/openai/tiktoken/blob/0.14.0/tiktoken_ext/openai_public.py) 发布。配置版本 `1.0.0`，配置 SHA-256：`e63605c54793bca24d79c89ae4e0a66f37e4c8c5409cea795f52e63e7e5024ae`。加载失败必须使启动/就绪失败，不能静默信任篡改后的资产。`Load` 只接受本二进制冻结的配置与摘要；更新映射必须发布审核过的新包。

差异测试发现依赖库原有计数路径在 NUL 和混合换行上与官方参考实现不一致。因此只使用它的内嵌词表；实际计数使用 `mii-bpe-v1` 的有界、左侧优先合并及冻结的官方等价分词模式，绕过依赖的生成正则路径。逐段验证正则完全覆盖输入，禁止漏字后返回 `exact`。特殊 token 样式字符串按普通可见字符计数，相当于官方 `encode_ordinary`，不会被解释为协议控制 token。

## 接口和质量边界

```go
engine, err := tokenizer.NewBuiltin()
inputEstimate, err := engine.EstimateInput(normalizedRequest)
inputEstimate, err := engine.EstimateInputFor(normalizedRequest, selection)
outputEstimate, err := engine.CountOutput(content, selection)
usageFeature := tokenizer.CompareUsage(response, outputEstimate, reasoningModel)
features, err := structure.Analyze(structure.Input{ /* frozen contract + response metadata */ })
```

`Selection` 仅接受 `ReportedModel / RequestedModel / StandardModel`。依次查找这三个来源，在每个来源内优先显式映射，再查同族前缀；标准模型回退最高为 `compatible`。任意同族后缀不证明模型真实存在；显式模型映射的 `exact` 也只表示**在冻结编码下对可见字符串的精确计数**，不证明上游身份、隐藏消息、账单或真实 token 生成路径。未知编码（包括本包未实现的 harmony、SentencePiece 等）返回明确的 `heuristic`，不伪装为兼容。

输入 framing 固定估算为：角色与内容各自 token 数之和，加每条消息 4、回复起始 3，JSON object 响应格式额外 8。它依然只是输入估计，最高标 `compatible`，带 `MI_INPUT_FRAMING_ESTIMATED`。工具/多模态等未支持的 prompt 扩展明确拒绝，不能静默漏计。

`Tokens` 与 `BudgetTokens` 分开：精确可见输出无需估算系数；其余预算向上取整 `1.25 × reserve`。启发式显示计数为 ASCII 每四字符约一个 token、其他 Unicode 字符约一个；未知编码的预算另取更保守的原始字节数与 framing 作为下限，然后加安全系数。这不是对任意未知供应商隐藏预算的数学保证。`Tokens=nil, quality=unavailable` 明确表示无计数，不能当成 0 token。

资源边界：单次可见正文/总输入正文最大 1 MiB；BPE 最大 64 KiB、连续空白或非空白 run 1024 字节、总平方工作量 4 Mi 单位、单次 regex match 超时 100ms。总请求共享一个 BPE 工作上限，不能每条消息重新获得完整额度。超出 BPE 工作域但仍在正文上限内，完整正文使用启发式并标记降级；超出正文上限或非法 UTF-8 则不可用。每个 engine 最多两个并行 BPE 计算；调用方等待空闲槽，不生成后台计算，也不因瞬时负载改变结果质量。

## Usage 特征

默认相对误差为 `abs(reported_visible - local_visible) / max(local_visible, 1)`；exact/compatible 的单样本 5% 内为 normal、15% 内 warning、以上 mismatch。这里只产生单样本区间/方向，不能单样本输出 B 级。聚合仍须至少六个同方向有效样本、独立探针和适用性检查。

heuristic 阈值扩大为 10%/30%，`EligibleForAggregate=false` 且证据上限 C；调用方不得据此形成 Usage 伪造 B 级。推理模型没有可分离的 reasoning token 时跳过比较；已知 reasoning token 从 completion 中分离，负值或大于 completion 的元数据判不可用。输入估计禁止当作 completion 参与比较。

## 结构与结束特征

支持 JSON、逐行 JSON 对象、`NONCE|n` / 普通编号单元、Markdown 代码围栏和普通文本。JSON 检查语法以及对象/数组/字符串闭合；JSONL 可按冻结键（当前模板为 `n`）检查连续整数，拒绝重复键、字符串编号、缺号；末行不要求额外换行。代码围栏检查同种标记、长度、行首缩进和合法结尾。UTF-8 合法性与末尾边界分开；没有句号的短答仅为 unknown，不擅自判硬截断。

`StructureComplete`、`HardTruncation`、`TaskComplete`、`CompleteEarlyStop` 分开：未完成远大于输出预算的 COUNT，但最后一条完整闭合且编号连续，可以是正常自然提前结束，不是硬截断。

- `STOP + 明确硬截断`、正常 HTTP 流缺终止事件只形成样本提示。
- `LENGTH` 且 exact/compatible 的已知预算在请求值 ±10% 内，标 `NormalRequestedLimit`，不形成截断归因提示；远低于 70% 仅是待聚合的单样本提示。
- 推理预算不可分离时，不做精确长度矛盾比较；已知 reasoning token 加入请求预算比较。
- 内容过滤、拒答、工具调用、客户端取消/安全上限、协议和网络失败不按正常上游截断归因。

结构资源边界：正文 1 MiB、单行 64 KiB、10000 行、JSON 深度 64。资源上限返回显式错误/警告，不把客户端无法完成检查误记为上游截断。结果只包含数值、布尔、闭集状态/警告；输入的默认 JSON/格式化投影不暴露正文或随机标签。

## 验证与复现

固定 corpus 包含 759 个英文、中文、日文、阿拉伯语、印地语、组合字符、emoji、控制字符、换行、数字、特殊 token 字样及确定性随机组合。两种编码共 1518 个计数由实际官方 `tiktoken==0.14.0` 生成，保存于 `tokenizer/testdata/reference_counts.json`，默认 Go 测试完全离线对照。输入 corpus 摘要为 `bea11cca06962f03a56225706a9daf8dc111f439ee4ad17abb5f1be4ae03a8dc`。

额外实时差异测试 `TestDifferentialOfficialTiktoken014` 要求 `MII_TOKENIZER_REFERENCE_PYTHON` 指向仅供测试的 Python、其 `PYTHONPATH` 含 `tiktoken==0.14.0`，以及预先按官方摘要校验的 `TIKTOKEN_CACHE_DIR`。测试时可将 HTTP/HTTPS proxy 指向不可达 loopback，证明两端均离线。未配置 oracle 时只跳过这一项，固定 1518 向量仍必须通过。参考 Python 和缓存都在忽略的 `.tools` 中，不进入运行时依赖或发行包。

结构测试覆盖闭合与语法错误分离、末单元、重复/遗漏/超大编号、围栏边界、UTF-8、正常 length、自然短答、reasoning、协议失败和资源限额；另有变异 fuzz 与内容投影测试。没有调用收费模型 API。

当前边界：还没有新的 tokenizer 包动态发布/批准端点；不是任意模型编码平台。规则聚合、风险评分、生产启动接线、样本持久化及报告展示由上层模块接入后另行集成验证，不因本模块单元测试通过就宣称整体 M3 完成。
