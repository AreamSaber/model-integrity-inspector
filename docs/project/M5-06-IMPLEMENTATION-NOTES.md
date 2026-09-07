# M5-06 规则包回放、发布与退役：实施草案

状态：设计建议，未批准、未实现；不是 M5-06 / ALG-04 / M7-02 验收签署。

调查日期：2026-09-07；代码基点：`7f376a9`。

范围：在现有模块化单体内增加真实规则管理和离线回放；不修改冻结 PRD 指标，不把开发样例、人工复核或基线审批当作算法校准。

## 1. 结论与依据

应拆成五个可独立验证的 checkpoint：受支持的类型化规则制品与运行时解析器、真实离线回放、独立验收回执与准入、管理发布/退役、受控灰度。只增加规则 CRUD 或写入 `replay_metrics_json` 不能交付 M5-06。

主要依据：PRD 4、5、6、9.7～9.10、11、15.2、19；TECH 8、9、10.8～10.10、11.5、13、17、19、22、23；开发计划 M5-06、M7-02、ALG-01～04；ADR-0001/0002/0003/0005/0006。权重、证据分级、检出率与误报指标若变更，必须走现有变更控制，不由本草案批准。

PRD 15.2 要求规则发布者在验收时不能接触标签；TECH 17.3 / 数据集 README 的“发布负责人可见标签”应解释为**独立 QA 标签保管人**，不是开发/调参/点击规则发布的人。同一人兼任时不能声称盲验收，需在实施前由 TL、QA/ALG 明确职责与真实访问控制。

## 2. 已具备的基础与真实缺口

| 现有代码 | 已有能力 | 不能据此声称已完成的部分 |
|---|---|---|
| `internal/integrity/bundle/builtin.go` | 规则、模板、tokenizer、算法版本及参数的固定 SHA-256；开发限制显式记录 | 只有 `1.0.0-dev.1`，不是可加载任意新规则的发布解析器 |
| `repository/bootstrap_bundles.go` | 按组织安装内置 development 制品；同版本不同内容拒绝；确认 Run 时检查原字节与哈希 | 没有规则管理服务、回放、正式发布或退役流程；宽 JSON `ReplayMetricsJSON` 不是可信回执 |
| `probe/templates` / `probe/generator` | 类型化模板、有限占位符、不可变注册表；96-bit 随机变量、配对/分组、HMAC 冻结 Manifest、预算冻结与精确请求复现 | 模板是公开开发材料，未成为私有审核池；Manifest 当前没有单独规则内容哈希/运行时制品哈希 |
| `analysis/features` / `worker/analysis.go` | 实际队列租约、冻结 Manifest、最终 Attempt、AAD 解密证据绑定；本地 token/结构/行为分析 | 不能把普通输入 JSON 形状相同视为来源可信；自定义模板的合同映射仍未支持 |
| `analysis/tokenrisk` / `behavior` / `scoring` / `analyzer` | median/MAD、分组 bootstrap、完整配对族、BH、缺失重归一、内容无关 S1 输出及确定性规则测试 | 参数仍是多处 `Parameters()` 常量；没有校准回执构造路径；当前只能 C/D，不能正式 A/B |
| `repository/analysis_result.go` / `run/result.go` | 原子不可变 revision 1、Finding 引用、严格 S1 读取；版本/哈希闭集守卫 | 持久化与读取也只允许当前开发评分，不能只放宽一个常量完成多版本支持 |
| `tests/datasets` | 输入/控制 manifest/标签隔离；五分区、实际输入哈希、重复及 lineage 校验；生产导入防护 | 只有一个公开 development 案例；没有真实 calibration/regression/blind/gray 语料、指标 runner 或独立验收回执 |
| 身份、审计、队列、双库 | `rules.read` / `rules.manage`，会话与权限事务复验、组织审计链、60s 租约/15s 心跳及完成 fencing | 没有规则 replay Job 类型、组织活动规则指针、规则 CAS / 发布 / 退役元数据 |

特别需要保留的事实：标准 60 次计划的真实本地 tokenizer/结构合成回归中，固定 256 代理产生平台候选，但加权 Token 为 **41**；正常 Usage 和跨流对照仍是正常分母。本次没有调权把它凑成 60。公开开发评分最高 C，现状不能满足 AC02 的 B 级要求，也不能证明 95%/90%/85%/≤5%。

部分旧模块 README 仍写“未接入 API/Worker”；本表以已落盘实际 Worker、读取、报告和控制层为准，不据过时说明重复实现这些模块。

## 3. 类型化制品与受支持运行时

### 3.1 三类对象必须分开

1. **不可变制品**：规则、模板、tokenizer 的规范字节、版本、内容哈希。创建候选后内容不更新；调参/改模板创建新版本。展示名等非语义元数据如允许编辑，则单独 CAS，不能影响制品身份。
2. **运行时套件**：应用实际支持的 adapter/feature/structure/behavior/tokenrisk/scoring/generator 语义版本及实现哈希，以及允许的类型化参数/模板合同。不能只根据调用方给的版本字符串创建。
3. **可变组织选择**：已发布候选中的默认/灰度规则指针、CAS 版本、激活历史。它不能改变已冻结 Run 或旧报告。

建议新增 `RuleArtifactV1`，沿用当前字段语义但增加显式 schema、engine suite、evaluation policy 引用、每个规则 ID、实现枚举、参数类型和内容审核引用。Prompt/Token 权重等冻结约束必须验证；新增自由参数不意味着允许越过冻结约束。禁止可执行 Go/JS、任意表达式、SQL、动态插件、任意文件路径/URL、无界 regex 或通用 `map[string]any`。

规范化 decoder 必须拒绝未知/重复字段、非规范重复表示、尾部 JSON、非法 UTF-8、NaN/Inf、越界数字、重复规则 ID、不支持的实现与空规则集；先限制读取字节再解析。可复用模板 canonical equality 方法，但不能把仅做 `json.Unmarshal` 的 bootstrap 宽投影作为导入验证器。建议规则制品先沿用 1 MiB 硬上限，模板沿用 1 MiB/256 条/8 KiB 单模板上限；资源参数也进入规则制品身份。

模板语义必须是受控的 `exact_marker`、`single_json_field`、`sequence`、`jsonl`、已审核 neutral 合同等枚举，合同由模板审核后的元数据与真实 Manifest 派生。不能让任意 `assertions` 字符串或请求中的 `neutral=true` 获得中立任务资格。当前 `features.mapping` 和 `behavior.catalog` 仅认 builtin 的保护需替换为受审核目录能力，不能简单删除。

### 3.2 最小运行时接口方向

`RuntimeResolver.Resolve(frozenRef)` 返回私有字段的 `VerifiedRuntime`，绑定规则内容哈希、模板/tokenizer 哈希、算法参数及已验证准入状态；调用方不能通过 `Trusted=true`、`Calibrated=true` 或伪造 Result 获得它。HTTP 不绑定这些内部类型。

运行时构造器须把不可变 Rules 值显式传入每个核，消除内部遗漏的 `Parameters()` 全局读取。测试必须证明：改变允许参数会真实改变相应计算；改变制品哈希不能仍按旧参数执行；旧制品输出 byte-for-byte 可重放。版本解析失败、所需词表不存在、语义实现未知时失败关闭，不能回退当前默认版本。

完整接线面至少包括 app bootstrap、Run 估算/确认、generator Verify、Worker Analyze、features 合同、tokenrisk/scoring、发布验证、结果/报告 DTO 及前端闭集版本说明。禁止仅把 `validPublication` 的 C/D 改为 A/B/C/D；证据等级许可必须来自同一受信运行时，且没有网关 verifier 时始终不能 A。合格规则也不自动让未校准基线参与 D。

V1 首选 ADR-0005 的同版本 Server/Worker，启动对完整受支持套件清单做哈希校验。需要混合版本滚动升级时，必须先有节点 capability / 派发隔离，防止新规则 Job 被不支持的 Worker 反复领取失败；此前用暂停新任务、排空、同版升级，不假装已支持任意混部。

## 4. 可执行的离线回放路线

### 4.1 两条不同权限的通道

- **组织诊断回放**：从用户有权读取的已闭合 Run、不可变版本与仍存在的 S2 证据构建私有回放源；无标签、无新增上游请求；用于版本差异诊断，不产生正式验收资格。缺正文/过期则明确不可重放或 partial，不能用 S1 风险值倒造证据。需要 `rules.manage` 和 S2 对应授权/审计，不通过队列载荷传正文。
- **独立 QA 验收回放**：独立离线命令及用户/文件系统，从经过冻结的数据集捕获源运行同一生产算法；开发者、规则发布者看不到标签/控制 manifest/故障 seed。独立 evaluator 在预测封存后才把标签加入计算。生产 `cmd/mii` 和 `internal/**` 继续禁止导入 `tests/datasets` 或 mock 控制器。

建议测试工具放 `tests/replay/cmd/...`，先交付不需数据库、无网络、可取消的批量 CLI。此工具是质量工程制品，不是新增生产微服务/基础设施依赖；UI 后台回放仍遵守数据库 Job。命令参数只接受显式本地受控制品目录和输出目录，不自动下载规则/语料，不启动收费 API。

### 4.2 现有数据输入需补的真实捕获层

`tests/datasets.Input` 只有粗粒度 request/response/tokenizer 快照；没有足够的冻结模板、tier/GroupID/PairID/合同、最终重试、原始 SSE 及 request hash 绑定。特别是 `Tokenizer.Quality` 和 `LocalTokenCount` 是输入值，不能直接提升为 exact。现格式可用于开发单核测试，不能直接声称完成生产全链路 replay。

建议增加独立版本的 `ReplayCapture`：每个案例是一整个逻辑 Run，包含受冻结生成器验证的 Manifest/源 artifact refs、完成的 logical samples、唯一 final Attempt 选择、请求规范字节、有限原始 HTTP/SSE 响应字节和实际时间/终止/错误记录。只允许合成探针，不夹带业务正文。与标签分开的捕获程序绑定来源并封存原始字节哈希；“捕获受信”不等于“模型可信”。

离线 adapter 用真实请求 serializer 和真实 HTTP/SSE parser 处理这些字节，再走相同 tokenizer→structure/behavior→tokenrisk/scoring；tokenizer 重新本地计算，忽略输入自报 exact。对旧 normalized-only 快照应明确降级为 component replay，不能用于协议/SSE 验收。不伪造生产 Worker/AAD 身份：QA 捕获能力是单独命名、仅离线工具可构造的来源；共享纯映射代码，但不新增生产 HTTP 可调用的跳过身份校验入口。

同一 capture 只能回放与其真实请求/模板合同兼容的新分析参数；候选若改变探针文案、采样分配或请求参数，必须重新获得该候选生成的冻结 captures。不能把旧响应重新贴上新模板标签当作实验已发生。新 captures 可先来自隔离的实际 mock，若涉及真实收费上游则另行授权；纯 offline replay 本身始终不访问网络。

批处理顺序：

1. 校验候选制品、冻结评价计划、数据集 partition/input hash 与 capture 格式；拒绝无界载荷及路径逃逸。
2. detector 子进程只读取不含标签的 opaque capture stream。无网络、无父目录/控制器挂载、只读输入；输出仅封闭 S1 预测与证据引用。
3. 案例按冻结顺序处理；最终 Attempt 去重；分组 bootstrap 使用原 GroupID/seed；固定整个 hypothesis family；取消/超限/崩溃有显式失败记录，不能只输出成功案例。
4. 封存所有案例预测、规则及运行时 hash、输入集 hash、错误/缺失清单与 prediction hash。不得在封存后重写预测或选择“较好”的 retry。
5. evaluator 验证封存与案例一一对应后，在独立进程读取标签计算指标、证据覆盖和区间；输出签名回执及 QA 私有明细。

对总输入/案例数/每案例 150 个计划样本与算法现有 512 上限、重试数、正文、SSE 帧、内存和耗时分别限流。数据集可分块流式读取，但统计基于完整冻结成员集，不能用分块丢弃失败尾部。现有 16 MiB 单输入限制仅是起点，最终吞吐/内存配额须用真实规模测试后冻结。

## 5. 指标、分母及独立验收

| 冻结要求 | evaluator 必须输出的原始计数与约束 |
|---|---|
| 固定上限检出率 ≥95% | `detected_fixed / eligible_fixed`；正样本是独立案例/Run，不是单 Run 内 60 行或 retry；实际 AC02 仍需可解释 B，不以平台候选存在代替 |
| 分段/概率上限检出率 ≥90% | 独立预声明分层与总体 TP/FN；控制器记录实际实现的干预，未触发概率干预不能悄悄搬组；现有合并 coverage enum 需补明确子层 |
| 稳定隐藏影响检出率 ≥85% | 依预冻结正判规则和独立案例计数，区分安全策略/语言能力/正常风格；模型自述永远不算 TP |
| 正常及困难阴性误报率 ≤5% | 全阴性与自然 EOS、安全拒绝、unknown tokenizer、reasoning、网络错误等分层 FP/TN；不能把 insufficient 全当健康来压低 FP |
| 证据链覆盖 100% | 每个必需结论/命中能解析到准确 rule ID+版本+哈希、阈值/实测值、有效逻辑样本、capture/prediction hash；引用实际存在且同 scope，不能用非空数组代替 |

发布代码对签名整数分子/分母按有界整数交叉乘法重算指标，不能信任导入百分比或 `passed=true`。零分母、缺类、缺必需结论或空回放都是不可验收，不把 0/0 当 100%。负样本无 Finding 时也需完整可复核的判断/缺失说明，不能靠少输出 Findings 满足覆盖。

评价计划须在看独立验收预测/标签前冻结：阳性判断使用哪个维度/阈值/证据等级、每类最小独立案例数/lineage 数、模型/语言/tokenizer 分层、失败与 unavailable 处理、重复验收次数、效应量/区间方法、完整多重检验族。当前文档只冻结百分比，没有充分样本量；不能由代码临时用一两个案例宣布达标。QA/ALG 需提交有依据的 N/效能方案；本草案不擅自添加新的审批数字。

保留所有计划案例总数、有效数、abstention、invalid、超限、缺证据及原因。正类的分析失败/信息不足不得默默排出正类分母而只统计容易案例；负类另报覆盖率和 abstention，避免全 D 模型获得“低误报”。确需排除基础设施失效案例时，按事前冻结规则标记整次验收 invalid 或公开排除，不能看结果后删除。

区间与效应量单列；共享 lineage/nonce 的相关案例不能按独立 Bernoulli 扩大 N。bootstrap 的不确定性和比例区间方法本身也要版本化。PRD 目前是点估计门槛；若要把置信区间下界作为新的硬门槛，另行批准，不能暗改指标。BH 只控制其完整声明的假设族，不等于整套真实性规则的整体误报已校准。

五个分区应冻结全局 lineage 图和实际输入哈希；精确重复、改名重复与同源变体跨分区拒绝，语义近重复还需独立人工复核。当前 coverage 检查只证明类别存在；不能拿一个多标签案例满足全部准确率/样本量要求。公开开发模板/案例保留 development 标签，不改名后放入 blind；新私有审核模板需真实安全审核与隔离。

### 校准与 B 级验收的先后关系

先在 calibration 分区调参并冻结新 candidate，产生与候选精确哈希绑定的校准记录；然后独立 blind 验收该不可变候选。校准记录只能允许**隔离 QA evaluation 域**执行该候选的正式证据政策，结果明确非生产发布；生产 resolver 还必须验证独立 blind 回执与发布事实。这样不会用当前开发 C 上限假冒 B，也不需要先把未验收候选开放给生产用户才能验收。

校准缺失则候选仍发展性/C/D；开发包原版本不能升级为“已校准”。真实 calibration/evaluation 入口由私有 verified capability 控制，而不是新增 HTTP `allow_b=true`。没有真实网关验证器，QA 和生产都不能 A。基线 D 的准入是另一能力，规则合格也不能把 organization-declared 基线变为官方证据。

## 6. 不可由普通调用者伪造的回执边界

### 6.1 推荐：独立 QA 离线签名

候选冻结后由系统生成一次性、组织/候选/评价计划绑定的随机 challenge。独立 evaluator 的签名私钥留在 QA 离线环境，生产仅通过受控部署安装公钥信任根与 key ID；普通规则管理员不能上传一个公钥给自己的结果背书。建议使用 Go 标准库 Ed25519 的固定签名格式，无新增运行依赖；这属于 evaluator 身份认证，不声称已交付所有发行包供应链签名。

回执规范字节至少绑定：schema/key ID、组织/候选 ID+version+content hash、runtime/build hash、模板/tokenizer hash、评价计划 hash、数据集版本/成员集承诺、标签承诺、calibration 与 blind 分区标识、prediction hash、完整分子/分母/缺失/证据覆盖、开始/完成时间、challenge、签名。label commitment 加独立随机盐并留 QA 原始核验材料，避免公开低熵标签哈希成为猜测入口。类型字段全部有界，签名覆盖所有准入相关字节。

应用验签后仍复验组织、制品原字节、支持版本、审批权限、challenge 状态/有效期、回执用途/分区、calibration 与 acceptance lineage 不相交的 QA 声明、指标内部和总数一致性、固定门槛。复用一张别组织/别候选/已消费/过期或部分修改回执必须拒绝。幂等重试仅返回同一已保存回执，不重新消费另一个 challenge。

签名证明的是受信 evaluator 对这些记录负责，**不是密码学证明标签真实、数据足够独立或执行环境未串通**。这些仍依赖真实 QA 访问隔离、冻结材料、独立复核和可重跑证据。与 ADR-0006 一致，不声称抵御同时控制主机、二进制、信任根及 QA 私钥的联合特权主体。

单纯用应用主密钥 HMAC 包一段用户 JSON 不能证明独立验收；它最多证明应用曾收到该 JSON。不得提供通用“上传指标并标已通过”接口，也不得允许规则发布者选择签名器 URL/KMS/public key。

### 6.2 无离线签名基础设施时的受控替代

可以由独立运维/QA 在独立主机执行专用离线 import 命令：加载实际受控 captures、封存 predictions、私有标签及冻结策略，**本地重新计算并验证**全部度量后产生服务接受的收据。命令不接受单独 `metrics.json` 就宣告通过；凭证和文件读取范围需要独立管理，不能公开 Web endpoint。若只有同一发布者手填 JSON/运行命令、没有真实职责隔离，该记录只能标记 operator-reported/development，不能放行正式发布。

### 6.3 防验收结果成为调参 oracle

发布者不读取 blind per-case 标签、故障类别、控制 seed、case 级错误明细或可反推出标签的对照下载。S1 也可能泄露验收标签，不能因为“不含正文”就全量开放。对 publisher 只返回预声明聚合/限制；详细验收材料只给独立 QA。

同一 heldout 上反复看 aggregate/pass-fail 也会泄漏。challenge 必须绑定冻结提交；限制预声明次数，失败保留记录，若据结果调参则更换独立 holdout。开发/回归回放可以重复，但不能再自称 blind。技术访问控制不能代替组织监督，相关暴露须使验收失效而非继续累计成功率。

## 7. 仓储、API、权限与审计建议

本节仅设计，不占用迁移编号、不修改既有合同。迁移采用 expand，1～现有版本均冻结。建议新增/扩展：

- Rule Bundle：CAS `version` 与语义版本字段分名；immutable content hash；runtime/evaluation refs；publisher/published_at、retired_by/at、封闭 reason code。现有 development 行保持原字节和状态，不被迁移提升。
- `integrity_rule_replays`：组织、候选、用途、dataset/plan refs、状态、进度计数、取消标记、Job、创建者及时间、CAS。Job 只带 replay ID；对象与 enqueue 同事务。
- `integrity_rule_replay_receipts`：追加式规范回执/签名/哈希及索引化分子分母、challenge refs；不覆盖上一失败/作废回执。
- `integrity_rule_admission_challenges`：组织/候选/评价 hash、截止时间、唯一 consumption/receipt 关系。
- `integrity_rule_activations`：组织默认/灰度指针、比例、CAS、rollout salt/hash、前一指针及追加式变更记录。具体灰度 P1 可后交，但默认选择不能藏在可修改 rules JSON 里。

所有外键按 `(organization_id, id)` 约束；列表只投影有界 S1 列，不取 content/receipt 大 JSON。按组织+状态+created_at/id 建索引；采用已实现的 SQLite deferred / PG repeatable-read 只读快照和 SQL 字节上限。签名游标绑定 user/org/筛选；可变状态不能导致旧 anchor 分页失效。

合同沿用 TECH 既定 `/api/v1/rule-bundles` 与 `/{id}/replay|publish|retire`；补 `/{id}`、`/{id}/replays` 和回放详情/取消的明确 S1 DTO。创建内容只能是上述受支持 typed artifact；内部类型、模板明文、任意 raw replay JSON 不直接序列化。HTTP IDs 十进制字符串、CAS 正整数、Strict JSON、组织 header 与 path 对齐、写入 CSRF/幂等语义沿用现有实现。无法验收与已失败必须显示真实原因，不能通过 disabled 按钮代替服务拒绝。

权限建议先复用 `rules.read`（组织 S1 列表/详情）和 `rules.manage`（创建/诊断 replay/发布/退役），按冻结“仅管理员编辑规则”要求在敏感事务复验实际组织 admin 身份；系统管理员不自动跨组织。附加 permission 不能让非 admin 绕过此冻结限制。若要允许 QA/operator 单独触发回放或发布职责分离，新增细粒度权限应先冻结矩阵，不借此任务静默扩权。QA 标签/签名私钥不属于这两个应用权限。

事务内固定复验 Session、User 启用/临时改密/锁定、Membership、当前权限、候选 CAS/生命周期、immutable hash、回执签名/用途/未失效及 runtime 支持。并发撤权、退出、退休、内容变化不能在 handler 检查后继续成功发布。慢 replay/签名外部计算在事务外，短事务提交时重新验证绑定事实；签名对象字节不可变，状态变化则 CAS 失败。

创建、回放请求/取消、回执导入/失效、发布、激活、退役同事务审计；审计失败业务回滚。审计只写对象/版本/哈希/闭集原因、脱敏差异，不能写模板/响应/标签/私钥。后台完成使用现有租约 owner+generation+到期 fencing；进程崩溃、重复回放完成、超时取消不得制造两个可使用回执。

## 8. 发布、退役与灰度状态语义

内容生命周期：`candidate → published → retired`；已安装 `development` 仍是受限开发版本，不能原地冒充正式 `published`。回放的 pending/running/completed/failed/cancelled/invalid 是独立状态；completed 仅代表计算完成，不等于 acceptance passed。

发布必须同时满足候选内容/runtime/template/tokenizer 支持、真实内容审核、校准+独立验收回执、门槛/覆盖、组织权限、CAS 和审计。组织发布不等于 TL/PO/OPS/SEC 对项目里程碑签字。发布、选择默认、灰度扩量可以是分别审计的命令，避免创建即面向所有未来 Run。

估算时解析并冻结确切 rule hash/runtime/activation revision，报价、确认、分析都使用同一套件。确认前仅“默认规则换了”不自动替用户换版本；原规则仍可选择时保持原报价，否则明确冲突并重新估算。确认后退休只禁止新选择，不改变已派发 Run/原报告；若是紧急安全撤销，则显式暂停未发部分并记录取消/限制，不能替换旧算法伪装完成。

旧 Run 永远带原规则、模板、tokenizer、scoring 和运行时引用；旧制品至少保留到全部关联证据/结果/报告保留期及备份恢复窗口结束。历史读取优先保存的 S1 revision；重分析仅新增 revision，不能更新 revision 1 或原报告哈希。当前仓库仅实现 revision 1，本任务不顺手实现重分析。

灰度按组织启用、受控目标 allowlist 和确定性散列选择候选；分配在 Manifest 里冻结。先真实 3 正常/3 控制异常及误报复核，再按 TECH23 的独立授权少量真实目标/预算运行观察期。公开 mock 回归不等于真实 gray。默认不做收费 shadow 双调用；同一已保存响应做本地新规则分析可另记诊断，不混成两次独立实验。

回滚是 CAS 切回仍可选择且受支持的上一制品，停止新候选任务并保留数据；没有安全回退项时暂停创建，不隐式启用已退役版本。并发失败、Worker 不兼容、错误率/证据缺失/预算异常的停止条件应提前冻结，不能上线后用风险分下降当作自动成功信号。

## 9. 实施拆分与验收测试

| Checkpoint | 可实际交付 | 仍需显式保留的未完成边界 |
|---|---|---|
| A. 制品/运行时 | 严格 decoder、支持套件解析器、参数真实注入、双版本结果复现、旧开发行为不变 | 不意味着校准完成；未知模板语义拒绝 |
| B. 离线回放 | capture v2、无网络 parser→完整核、封存预测、计数/区间/证据验证的 CLI、真实合成正阴性 | 合成计算仍是 development，不能用自编测试当 blind |
| C. 验收准入 | 校准/独立验收两域、独立签名或受控重算导入、challenge 防重放、计算型门槛、审计 | 实际私人语料、N 方案、内容审核、独立执行与签署必须真实完成 |
| D. 管理/异步 | 双库迁移、RBAC/CAS 生命周期、诊断 replay Job、S1 API/页面、原版本保持 | 不替代 M7/M8 项目级 Gate；若真实回执缺失发布必须拒绝 |
| E. 灰度/回滚 | 显式激活、冻结分配、兼容节点/维护升级、观察与回滚实测 | 少量真实收费请求需额外明确授权，不由实现任务推断 |

关键测试必须包含：

- 内容/版本/参数漂移、未知算法/模板/词表、伪造 hash、重复 JSON、巨型/非 UTF-8 文档、读取前字节限制；旧规则输出恒定、新参数确实生效。
- retry 去重、共享 group/lineage 不膨胀 N、缺 final、缺一类/零分母、全 D/全 unavailable、分段概率实际干预分层、100% 覆盖少一条即拒绝；对已知手算指标边界做精确比较。
- 固定上限/概率上限/隐藏影响阳性，正常 length、自然 EOS、安全拒绝、身份自述、语言能力、启发式 tokenizer、reasoning、stream-only、网络错误困难阴性；完整标准计划而非只挑有利探针。
- 标签或控制 manifest 注入 detector 拒绝；文件路径/symlink/目录越界、外网访问、case ID 侧信道；预测 sealed 后修改、删失败案例、重复/跨 split lineage 必须失败。
- 伪造/错 key/撤销 key/篡改 signature、跨组织/候选/政策/分区回执、过期 challenge、重复使用、失败回执改 passed、校准回执冒充 blind、开发模板重命名冒充私有包全部拒绝。
- SQLite 与真实 PostgreSQL：并发 publish/retire/CAS、审批期间权限撤销/临时改密/会话退出、审计失败原子回滚、Job 完成 fencing/崩溃恢复/取消、列表不阻塞写与快照一致性。
- 默认规则切换不改已确认 Run；确认和退休竞态；旧结果/报告读取不重算；升级回滚留数据、旧 runtime 缺失失败关闭；未经证明不能 A/B。

## 10. 本次验证与下一步需要确认的决定

本次仅只读调查并新增此草案，没有改 Go、前端、迁移、OpenAPI 或既有文档，没有发起收费请求。

2026-09-07 在本地固定工具链执行以下定向测试，全部 PASS：

```powershell
$env:CGO_ENABLED='0'
& .tools/go/bin/go.exe test ./internal/integrity/bundle ./internal/integrity/probe/templates ./internal/integrity/probe/generator ./internal/integrity/analysis/behavior ./internal/integrity/analysis/tokenrisk ./internal/integrity/analysis/scoring ./tests/datasets -count=1
```

这些测试证明现有实现不变量，不证明独立数据集门槛通过；没有运行新增 replay runner（尚不存在），没有产生真实校准/独立验收签名。

进入实现前由 root/TL/QA 对齐：独立标签保管人与 publisher 职责；签名或受控离线重算边界及公钥安装职责；冻结评价计划/N/分层/abstention 规则；私有模板安全审核的实际来源；最小可执行 runtime 参数化范围与多版本兼容；管理员附加权限边界；迁移和模块所有权。完成 A/B/D 工程能力后若仍无真实 C 材料，应标为“工程能力已实现、正式发布准入未满足”，不将 M5-06 整项伪报完成。
