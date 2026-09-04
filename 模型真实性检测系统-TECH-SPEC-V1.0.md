# 模型真实性检测系统 TECH SPEC

版本：V1.0  
状态：V1.0 冻结版  
日期：2026-09-04  
冻结日期：2026-09-04  
冻结依据：`docs/decisions/M0-01-V1.0-决策记录.md`  
对应 PRD：《模型真实性检测系统 PRD V1.0》  
项目形态：独立仓库、独立应用、独立数据库与账号体系

---

## 1. 文档目标

本文给出模型真实性检测系统 V1.0 的可实施技术规格，包括系统边界、总体架构、模块职责、协议适配、任务状态机、数据模型、API、探针生成、算法判定、评分、密钥和网络安全、可观测性、测试、部署、迁移及研发任务拆分。

本文默认：

- 首版检测 OpenAI-compatible Chat Completions 文本接口；
- 检测任务独立于生产请求链路执行，不把探针混入真实用户请求；
- 作为独立项目整体交付，不导入或调用其他业务项目的代码、数据库或内部接口；
- 后端采用 Go，前端采用 React + TypeScript，版本由项目清单锁定；
- 系统自带用户、组织、RBAC、供应商、模型档案、密钥、任务队列、报告和审计能力；
- 单机模式支持 SQLite；标准生产模式使用 PostgreSQL；
- 默认任务队列基于数据库租约实现，不强制依赖 Redis、消息队列或对象存储；
- 黑盒结果表达为异常风险，只有受控网关观测数据才能形成 A 级直接证据。

---

## 2. 设计原则

1. **证据优先**：评分必须能追溯到规则、统计量和样本。
2. **实验隔离**：检测流量使用独立队列、限流和预算，不挤占管理面资源。
3. **规则版本化**：探针模板、判定规则、评分权重和 tokenizer 配置全部冻结到任务。
4. **最小数据**：仅使用合成探针；默认保存脱敏摘要，不保存 API Key 明文。
5. **统计而非单点判断**：禁止用一次短输出或模型自述直接判定篡改。
6. **协议异常不等于模型异常**：适配失败、限流、网络错误首先归为有效性问题。
7. **适用性显式化**：推理模型、未知 tokenizer、不支持 seed 的接口应降低置信度或跳过规则。
8. **安全失败**：队列、分析或报告失败时，管理端仍可查询历史数据并执行恢复操作。
9. **可校准**：阈值和权重来自冻结数据集，可回放、可灰度、可回滚。
10. **不可抵赖审计**：密钥变更、规则发布、报告导出和人工复核必须留痕。

---

## 3. 系统边界与模式

### 3.1 黑盒模式（V1.0 默认）

输入：Endpoint、API Key、模型名、协议参数。  
可观测：客户端实际发送内容、HTTP/SSE 响应、Usage、响应头白名单、耗时。  
结论上限：B 级强统计证据。

### 3.2 对照模式（V1.0）

待测目标与可信基线使用相同探针变量和等价参数分别调用。分析器执行成对或分布比较。基线可以是官方接口，也可以是人工审核通过的稳定历史批次。V1.0 由各组织自行维护和审批基线、提供调用凭证并承担调用费用，不内置跨组织共享官方账号。

### 3.3 网关观测模式（V1.1 接口预留）

如果检测器部署在自有代理网关内，可额外记录：

- 入站规范化参数；
- 参数覆盖后的出站摘要；
- 转换链和规则 ID；
- 出站请求哈希；
- 上游原始结束原因。

该模式可直接证明自有网关是否修改参数，形成 A 级证据。V1.0 数据结构预留 `observation_mode` 和 `gateway_evidence_id`，但不强制实现采集器。

### 3.4 明确排除

- 不读取或破解供应商内部系统提示词；
- 不对第三方系统执行越权测试；
- 不使用真实用户业务输入作为检测样本；
- 不自动修改生产渠道开关；
- 不在热路径同步写检测明细。

---

## 4. 总体架构

```text
┌──────────────────────── 独立 Web 管理端 ──────────────────────────────┐
│ 登录/组织  供应商/模型  目标  检测  结果/证据  基线  规则  审计       │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Internal REST + SSE
┌──────────────────────────────▼─────────────────────────────────────────┐
│ Control API                                                          │
│ RBAC │ Target │ Secret │ Run │ Baseline │ Report │ Audit             │
└───────────────┬──────────────────────────┬─────────────────────────────┘
                │ DB transaction/outbox   │ query
        ┌───────▼────────┐          ┌──────▼─────────┐
        │ Database Jobs │          │ Project DB    │
        └───────┬────────┘          └────────────────┘
                │
┌───────────────▼──────────────── Detection Worker ─────────────────────┐
│ Scheduler → Probe Generator → Protocol Adapter → Safe HTTP Client     │
│                         ↓                         ↓                    │
│                   Sample Store ← Response Parser / Token Estimator    │
└────────────────────────┬──────────────────────────────────────────────┘
                         │ run completed
┌────────────────────────▼──────────────────────────────────────────────┐
│ Analyzer                                                            │
│ Sample Rules → Probe Aggregation → Baseline Compare → Score/Confidence│
└────────────────────────┬──────────────────────────────────────────────┘
                         │
               ┌─────────▼─────────┐
               │ Report Generator │
               └───────────────────┘
```

### 4.1 部署单元

MVP 由本项目构建的同一 Go 二进制承载静态前端、Control API、Worker 和 Analyzer，但代码模块保持解耦。通过配置控制角色：

```text
APP_ROLE=server | worker | all
```

单机模式只需要应用二进制和一个可写数据目录，默认使用 SQLite，可用于小规模正式部署；精确并发和容量上限由 M7 性能验收冻结。标准生产模式必须使用 PostgreSQL，建议：

- 2 个 Server 实例；
- 2 个 Worker 实例；
- PostgreSQL（由本项目部署清单提供）；
- 共享报告存储卷；
- 独立密钥主密钥文件或可选 KMS。

Redis、外部对象存储、OIDC 和 KMS 都只能作为可选增强，不得成为默认安装的强制依赖。

### 4.2 独立项目边界

- 项目拥有独立的代码仓库、版本号、构建流水线、镜像和发布包；
- 项目拥有用户、组织、角色、供应商、模型档案、目标、任务和报告等全部主数据；
- 项目只通过公开模型协议调用被测 Endpoint，不读取外部业务数据库；
- 核心功能不要求安装任何第三方业务项目、插件或私有 SDK；
- 可选外部集成统一通过版本化 REST API、Webhook、OIDC 或存储适配器完成；
- 删除任何可选集成都不能阻止用户登录、创建目标、运行检测和查看报告；
- 升级和回滚只操作本项目的数据库对象、数据目录与服务。

### 4.3 技术栈与仓库

建议单仓库：

```text
model-integrity-inspector/
  cmd/mii/                 # 单一可执行入口，APP_ROLE 控制 Server/Worker/All
  internal/                # 后端领域模块
  web/                     # React + TypeScript 管理端
  migrations/              # PostgreSQL/SQLite 迁移
  rules/                   # 内置规则和模板包
  deploy/docker-compose/   # 标准部署
  deploy/helm/             # P1
  tests/mock-upstream/     # 可控异常代理
```

基础选择：

| 层 | 默认实现 | 独立部署说明 |
|---|---|---|
| 后端 | Go 标准 HTTP 栈 + 明确选定的路由/ORM 库 | 编译为单一可执行文件 |
| 前端 | React + TypeScript + Vite | 构建后嵌入 Go 二进制 |
| 数据库 | SQLite（单机）/PostgreSQL（生产） | 迁移工具内置 |
| 任务队列 | 数据库 Job + 租约 | 不强制 Redis |
| 报告存储 | 本地/共享文件系统 | S3-compatible 为可选适配器 |
| 认证 | 本地账号 + 安全 Cookie 会话 | OIDC 为可选适配器 |
| 密钥保护 | 主密钥文件/环境注入 + 信封加密 | KMS 为可选适配器 |

所有第三方库必须锁版本并生成 SBOM；不得引用其他业务项目的源码包。

---

## 5. 模块职责

### 5.0 Identity 与系统管理

- 首次启动初始化首个组织和管理员；
- 本地用户名/密码登录、退出、密码修改和会话吊销；
- 用户、组织、成员、角色和权限管理；
- 密码使用 Argon2id 等内存困难算法保存，参数随版本记录；
- Web 会话使用 `HttpOnly + Secure + SameSite` Cookie，并提供 CSRF 防护；
- 登录限速、失败锁定、管理员操作审计和紧急恢复流程；
- 可选 OIDC 登录通过适配器启用，不影响本地账号体系；
- 系统设置、健康状态、版本、迁移状态和许可证信息（如未来需要）由本模块提供。

### 5.1 Control API

- 调用独立 Identity 模块完成会话鉴权和 RBAC；
- 目标 CRUD、密钥更新、连通性预检；
- 检测任务创建、成本预估、取消和查询；
- 基线审核和绑定；
- 人工复核、报告导出、审计查询；
- 规则包管理和发布。

### 5.2 Probe Generator

- 从已发布模板生成本次任务的具体样本；
- 生成 CSPRNG nonce、随机标签、顺序和同义变体；
- 生成同批待测/基线共享的配对变量；
- 验证预计长度、内容安全级别和参数合法性；
- 输出不可变 `probe_manifest`。

### 5.3 Scheduler

- 按目标、组织和全局并发限制派发样本；
- 执行预算、超时、熔断、重试和提前停止；
- 公平调度不同组织；
- 检测取消标记并停止未发出的样本。

### 5.4 Protocol Adapter

统一接口：

```go
type Adapter interface {
    ValidateTarget(ctx context.Context, target TargetRuntime) PrecheckResult
    BuildRequest(ctx context.Context, sample PlannedSample) (*http.Request, RequestSnapshot, error)
    ParseNonStream(resp *http.Response) (NormalizedResponse, error)
    ParseStream(resp *http.Response, sink StreamEventSink) (NormalizedResponse, error)
    EstimateUsage(req RequestSnapshot, resp NormalizedResponse, cfg TokenizerConfig) UsageEstimate
    Capabilities() AdapterCapabilities
}
```

V1.0 实现 `OpenAIChatCompletionsAdapter`。Responses API、Anthropic 和 Gemini 使用新 Adapter 扩展。

### 5.5 Safe HTTP Client

- SSRF 防护和 Endpoint 白名单；
- DNS 解析与目标 IP 固定；
- 连接、首字节、总请求和空闲流超时；
- 限制重定向，默认禁止；
- TLS 校验；
- 请求/响应大小限制；
- Header 白名单和敏感 Header 脱敏；
- 连接池按目标隔离，避免跨目标凭证污染。

### 5.6 Response Parser

规范化不同供应商响应：

```go
type NormalizedResponse struct {
    ProviderRequestID string
    ModelReported     string
    Content           string
    FinishReason      string
    PromptTokens      *int64
    CompletionTokens  *int64
    TotalTokens       *int64
    ReasoningTokens   *int64
    HTTPStatus        int
    ContentType       string
    FirstByteMs       int64
    FirstTokenMs      *int64
    DurationMs        int64
    StreamChunkCount  int
    StreamTerminated  bool
    ParseWarnings     []string
    HeaderSummary     map[string]string
}
```

### 5.7 Analyzer

- 样本有效性判定；
- 样本特征提取；
- 样本级规则；
- 探针级统计；
- 基线对比；
- 风险、置信度和证据等级计算；
- 形成结构化 Finding。

### 5.8 Report Generator

- 从冻结的结果快照生成 HTML/JSON；
- 报告包含内容哈希、版本和免责声明；
- 导出不访问已轮换或已删除的密钥；
- 报告失败可幂等重试。

---

## 6. 任务与样本执行模型

### 6.1 层级

```text
Run
 ├─ ProbeInstance: format_contract/zh/variant-2
 │   ├─ LogicalSample #1
 │   │   ├─ Attempt #1（网络超时）
 │   │   └─ Attempt #2（成功，参与统计）
 │   └─ LogicalSample #2
 └─ ProbeInstance: max_token_ladder/512
```

重试 Attempt 不能当成独立统计样本。只有每个 LogicalSample 的最终有效 Attempt 参与算法，所有 Attempt 均保留错误和计费记录。

### 6.2 Run 状态机

```text
DRAFT → PRECHECKING → QUEUED → RUNNING → ANALYZING → COMPLETED
                    ↘ FAILED       ↘ PARTIAL
                       ↑             ↘ REVIEW_REQUIRED
任意可运行状态 → CANCELLING → CANCELLED
```

状态转换规则：

- 状态更新使用乐观锁 `version`；
- Worker 通过租约领取任务，租约到期可由其他 Worker 恢复；
- `ANALYZING` 前必须写入 `execution_closed_at`，禁止再追加普通样本；
- 分析和报告使用 `run_id + analysis_version` 幂等；
- 已完成任务的发布分不可覆盖，重算产生新的 Analysis Revision。

### 6.3 并发控制

四级令牌桶：

1. 全局并发；
2. 组织并发；
3. 目标并发/RPM；
4. 单任务并发。

默认值：

```yaml
global_concurrency: 100
organization_concurrency: 20
target_concurrency: 3
run_concurrency: 3
target_rpm: 30
```

用户配置只能在管理员允许范围内降低或提高。收到 429 时优先尊重 `Retry-After`，并执行带随机抖动的指数退避。

### 6.4 超时

```yaml
connect_timeout: 10s
tls_timeout: 10s
response_header_timeout: 30s
first_stream_event_timeout: 60s
stream_idle_timeout: 30s
request_total_timeout: 180s
run_timeout: 45m
```

深度检测可由管理员调整总任务超时。超时参数进入任务快照。

### 6.5 重试

可重试：连接重置、临时 DNS 失败、408、409（供应商明确可重试时）、429、部分 5xx。  
不可重试：400 参数错误、401/403、404 模型不存在、内容策略拒绝、响应超过安全上限。

默认最多 2 次重试。每次重试复用相同 logical sample 和 nonce；若上游不支持幂等键，报告中单独统计可能重复费用。

### 6.6 预算

任务创建时估算：

```text
预计输入 tokens = Σ 本地估算输入 tokens
预计最大输出 tokens = Σ 每个样本请求上限
预计费用 = 输入 × 输入单价 + 输出 × 输出单价
```

运行时分别限制：请求数、实际/估算 Token、货币预算和时间。上游 Usage 缺失时使用本地估算；估算不确定时应用 1.25 安全系数。

---

## 7. 协议规格

### 7.1 规范化请求

```go
type NormalizedRequest struct {
    Model               string
    Messages            []NormalizedMessage
    Temperature         *float64
    TopP                *float64
    Seed                *int64
    MaxOutputTokens     int
    Stream              bool
    Stop                []string
    ResponseFormat      *ResponseFormat
    ExtraAllowedParams  map[string]any
}
```

探针只使用经过 Adapter capability 声明支持的字段。未知字段默认不透传，防止配置将敏感信息注入请求。

### 7.2 OpenAI-compatible 请求映射

优先级：

1. 目标显式指定 `max_output_parameter`；
2. Adapter 根据模型能力表选择；
3. 默认使用 `max_tokens`；
4. 若预检返回明确“不支持”，尝试一次 `max_completion_tokens` 并缓存能力结果。

能力探测只能改变协议映射，不能计入真实性风险。

### 7.3 非流式结束判定

必须保存：HTTP 状态、Content-Type、原始响应大小、解析状态、choices 数、正文、模型回显、Usage、finish_reason 和警告。

### 7.4 SSE 流式结束判定

流解析器记录：

- 首字节和首个有效 delta 时间；
- 每个事件的序号、到达间隔、数据大小和事件类型；
- 拼接后的正文；
- 最终 Usage（如有）；
- finish_reason 所在事件；
- 是否收到协议终止标记；
- EOF、超时、解析错误或连接重置；
- 最多保留前后各 N 个脱敏事件，不永久保存完整事件流。

`StreamTerminated=false` 本身是响应完整性证据，但网络故障率高时降低其归因置信度。

### 7.5 响应大小限制

```yaml
max_response_body_bytes: 8MiB
max_stream_event_bytes: 1MiB
max_saved_content_chars: 200000
max_error_body_bytes: 64KiB
```

超过限制时中止并标记 `CLIENT_SAFETY_LIMIT`，该样本不用于判断上游 Token 篡改。

---

## 8. 探针规范

### 8.1 模板结构

```yaml
id: max_token_ladder.sequence.v1
category: max_tokens
version: 1.0.0
languages: [zh-CN, en-US]
applicability:
  protocols: [openai_chat]
  excludes: []
parameters:
  max_output_tokens: [64, 128, 256, 512]
  repetitions: 3
  stream_modes: [false, true]
randomization:
  nonce: true
  shuffle: true
assertions:
  - sequence_integrity
  - termination_consistency
  - token_plateau
sensitivity: internal
```

发布后的模板不可修改；修订必须生成新版本。

### 8.2 随机化

- nonce 使用密码学安全随机数，建议 96 bit；
- 任务保存 nonce 的 HMAC 和明文变量；明文仅用于样本复现，不进入普通日志；
- 同一对照组共享任务级变量；
- 样本顺序 Fisher–Yates 打乱；
- 可选同义模板从审核后的私有模板池抽取；
- 禁止让模型根据固定公开字符串识别检测任务。

### 8.3 通用样本参数

为降低随机性，默认：

- `temperature=0` 或目标允许的最小值；
- 支持时设置固定 `seed`；
- 不设置业务无关 stop；
- 同一探针内除目标变量外其他参数保持一致；
- 每个关键条件至少 3 次重复，形成正式无异常结论建议至少 5 次。

### 8.4 提示词注入行为探针

#### 8.4.1 格式契约探针

目的：检测未知前缀、后缀、解释、身份声明或格式强制。

示例逻辑，不作为唯一固定模板：

```text
返回且只返回以下随机标记，不添加空格、标点或解释：<NONCE>
```

特征：

- `exact_match`；
- 首尾多余字符数；
- 固定前/后缀指纹；
- JSON/schema 合规率；
- 多次重复的额外文本相似度。

至少使用三种等价表达和两种语言，避免把模型普通格式能力误当作注入。

#### 8.4.2 成对差分探针

构造 A/B 两个语义近似请求，只改变不应影响任务完成的表面变量，例如标签名、项目顺序或语言。比较：

- 格式合规率差异；
- 拒答率差异；
- 非请求身份声明；
- 固定语义主题偏移；
- 响应嵌入/指纹相似度。

若差异能由语言能力、模型随机性或安全策略解释，则只形成 C 级迹象。

#### 8.4.3 中性拒答探针

使用明确无风险、无个人数据、无外部行动的任务，例如字符串转换、排序、格式化和简单算术。检测：

- 拒答；
- 非请求的政策说明；
- 强制转向特定主题；
- 供应商品牌或身份声明。

安全敏感题不进入中性拒答评分，避免将正常安全策略判为注入。

#### 8.4.4 身份与风格偏置探针

要求不同的中性角色或写作风格，检测是否持续出现同一未知身份/语气。该探针权重低于格式契约，必须与其他探针共同命中才可形成高风险。

#### 8.4.5 多语言等价探针

使用中英文等价表达，比较异常模式是否只在特定语言触发。语言能力差异属于替代解释；只有额外固定指令特征重复出现才计入高风险。

#### 8.4.6 自报告探针

询问模型是否存在系统提示、参数限制等。结果仅展示在“辅助观察”，算法权重恒为 0。原因是模型可能拒绝、猜测或虚构。

### 8.5 Token 上限探针

#### 8.5.1 阶梯设计

默认可见输出上限：`[64, 128, 256, 512]`。深度包增加 1024；若目标上下文或预算不足则自动缩减。

每档至少 3 次，正式 B 级结论至少要求高档位合计 6 个有效样本。流式与非流式至少各覆盖两个高档位。

#### 8.5.2 持续生成任务

任务必须满足：

- 输出可机械解析；
- 在请求上限前没有自然完成点，或目标完成点远高于最大档位；
- 每个单元长度相对稳定；
- 不包含无限循环、危险内容或大量版权文本；
- 可检测缺项、断句和结构未闭合。

推荐模板族：随机标签编号序列、短字段 JSONL、重复变换任务。不得只使用“写一篇文章”，因为模型可能自然短答。

#### 8.5.3 本地 Token 估算

Tokenizer 配置按 `reported_model`、请求模型和标准模型依次匹配：

1. 精确 tokenizer；
2. 同系列兼容 tokenizer；
3. 字符/字节启发式估算。

保存 `tokenizer_id`、版本和质量：`exact | compatible | heuristic | unavailable`。启发式估算不能单独产生 Usage 伪造的 B 级结论。

#### 8.5.4 结构完整性

按任务类型检查：

- JSON/JSONL 是否可解析；
- 数组、对象、字符串是否闭合；
- 编号是否连续；
- 最后一个单元是否完成；
- Markdown 代码块是否闭合；
- Unicode 是否在合法边界结束；
- 句子是否明显中断。

结构未完成是“硬截断”特征，但若 `finish_reason=length` 且长度符合请求值，则属于正常达到用户上限，不计作篡改。

### 8.6 响应完整性探针

- 相同请求对照 stream=false/true；
- 检查最终协议事件；
- 检查 `finish_reason` 与文本形态；
- 检查响应固定附加内容；
- 检查 Usage 是否缺失或与本地估算长期偏离；
- 检查代理错误页伪装成 200 JSON；
- 检查模型回显是否稳定变化。

---

## 9. 特征、规则与算法

### 9.1 样本有效性

样本分为：

- `VALID`：成功解析且满足探针分析条件；
- `VALID_WITH_WARNING`：可分析但 Usage、tokenizer 或终止事件不完整；
- `INVALID_RETRYABLE`：网络/限流等，重试后取最终 Attempt；
- `INVALID_PROTOCOL`：协议不兼容，不参与真实性评分；
- `INVALID_SAFETY_LIMIT`：触发客户端安全限制；
- `NOT_APPLICABLE`：模型类型或能力不适用。

有效样本不足时输出 D 级，禁止用少量异常直接外推。

### 9.2 核心特征

每个有效样本提取：

```text
requested_max_tokens
reported_completion_tokens
local_completion_tokens
visible_chars / bytes / units
finish_reason_normalized
stream_terminated
structure_complete
contract_exact_match
unexpected_prefix/suffix fingerprint
refusal_class
identity_claim_class
latency / TTFT / chunk_count
http/protocol warnings
baseline_pair_id
```

### 9.3 Token 平台效应检测

对每个请求档位 `M_i`，计算有效样本本地 Token 中位数 `E_i`、中位绝对偏差 `MAD_i` 和结构未完成率 `I_i`。

高档平台候选需同时满足：

1. 至少两个相邻高档位，后者请求值至少为前者 1.5 倍；
2. `E_high / E_prev < 1.20`，即输出中位数增长不足 20%；
3. 两档合并后的稳健变异系数低于规则阈值；
4. 平台值显著低于较高请求值，默认 `< 0.70 × M_high`；
5. 出现结构未完成、异常终止或与可信基线显著不同中的至少一项。

风险加分因素：

- 多个模板族出现相同平台；
- 流式与非流式均出现；
- `finish_reason=stop` 但文本硬截断；
- Usage 和本地估算均聚集于同一平台；
- 可信基线在相同任务下随档位正常增长。

降权因素：

- 模型频繁自然 EOS；
- 推理 Token 占用不可见预算；
- tokenizer 仅为启发式；
- 高档有效样本不足；
- 上游明确返回模型自身最大输出限制且与文档一致。

### 9.4 请求参数响应性

计算高低档位效应：

```text
responsiveness = (median(E_high) - median(E_low)) / (M_high - M_low)
```

该值不直接等同于篡改概率，只用于平台规则。使用 bootstrap 计算中位数差异置信区间；区间包含正常增长范围时降低结论。

### 9.5 Usage 一致性

若 tokenizer 质量为 exact/compatible：

```text
usage_relative_error =
abs(reported_completion_tokens - local_completion_tokens)
/ max(local_completion_tokens, 1)
```

默认规则：

- 单样本误差 ≤ 5%：正常；
- 5%～15%：警告，不单独计高风险；
- >15% 且跨 6 个以上样本同方向稳定偏离：形成 Usage 异常；
- tokenizer 为 heuristic 时阈值扩大且证据最高 C。

对推理模型必须分离 visible completion 与 reasoning token；无法分离时跳过总量一致性规则。

### 9.6 终止一致性

规范化结束原因：`STOP | LENGTH | CONTENT_FILTER | TOOL_CALL | ERROR | CLIENT_CANCEL | UNKNOWN`。

典型矛盾：

- `STOP` + JSON/序列明显未完成 + 长度高度聚集；
- `LENGTH` + 实际长度远低于请求值且跨档位固定；
- 流未收到终止事件但 HTTP 正常结束；
- Usage 声称完成 Token 显著高于可见内容和合理隐藏 Token 解释；
- 响应正文结束正常但代理追加固定尾部。

单个矛盾只形成样本迹象，聚合后才计风险。

### 9.7 提示词行为风险

每类探针计算 0～100 子分：

- 格式契约破坏率 `F`；
- 稳定未知前后缀率 `P`；
- 中性异常拒答率 `R`；
- 身份/风格固定偏置 `I`；
- 相对可信基线的差分效应 `D`。

默认组合：

```text
prompt_injection_risk =
0.30F + 0.25P + 0.20R + 0.10I + 0.15D
```

规则约束：

- 没有基线时 `D` 缺失，其余权重重新归一；
- 仅身份/风格探针命中，风险上限 39；
- 自报告权重为 0；
- 至少两个不同模板族稳定命中，才允许达到 70；
- 若受控网关存在直接出站提示摘要证据，可由独立规则提升证据等级，不直接篡改算法原分。

### 9.8 Token 风险

默认子项：

```text
token_risk =
0.45 × plateau_risk
+ 0.20 × termination_mismatch_risk
+ 0.20 × usage_mismatch_risk
+ 0.15 × stream_nonstream_difference_risk
```

Usage 不可用时重新归一；若只有一个档位有效，Token 风险最高 39 且证据为 C/D。

### 9.9 响应完整性风险

由固定追加内容、SSE 异常结束、协议字段异常和正文/元数据矛盾组成。网络错误率高于 20% 时，SSE 异常归因分乘以 0.5，并建议先排查网络。

### 9.10 协议与证据可信度风险

该分数反映“结果可能因协议代理或证据质量而失真”，不是供应商作弊分。包括：

- Usage 长期缺失或字段不合法；
- Content-Type/HTTP 状态异常；
- 模型回显与请求不一致；
- 大量未知 finish_reason；
- tokenizer 不可用；
- 有效样本率低。

前端必须将其命名为“协议与证据风险”，避免误解。

### 9.11 综合风险

设已有一级分数为 `s_i`、权重为 `w_i`：

```text
overall_risk = round(Σ(w_i × s_i) / Σ(w_i_available))
```

关键维度缺失时：

- 仍可计算展示分；
- `result_completeness` 标记 PARTIAL；
- 置信度受到惩罚；
- 不允许输出“低风险高置信度”。

### 9.12 置信度

置信度不等于 `100 - risk`。建议初版：

```text
confidence = 100 ×
  sample_factor ×
  repeatability_factor ×
  evidence_quality_factor ×
  baseline_factor ×
  applicability_factor
```

各因子范围 `[0,1]`：

- `sample_factor`：有效样本达到目标数量时趋近 1；
- `repeatability_factor`：跨重复和模板族的一致程度；
- `evidence_quality_factor`：终止事件、Usage 和 tokenizer 质量；
- `baseline_factor`：可信同批基线最高，无基线取较低默认值；
- `applicability_factor`：模型是否适用当前规则。

为避免乘法过度压低，工程实现可设最低/最高边界，但公式和参数必须版本化并通过数据校准。V1.0 发布前由算法验收集冻结确切参数。

### 9.13 证据等级映射

```text
A：存在已验证 gateway_evidence，且直接显示参数/提示变更
B：置信度 ≥ 75，风险 ≥ 60，至少两个独立探针族命中
C：存在异常但不满足 B，或仅单一行为信号
D：有效样本不足、关键协议证据缺失或结果不可复现
```

风险低且置信度高时显示“未发现明显异常”，证据等级可记为 B（强阴性证据）；不得显示“证明没有篡改”。

### 9.14 统计方法

- 连续变量优先使用中位数、MAD、bootstrap 置信区间；
- 比例差异使用 Fisher 精确检验或适合小样本的方法；
- 同批基线优先采用配对分析；
- 多规则同时检验时进行 FDR 控制或通过冻结阈值控制整体误报率；
- p 值不能单独作为风险结论，必须同时报告效应量；
- 规则发布必须记录训练/校准集与独立验收集结果。

---

## 10. 数据模型

以下为逻辑模型。物理迁移使用 GORM migration + 显式索引脚本，字段类型按数据库方言调整。

### 10.0 独立系统主数据

系统必须自行创建和维护以下主表：

- `organizations`：组织、状态、默认时区和配额；
- `users`：本地账号、密码哈希、状态、登录安全字段；
- `organization_members`：用户与组织的成员关系；
- `roles`、`permissions`、`role_permissions`、`member_roles`：RBAC；
- `user_sessions`：会话哈希、到期、撤销和设备摘要；
- `providers`：供应商名称、描述、状态和联系人等非敏感档案；
- `model_profiles`：供应商模型名、显示名、协议、能力、tokenizer、公开限制和可选的整数微单位输入/输出单价；价格未知时只展示 Token 消耗，不阻塞检测；
- `system_settings`：系统级版本化配置，不保存主密钥；
- `schema_migrations`：本项目数据库迁移版本。

这些表不是外部系统映射表。即使启用 OIDC 或导入模型目录，本地记录仍是权限和检测任务的唯一事实源。

### 10.1 `integrity_targets`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| organization_id | bigint | 组织隔离键 |
| provider_id | bigint nullable | 关联本系统 `providers` |
| name | varchar(128) | 目标名称 |
| endpoint | varchar(1024) | 规范化 Endpoint，不含密钥 |
| endpoint_fingerprint | char(64) | 用于去重的 HMAC |
| protocol | varchar(32) | `openai_chat` |
| model | varchar(128) | 请求模型名 |
| model_profile_id | bigint nullable | 关联本系统 `model_profiles` |
| auth_type | varchar(32) | bearer/custom_header |
| secret_id | bigint | 密钥引用 |
| options_json | json | 超时、代理、参数映射等 |
| status | varchar(20) | active/disabled |
| created_by/updated_by | bigint | 操作者 |
| created_at/updated_at | datetime | 时间 |
| deleted_at | datetime nullable | 软删除 |

索引：`(organization_id, status)`、`provider_id`、`model_profile_id`、`endpoint_fingerprint`。

### 10.2 `integrity_secrets`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| organization_id | bigint | 组织隔离 |
| encrypted_data_key | blob | KMS/主密钥加密的数据密钥 |
| ciphertext | blob | API Key 与全部自定义 Header 组成的版本化凭证载荷 AES-GCM 密文 |
| nonce | binary | 凭证载荷的独立随机 96-bit nonce |
| key_version | varchar(64) | 主密钥版本 |
| fingerprint | char(64) | Key 的 HMAC，仅用于识别复用 |
| last_four | varchar(8) | 掩码展示 |
| created_at/rotated_at | datetime | 时间 |
| deleted_at | datetime nullable | 删除时间 |

该表不出现在通用 ORM JSON 序列化中。

`integrity_targets` 只通过 `secret_id` 引用凭证。API Key 与全部自定义 Header 必须位于同一版本化 Secret 载荷中，不得在 Target 或配置快照中保存第二份密文；轮换、删除、掩码和审计统一由 Secret Service 处理。`encrypted_data_key` 自包含包裹算法、wrap nonce、认证 tag 和 key/provider version 等 envelope 元数据。

### 10.3 `integrity_runs`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| organization_id | bigint | 组织隔离 |
| target_id | bigint | 检测目标 |
| baseline_run_id | bigint nullable | 对照基线 |
| package | varchar(32) | quick/standard/deep/custom |
| observation_mode | varchar(20) | blackbox/compare/gateway |
| status | varchar(32) | 状态机 |
| config_snapshot | json | 任务冻结配置，不含密钥 |
| manifest_hash | char(64) | 探针清单哈希 |
| rule_bundle_version | varchar(64) | 规则包 |
| template_bundle_version | varchar(64) | 模板包 |
| scoring_version | varchar(64) | 评分版本 |
| tokenizer_bundle_version | varchar(64) | tokenizer 配置 |
| request_budget/token_budget | bigint | 预算 |
| money_budget_micros | bigint nullable | 货币预算 |
| request_count/token_count | bigint | 实际消耗 |
| estimated_cost_micros | bigint | 估算费用 |
| valid_sample_count | int | 有效样本 |
| error_summary | json nullable | 错误摘要 |
| lease_owner/lease_until | varchar/datetime | Worker 租约 |
| cancel_requested_at | datetime nullable | 取消标记 |
| execution_closed_at | datetime nullable | 停止追加样本 |
| created_by | bigint | 发起人 |
| created_at/started_at/finished_at | datetime | 时间 |
| version | int | 乐观锁 |

索引：`(organization_id, created_at)`、`(target_id, created_at)`、`(status, lease_until)`。

### 10.4 `integrity_probe_instances`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| run_id | bigint | 任务 |
| probe_type | varchar(64) | 探针类型 |
| template_id/version | varchar | 模板信息 |
| category | varchar(32) | prompt/token/integrity |
| variant | varchar(64) | 语言/变体 |
| planned_samples | int | 计划数 |
| valid_samples | int | 有效数 |
| status | varchar(24) | 状态 |
| parameters_json | json | 冻结参数 |
| result_json | json nullable | 统计结果 |
| risk_score/confidence | decimal | 分数 |
| evidence_grade | char(1) | A/B/C/D |
| created_at/finished_at | datetime | 时间 |

### 10.5 `integrity_logical_samples`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| run_id/probe_instance_id | bigint | 归属 |
| ordinal | int | 样本序号 |
| pair_id | varchar(64) nullable | A/B 或基线配对 |
| idempotency_key | varchar(128) | 内部幂等键 |
| request_plan | json | 计划参数和变量 |
| final_attempt_id | bigint nullable | 最终 Attempt |
| validity | varchar(32) | 有效性 |
| feature_json | json nullable | 特征 |
| rule_result_json | json nullable | 样本规则结果 |
| created_at/completed_at | datetime | 时间 |

唯一索引：`(run_id, probe_instance_id, ordinal)`、`idempotency_key`。

### 10.6 `integrity_sample_attempts`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| logical_sample_id | bigint | 逻辑样本 |
| attempt_no | int | 重试序号 |
| request_snapshot | json | 脱敏后的实际请求 |
| request_hash | char(64) | 规范化请求哈希 |
| response_meta | json | HTTP、Usage、finish、头摘要 |
| response_content_enc | blob nullable | 可选加密正文 |
| response_content_redacted | text nullable | 脱敏/截断正文 |
| response_hash | char(64) nullable | 原响应哈希 |
| http_status | int nullable | 状态码 |
| provider_request_id | varchar(256) nullable | 上游追踪 ID |
| reported_model | varchar(128) nullable | 模型回显 |
| error_code/error_detail | varchar/json | 结构化错误 |
| prompt/completion/total_tokens | bigint nullable | Usage |
| local_completion_tokens | bigint nullable | 本地估算 |
| tokenizer_id/quality | varchar | tokenizer 信息 |
| first_byte_ms/first_token_ms/duration_ms | bigint | 时延 |
| stream_chunk_count | int | 块数 |
| stream_terminated | bool nullable | 终止状态 |
| billed_estimate_micros | bigint | 估算费用 |
| started_at/finished_at | datetime | 时间 |

唯一索引：`(logical_sample_id, attempt_no)`。

### 10.7 `integrity_findings`

| 字段 | 类型 | 说明 |
|---|---|---|
| id | bigint | 主键 |
| run_id | bigint | 任务 |
| analysis_revision | int | 分析修订 |
| category/type | varchar | 分类和规则类型 |
| severity | varchar(16) | info/low/medium/high/critical |
| risk_score/confidence | decimal | 分数 |
| evidence_grade | char(1) | 证据等级 |
| title | varchar(256) | 标题 |
| summary | text | 摘要 |
| statistics_json | json | 阈值、实际值、效应量、区间 |
| alternative_explanations | json | 替代解释 |
| sample_refs | json | 样本引用 |
| rule_id/version | varchar | 规则 |
| gateway_evidence_id | bigint nullable | 直接证据 |
| created_at | datetime | 时间 |

### 10.8 `integrity_run_results`

| 字段 | 类型 | 说明 |
|---|---|---|
| run_id + analysis_revision | composite | 主键 |
| prompt_risk/token_risk | decimal | 一级分数 |
| response_risk/evidence_risk | decimal | 一级分数 |
| overall_risk | decimal | 综合风险 |
| confidence | decimal | 置信度 |
| risk_level | varchar(16) | 风险级别 |
| evidence_grade | char(1) | 最高/总体证据 |
| completeness | varchar(16) | full/partial/insufficient |
| conclusion_json | json | 关键结论和建议 |
| is_published | bool | 是否发布版本 |
| created_at | datetime | 时间 |

### 10.9 其他表

- `integrity_baselines`：模型、协议、运行、审核人、有效期、适用范围；
- `integrity_rule_bundles`：规则包、状态、内容哈希、回放指标；
- `integrity_template_bundles`：模板包、敏感级别、内容哈希；
- `integrity_reviews`：人工结论、说明、操作者和时间；
- `integrity_reports`：格式、版本、内容哈希、存储位置、生成状态；
- `integrity_audit_logs`：只追加的主体、动作、对象、结果、IP、User-Agent、脱敏差异摘要、前序哈希、事件 HMAC、规范化版本和完整性密钥版本；
- `integrity_audit_chain_heads`：按组织串行化的当前链头、事件计数和密钥版本；
- `integrity_audit_segments`：保留期清理后的密封分段起止哈希、数量、时间范围和删除凭证；
- `integrity_jobs`：数据库任务队列，包含类型、载荷引用、状态、优先级、租约、重试和计划时间；
- `integrity_outbox`：可选外部通知/集成事件的事务 outbox；
- `integrity_gateway_evidence`：V1.1 预留的出入站参数差异和签名。

### 10.10 数据约束

- 所有业务查询必须包含 `organization_id`；
- `run` 创建后不可替换 target，密钥轮换只影响未来调用；
- 任务配置快照不保存密钥，只保存 `secret_id + secret_version`；
- 报告引用 Analysis Revision，不能引用“最新结果”动态变化；
- response 正文保存前执行长度限制、加密和内容策略；
- JSON 大字段禁止进入默认列表查询。

---

## 11. 内部 API

统一前缀：`/api/v1`。本项目自行定义响应 envelope：成功返回 `{"data": ..., "request_id": "..."}`，失败返回 `{"error": {"code": "...", "message": "...", "details": ...}, "request_id": "..."}`。敏感详情不得放入 `message`。

### 11.0 初始化、认证与系统管理

```text
GET  /setup/status
POST /setup/initialize             # 仅未初始化时可用
POST /auth/login
POST /auth/logout
GET  /auth/me
POST /auth/change-password
GET  /users
POST /users
PATCH /users/{id}
GET  /organizations
POST /organizations
GET  /organizations/{id}/members
POST /organizations/{id}/members
PATCH /organizations/{id}/members/{memberId}
GET  /roles
GET  /system/health
GET  /system/version
```

初始化接口必须满足：只允许系统未初始化时调用；创建首个组织、管理员和基础角色；成功后永久关闭普通初始化入口；首次登录强制修改临时密码（若使用临时密码）。

供应商与模型档案：

```text
GET/POST       /providers
GET/PATCH      /providers/{id}
GET/POST       /model-profiles
GET/PATCH      /model-profiles/{id}
```

### 11.1 目标

```text
POST   /targets
GET    /targets
GET    /targets/{id}
PATCH  /targets/{id}
POST   /targets/{id}/rotate-secret
POST   /targets/{id}/precheck
DELETE /targets/{id}
```

创建示例：

```json
{
  "name": "供应商A-gpt-x",
  "provider_id": 123,
  "endpoint": "https://example.com/v1/chat/completions",
  "protocol": "openai_chat",
  "model": "gpt-x",
  "auth": {"type": "bearer", "api_key": "<write-only>"},
  "options": {
    "max_output_parameter": "auto",
    "tls_verify": true,
    "timeout_seconds": 180
  }
}
```

返回绝不包含 `api_key` 或密文。

### 11.2 任务

```text
POST /runs/estimate
POST /runs
GET  /runs
GET  /runs/{id}
POST /runs/{id}/cancel
POST /runs/{id}/retry-probes
GET  /runs/{id}/events          # SSE，仅任务进度
GET  /runs/{id}/result
GET  /runs/{id}/findings
GET  /runs/{id}/samples
GET  /runs/{id}/samples/{sampleId}
POST /runs/{id}/reanalyze       # P1/管理员
```

创建任务：

```json
{
  "target_id": 42,
  "package": "standard",
  "baseline_id": 7,
  "options": {
    "stream_modes": [false, true],
    "max_requests": 60,
    "max_tokens": 50000,
    "max_cost_micros": 2000000,
    "concurrency": 3,
    "early_stop": true
  }
}
```

创建返回 `202 Accepted`，包含任务 ID、冻结版本、估算消耗和状态。

### 11.3 基线

```text
GET    /baselines
POST   /baselines
GET    /baselines/{id}
PATCH  /baselines/{id}
POST   /baselines/{id}/approve
POST   /baselines/{id}/retire
```

普通用户不能直接把高风险任务设为可信基线；需要具备基线审核权限。

### 11.4 人工复核和报告

```text
POST /runs/{id}/reviews
GET  /runs/{id}/reviews
POST /runs/{id}/reports
GET  /runs/{id}/reports
GET  /reports/{reportId}/download
```

### 11.5 规则

```text
GET  /rule-bundles
POST /rule-bundles
POST /rule-bundles/{id}/replay
POST /rule-bundles/{id}/publish
POST /rule-bundles/{id}/retire
```

发布接口必须校验离线回放结果、审批权限和内容哈希。

### 11.6 错误码

| 错误码 | 含义 |
|---|---|
| MI_TARGET_INVALID | 目标配置不合法 |
| MI_TARGET_BLOCKED_ADDRESS | Endpoint 命中 SSRF 禁止地址 |
| MI_AUTH_FAILED | 上游鉴权失败 |
| MI_MODEL_NOT_FOUND | 上游模型不存在 |
| MI_PROTOCOL_UNSUPPORTED | 接口协议不兼容 |
| MI_RATE_LIMITED | 上游限流 |
| MI_BUDGET_EXCEEDED | 任务预算达到上限 |
| MI_RUN_CONFLICT | 任务状态冲突 |
| MI_INSUFFICIENT_SAMPLES | 有效样本不足 |
| MI_ANALYSIS_FAILED | 分析失败 |
| MI_SECRET_UNAVAILABLE | 密钥解密/版本不可用 |
| MI_PERMISSION_DENIED | 权限不足 |

错误详情中禁止包含完整 Endpoint query、Key、鉴权 Header 和未脱敏正文。

---

## 12. 队列与可靠性

### 12.1 内置数据库 Job 队列

```text
integrity.run.plan
integrity.sample.execute
integrity.run.analyze
integrity.report.generate
integrity.retention.delete
integrity.notification.send    # P1
```

以上是 `integrity_jobs.type` 的逻辑类型，不要求外部消息中间件。Job 只保存业务对象 ID、组织 ID和非敏感执行选项，不包含密钥或响应正文。

PostgreSQL 模式使用 `SELECT ... FOR UPDATE SKIP LOCKED` 原子领取到期 Job；SQLite 单机模式使用短事务、条件更新和单 Worker 写锁。Job 包含 `status`、`priority`、`available_at`、`lease_owner`、`lease_until`、`attempt_count`、`max_attempts` 和 `last_error_code`。

### 12.2 事务一致性

创建任务与写入首个 Job 在同一数据库事务中，不存在“任务已创建但消息未投递”的窗口。Worker 按至少一次语义处理，每个处理器通过业务幂等键避免重复副作用。

`integrity_outbox` 只用于 P1 Webhook 等外部通知：业务变更与 outbox 同事务写入，由 dispatcher 异步发送。核心检测不依赖 outbox 或外部消息服务。

### 12.3 Worker 恢复

- 任务/样本领取时设置租约；
- Worker 每 15 秒续租；
- 超过 60 秒未续租可被回收；
- 外部请求已发出但结果未知时，重试前标记 `UNCERTAIN_ATTEMPT`；
- 不确定 Attempt 计入预算，但不重复作为有效样本；
- 任务长期无进展由 reconciler 转为 PARTIAL/FAILED。

### 12.4 可选队列适配器

大规模部署未来可以实现 Redis Streams、NATS 或云队列适配器，但数据库 Job 始终保留为默认实现。队列适配器必须通过同一 `JobQueue` 接口，不能改变任务幂等与状态语义。

---

## 13. 密钥与网络安全

### 13.1 信封加密

1. 每条 Secret 生成随机 256-bit 数据密钥；
2. 使用 AES-256-GCM 和独立随机 96-bit nonce，加密 API Key 与全部自定义 Header 组成的版本化凭证载荷；
3. 默认文件/容器 Secret 模式使用 HKDF-SHA-256 派生用途隔离的 wrapping、fingerprint 和 audit-integrity key；
4. 默认使用 AES-256-GCM 和另一独立随机 96-bit nonce 包裹数据密钥；`encrypted_data_key` envelope 自包含算法、nonce、认证 tag 和 key version；启用 KMS 时保存 KMS opaque ciphertext 及 provider/key 元数据；
5. AAD 至少包含 organization_id、secret_id、secret_version、key_version 和 envelope/payload 用途标识；
6. 只有 Worker 可按 `secret_id` 请求解密；Safe HTTP 不解析 Secret 引用。明文仅存在于出站请求作用域及底层发送所必需的短生命周期内存；
7. 禁止把解密对象格式化、序列化或写入错误对象；
8. 主密钥轮换通过重新包裹数据密钥完成。

单机和私有部署可使用权限受限的主密钥文件，标准生产也可从容器 Secret 注入；KMS 是可选增强。任何模式都禁止把主密钥保存在业务数据库、镜像或普通配置文件中。系统启动时校验主密钥权限、长度和版本，无法安全加载时拒绝启动 Secret Service。

### 13.2 日志脱敏

统一日志中间件必须处理：

- `Authorization`、`Proxy-Authorization`、`X-API-Key`；
- 名称匹配 `key|token|secret|auth` 的自定义 Header；
- URL query 中的凭证；
- 上游错误正文中的疑似密钥；
- 请求/响应内容默认不进入日志。

增加 CI 检查与运行时 canary secret 测试，验证日志系统不会采集完整值。

### 13.3 SSRF 防护

- 只允许 `https`，开发环境可显式允许 `http`；
- 解析 hostname 后拒绝 loopback、link-local、multicast、unspecified、保留地址和默认私网地址；
- 私有部署若需内网目标，使用管理员维护的 CIDR allowlist；
- TCP 连接使用校验后的 IP，并保留原 hostname 进行 TLS SNI/证书校验；
- 每次新连接重新解析并校验，防 DNS rebinding；
- 默认不跟随重定向；允许时对每个跳转重新完整校验；
- 禁止非 HTTP 协议和 Unix socket；
- 代理地址同样执行白名单控制；
- 阻止云元数据地址和平台控制面地址。

### 13.4 内容安全

- V1.0 模板只包含中性、合成任务；
- 私有模板内容需要安全审核、不可变版本和 SHA-256 校验；密码学包签名列为 P1；
- 不允许用户在标准检测中自由注入任意提示；自定义包需要额外权限；
- 自定义提示正文标记 S2，受保留期和导出限制；
- 防止报告页面渲染模型返回的 HTML/Markdown 脚本，默认纯文本转义。

### 13.5 租户隔离

- Repository 层要求显式 organization scope；
- 禁止仅在前端过滤；
- 对象存储路径包含不可猜测 ID，并通过短时签名下载；
- 后台任务载荷同时保存 organization_id 并在消费时复核；
- 管理员跨组织操作需要单独的系统角色和审计原因。

### 13.6 审计完整性

- 审计 Repository 对应用只暴露追加和验证能力，不提供更新既有事件的接口；普通用户无删除权限。
- 每个组织维护独立 HMAC-SHA-256 链，事件哈希覆盖版本化规范字段和前序哈希；完整性密钥由外置主密钥按独立用途派生，不进入业务数据库。
- PostgreSQL 锁定组织链头后追加；SQLite 使用短单写事务。敏感状态变更与强制审计事件同事务提交，审计失败则变更失败。
- 365 天保留期清理只能删除已密封分段，并永久保留分段锚点与删除事件；清理使用独立维护权限。
- 系统支持尾链健康检查和全链离线验证；恢复后必须验证通过才开放敏感写操作。
- 威胁模型和限制以 `docs/adr/ADR-0006-audit-log-integrity.md` 为准。

---

## 14. 前端实现规格

### 14.1 状态管理

- 列表和详情使用服务端查询缓存；
- 运行进度使用 SSE，断线后携带最后事件 ID 重连；
- SSE 只传任务统计，不传响应正文；
- 完成后拉取不可变结果快照；
- 权限决定入口与字段，后端仍需强制校验。

### 14.2 关键组件

- `TargetForm`：Endpoint、Key、模型和高级配置；
- `SecretInput`：只写、掩码、替换状态；
- `RunConfigurator`：检测包、预算、基线和预计费用；
- `RunProgress`：阶段、探针、消耗、错误；
- `RiskSummary`：风险、置信度、证据等级、完整性；
- `FindingCard`：统计、样本引用、替代解释；
- `TokenLadderChart`：请求上限 vs 实际输出分布；
- `PairComparison`：待测与基线/配对差异；
- `EvidenceViewer`：脱敏请求响应、事件时间线；
- `ReviewPanel`：人工复核；
- `RuleReplayResult`：发布前回归指标。

### 14.3 图表要求

Token 阶梯图必须同时展示：

- X 轴请求 `max_tokens`；
- Y 轴本地/上游 Token；
- 每个样本散点和中位数；
- 正常 `y=x` 参考线；
- 检测到的平台区间；
- stream/non-stream 区分；
- tokenizer 质量说明。

风险分不得只用颜色表达，必须同时显示文字、数值和图例。

### 14.4 页面异常状态

每个页面覆盖：加载、空数据、无权限、目标已删除、任务部分完成、规则已退役、正文已过期、报告生成失败和网络断开。

---

## 15. 可观测性

### 15.1 指标

```text
integrity_runs_total{status,package}
integrity_run_duration_seconds{package}
integrity_samples_total{probe,status,error_class}
integrity_upstream_request_duration_seconds{target_bucket,stream}
integrity_upstream_tokens_total{direction,source}
integrity_estimated_cost_micros_total{organization}
integrity_queue_depth{topic}
integrity_worker_lease_recoveries_total
integrity_analysis_duration_seconds{version}
integrity_report_generation_total{format,status}
integrity_secret_decrypt_failures_total
integrity_ssrf_blocks_total{reason}
```

高基数字段如 target_id、run_id 不进入普通时序标签，使用日志/Trace 查询。

### 15.2 日志

结构化字段：trace_id、organization_id、run_id、probe_instance_id、logical_sample_id、attempt_id、phase、error_code。不得记录密钥和默认正文。

### 15.3 Trace

链路：API 创建任务 → outbox → scheduler → sample attempt → analyzer → report。对外 HTTP span 仅记录脱敏 host 指纹、状态和耗时。

### 15.4 告警

- 队列积压超过 10 分钟；
- Worker 无活跃消费者；
- 任务失败率 > 10%；
- 密钥解密失败；
- SSRF 拦截异常增长；
- 日调用费用超过组织预算；
- 数据库连接/慢查询异常；
- 报告生成持续失败；
- 任务 RUNNING 超过最大时长。

---

## 16. 报告结构

JSON 报告使用版本化 schema：

```json
{
  "schema_version": "1.0",
  "report_id": "...",
  "run": {
    "id": 1001,
    "target": {"endpoint_masked": "https://exa.../v1/chat/completions", "model": "..."},
    "started_at": "...",
    "finished_at": "...",
    "versions": {
      "rule_bundle": "...",
      "template_bundle": "...",
      "scoring": "...",
      "tokenizer_bundle": "..."
    }
  },
  "result": {
    "overall_risk": 72,
    "risk_level": "high",
    "confidence": 86,
    "evidence_grade": "B",
    "completeness": "full"
  },
  "dimensions": [],
  "findings": [],
  "sample_summary": {},
  "limitations": [],
  "recommendations": [],
  "review": null,
  "disclaimer": "...",
  "content_hash": "sha256:..."
}
```

HTML 由该 JSON 快照渲染。报告哈希对去除 `content_hash` 字段后的 canonical JSON 计算。

---

## 17. 测试策略

### 17.1 单元测试

- Adapter 参数映射和错误归一化；
- SSE 分块、跨 chunk UTF-8、终止事件和异常 EOF；
- Tokenizer 选择和估算；
- JSON/序列/代码块完整性；
- 平台检测、Usage 误差、风险和置信度；
- 权重缺失重新归一；
- 状态机和乐观锁；
- 密钥加解密与日志脱敏；
- URL/IP/重定向 SSRF 校验；
- 报告 canonicalization 和哈希。

### 17.2 可控异常代理

实现仅用于测试的 mock upstream，可组合开关：

```yaml
inject_system_instruction: null | fixed_prefix | forced_identity | neutral_refusal
override_max_tokens: null | 64 | 128 | 256
override_probability: 0.0..1.0
usage_mode: honest | missing | inflated | deflated
finish_reason_mode: honest | always_stop | always_length | missing
stream_mode: normal | truncate | omit_done | delay | malformed_event
response_suffix: null | fixed
model_alias: null | custom
http_error_rate: 0.0..1.0
```

代理必须记录真实收到的参数，供验收标签使用，但检测器盲测阶段不能读取这些标签。

### 17.3 算法数据集

分为：

- 开发集：用于实现和初步调参；
- 校准集：用于冻结阈值和权重；
- 回归集：每次 CI 执行，防止规则退化；
- 盲验收集：发布负责人之外不可见标签；
- 真实灰度集：经脱敏和人工审核，用于发布后观察。

每个集合覆盖正常、固定篡改、概率篡改、流式篡改、Usage 伪造、自然短答、安全拒答、未知 tokenizer、推理模型和高网络错误率。

### 17.4 集成测试

- API → DB → outbox → queue → Worker → Analyzer → Report 全链路；
- Worker 崩溃与租约恢复；
- 429 Retry-After 与预算计算；
- 任务取消竞态；
- 密钥轮换期间运行任务；
- 基线配对；
- 规则发布和历史结果冻结；
- 正文到期后报告可用性。

### 17.5 端到端测试

- 新建目标、预检、标准检测、查看证据、人工复核、导出报告；
- 从本系统供应商或检测目标详情发起检测；
- 权限矩阵；
- SSE 断线重连；
- 部分完成与失败任务；
- 删除目标后的历史报告行为。

### 17.6 安全测试

- SSRF：127.0.0.1、IPv6 loopback、私网、十进制/八进制 IP、DNS rebinding、重定向、云元数据；
- Header 注入和 CRLF；
- 响应 HTML/Markdown XSS；
- 压缩炸弹、超大事件、慢速流；
- 跨组织 IDOR；
- API Key 在日志、Trace、错误、报告、备份中的泄漏扫描；
- KMS 不可用和密钥轮换；
- 队列伪造消息和重放。

### 17.7 性能测试

- 20 并发任务、100 并发请求；
- 8 MiB 响应限制；
- 100 万样本下列表和聚合查询；
- 数据库 Job 锁竞争、租约回收和短暂数据库连接中断；
- 报告批量生成；
- Worker 满负载时管理端查询 P95 仍满足 PRD，且并发限制能够保护数据库连接池。

---

## 18. 数据保留与清理

每日清理任务按组织策略执行：

1. 删除到期的加密完整正文；
2. 保留 response hash、统计特征和脱敏摘要；
3. 删除到期样本明细；
4. 保留聚合结果和审计日志；
5. 更新报告中的“正文已过期”状态，不修改原始报告哈希；如需新报告则生成新版本；
6. 记录删除批次、数量和失败，不记录正文。

大表建议按月分区（数据库支持时）；删除使用小批次，避免长事务。

---

## 19. 部署与配置

### 19.1 核心配置

```yaml
integrity:
  enabled: true
  role: all
  queue:
    provider: database
    poll_interval: 1s
  worker:
    global_concurrency: 100
    lease_seconds: 60
  network:
    allow_http: false
    allow_private_networks: false
    allowed_private_cidrs: []
    max_redirects: 0
  storage:
    save_full_response: true
    full_response_retention_days: 30
    sample_retention_days: 180
    report_retention_days: 365
  security:
    master_key_source: file
    master_key_file: /run/secrets/integrity_master_key
    kms_provider: optional
    log_content: false
  defaults:
    max_requests_per_run: 60
    max_run_minutes: 45
    target_concurrency: 3
```

### 19.2 环境隔离

- 开发环境使用 mock upstream 和开发密钥；
- 测试环境使用本项目独立数据库、数据目录和主密钥；
- 生产环境禁止启用 mock 控制接口；
- 规则包、模板包和 tokenizer 配置包从受控制品发布，V1.0 启动时必须校验 SHA-256；包签名列为 P1 增强；
- 私有模板不进入公开前端包。

### 19.3 安装形态

**单机一体化包**：一个二进制、一个配置文件、一个主密钥文件和一个数据目录。首次启动自动创建 SQLite、运行迁移并进入初始化向导。适用试用、小团队和低并发部署。

**Docker Compose 标准包**：由本项目仓库提供应用、Worker、PostgreSQL、共享报告卷、健康检查和备份脚本。用户只需生成 `.env`/Secret、启动 Compose 并完成 Web 初始化，不需要预先安装其他业务项目。

**Kubernetes/Helm**：列为 P1；使用同一镜像拆分 Server/Worker，外接 PostgreSQL 和持久卷。

### 19.4 初始化与升级

1. 启动时检查配置、主密钥、数据目录和数据库连接；
2. 获取迁移锁并运行本项目 migration；
3. 未初始化时仅开放 `/setup/status`、`/setup/initialize` 和健康检查；
4. 创建首个组织、管理员、基础角色、内置规则包和模板包；
5. 初始化完成后关闭初始化写入口并开放登录；
6. 升级前执行兼容性检查和备份提示；
7. 数据迁移采用 expand → deploy → contract，破坏性 contract 至少延迟一个版本。

### 19.5 备份与恢复

- PostgreSQL：项目提供数据库备份脚本、报告目录归档和 manifest；
- SQLite：先暂停新 Job 或进入维护模式，再使用 SQLite online backup API；
- 备份包含数据库、报告文件、规则包版本和配置模板，不包含明文主密钥；
- 恢复时必须由操作者单独提供匹配的主密钥；
- 恢复后校验 schema 版本、报告哈希、Secret 可解密性和 Job 状态；
- 每个正式版本发布前至少完成一次恢复演练。

### 19.6 数据库迁移与回滚

迁移分三步：

1. 备份数据库和报告 manifest；
2. 运行向前兼容迁移，旧版本仍可读取核心数据；
3. 发布新 Server/Worker，先暂停新任务创建再滚动切换；
4. 健康检查、迁移版本和内置规则自检通过后恢复任务创建。

回滚：停止新任务、等待或取消在途 Worker、恢复上一应用镜像；只要迁移仍处于 expand 阶段就不回滚数据库。确需恢复数据库时使用发布前备份，并明确会丢失备份后的任务数据。紧急回滚不得直接删除检测表或报告目录。

---

## 20. 研发任务拆分

### Epic A：基础领域与安全

| 任务 | 输出 | 依赖 |
|---|---|---|
| A1 数据迁移与 Repository | 目标、任务、样本、结果、规则等表 | 无 |
| A2 Secret Service | 信封加密、轮换、掩码、审计 | A1 |
| A3 Safe HTTP Client | SSRF、超时、大小、重定向、TLS | 无 |
| A4 RBAC 与组织隔离 | 权限点、中间件、Repository scope | A1 |
| A5 审计日志 | 敏感动作记录与查询 | A1/A4 |
| A6 Identity 与初始化 | 本地登录、会话、首个管理员、用户组织管理 | A1/A4 |
| A7 供应商与模型档案 | 独立主数据 CRUD 和能力配置 | A1/A4 |

### Epic B：协议与执行引擎

| 任务 | 输出 | 依赖 |
|---|---|---|
| B1 OpenAI Chat Adapter | 请求构建、非流解析、错误归一 | A3 |
| B2 SSE Parser | 流事件、终止、Usage、时间 | A3 |
| B3 目标预检 | 鉴权、模型、参数能力、流式能力 | B1/B2 |
| B4 队列与 Outbox | 可靠任务投递 | A1 |
| B5 Scheduler/Worker | 租约、并发、限流、重试、取消 | B1/B2/B4 |
| B6 预算与成本 | 请求/Token/费用/时间硬限制 | B5 |

### Epic C：探针与分析

| 任务 | 输出 | 依赖 |
|---|---|---|
| C1 模板包与 Manifest | 版本化、随机化、哈希 | A1 |
| C2 格式契约/差分探针 | 提示词行为样本 | C1/B5 |
| C3 中性拒答/身份/多语言探针 | 提示词行为样本 | C1/B5 |
| C4 Token 阶梯探针 | 多档位、流/非流样本 | C1/B5 |
| C5 Tokenizer 与完整性解析 | Token 估算、结构特征 | B1/B2 |
| C6 样本规则引擎 | 特征和规则输出 | C2-C5 |
| C7 聚合评分与置信度 | Finding、四维分、综合分 | C6 |
| C8 基线比较 | 成对/分布分析 | C7 |
| C9 规则回放与发布 | 数据集回放、指标、灰度 | C7 |

### Epic D：API、前端与报告

| 任务 | 输出 | 依赖 |
|---|---|---|
| D1 目标/任务 API | CRUD、预估、运行、取消 | A/B |
| D2 结果/证据 API | Finding、样本、权限过滤 | C7 |
| D3 基线/规则/复核 API | 管理和审核 | C8/C9 |
| D4 目标与运行页面 | 配置、预检、进度 | D1 |
| D5 结果与证据页面 | 图表、下钻、对比 | D2 |
| D6 报告生成 | JSON/HTML、哈希、下载 | C7/D2 |
| D7 系统管理页面 | 初始化、登录、用户、组织、角色、供应商和模型档案 | A6/A7 |
| D8 独立部署与备份 | 单机包、Compose、迁移、备份恢复、健康检查 | A/B/D |

### Epic E：质量与交付

| 任务 | 输出 | 依赖 |
|---|---|---|
| E1 可控异常代理 | 组合式阳性/阴性场景 | 无 |
| E2 冻结数据集 | 开发、校准、回归、盲验收 | E1/C |
| E3 安全测试 | 密钥、SSRF、越权、XSS | A/D |
| E4 性能与故障测试 | 并发、恢复、队列、DB | B/D |
| E5 监控与告警 | 指标、日志、Trace、看板 | A-D |
| E6 灰度与回滚 | 功能开关、Runbook、发布报告 | 全部 |

---

## 21. 建议 Sprint 顺序

### Sprint 0：规格冻结与实验底座

- 确认评审决策；
- 建立可控异常代理；
- 定义规则/模板 schema；
- 准备开发集和验收设计；
- 完成页面低保真原型。

### Sprint 1：安全调用链路

- 初始化、登录、组织/RBAC、供应商与模型档案；
- 目标、Secret、Safe HTTP Client；
- OpenAI 非流式 Adapter；
- 预检；
- 基础任务/样本表。

### Sprint 2：任务执行

- Queue、Outbox、Worker、租约；
- SSE Adapter；
- 并发、重试、取消、预算；
- 运行进度 API。

### Sprint 3：Token 检测

- 阶梯探针；
- tokenizer、结构完整性和结束一致性；
- Token 风险初版；
- Token 阶梯图。

### Sprint 4：提示词行为检测

- 五类 P0 探针；
- 指纹、合规率和成对差分；
- 注入行为风险初版；
- Finding 下钻。

### Sprint 5：评分、基线和报告

- 综合风险、置信度、证据等级；
- 基线管理；
- JSON/HTML 报告；
- 人工复核和审计。

### Sprint 6：集成与发布

- 独立安装包、初始化向导、备份恢复和系统状态页；
- 权限、安全、性能和故障测试；
- 盲验收校准；
- 灰度、告警和 Runbook。

---

## 22. 关键验收用例

| 编号 | 场景 | 预期 |
|---|---|---|
| AC-01 | 正常接口，多档位随请求增长 | Token 风险低，不误报平台 |
| AC-02 | 1024/512 均被改为 256 | 高概率检出，证据至少 B |
| AC-03 | 模型自然在约 100 Token 完成文章 | 通过持续任务对照避免高风险误报 |
| AC-04 | `finish_reason=stop` 但序列在 256 附近断裂 | 终止矛盾 + 平台规则命中 |
| AC-05 | Usage 比本地估算稳定高 30% | Usage 异常；精确 tokenizer 下可达 B |
| AC-06 | 推理模型含不可见 reasoning tokens | 不把总量差异错误计为可见输出篡改 |
| AC-07 | 添加固定响应前缀 | 格式契约和前缀指纹命中 |
| AC-08 | 中性任务被固定身份指令影响 | 多探针重复后提示注入行为风险 |
| AC-09 | 普通安全敏感题拒答 | 不进入中性拒答主评分 |
| AC-10 | 模型自称“没有系统提示词” | 自报告权重为 0 |
| AC-11 | 流式省略终止事件，非流正常 | 响应完整性风险命中 |
| AC-12 | 网络随机断连 30% | 降低归因置信度并提示网络问题 |
| AC-13 | 上游 429 后恢复 | 遵守 Retry-After，不重复统计 Attempt |
| AC-14 | 任务预算耗尽 | 停止派发，状态 PARTIAL，报告标注不完整 |
| AC-15 | Worker 在请求后崩溃 | 恢复任务，不把不确定 Attempt 重复作为样本 |
| AC-16 | Endpoint 指向云元数据 | 预检拦截且写审计 |
| AC-17 | Key 出现在上游错误体 | 入库/日志/页面前脱敏 |
| AC-18 | 组织 A 枚举组织 B 的 run_id | 返回无权限/不存在，不泄漏元数据 |
| AC-19 | 规则升级后查看旧报告 | 旧分和版本保持不变 |
| AC-20 | 对旧任务重算 | 生成新 Analysis Revision，不覆盖发布结果 |
| AC-21 | 全新主机安装单机包 | 不安装其他业务系统即可初始化并完成首次检测 |
| AC-22 | 全新主机启动 Compose | Server、Worker、PostgreSQL 和健康检查均由本项目清单启动 |
| AC-23 | 备份后恢复到干净环境 | 目标、密钥密文、任务、报告和审计数据一致，主密钥单独提供 |
| AC-24 | 不配置 Redis、S3、OIDC 或 KMS | 核心检测、账号、任务和报告功能仍完整可用 |

---

## 23. 发布与回滚 Runbook 摘要

### 发布前

- 数据库迁移已在同量级副本验证；
- 默认数据库 Job consumer 和告警可用；仅在启用可选 KMS、Redis 等适配器时检查对应组件；
- 规则包、模板包和 tokenizer 包哈希确认；
- 盲验收指标达标；
- canary secret 泄漏扫描通过；
- SSRF 和租户越权测试通过；
- 独立产品核心能力默认启用；灰度访问默认仅系统管理员可见并限制为 mock/测试 Endpoint。

### 灰度

1. 仅系统管理员可见；
2. 只允许 mock/测试 Endpoint；
3. 开放 3 个可信和 3 个受控异常目标；
4. 开放少量真实渠道，限制每日预算；
5. 观察一周误报、成本、队列和故障；
6. 再开放运营角色。

### 紧急回滚

1. 关闭新任务创建；
2. 请求 Worker 安全取消未发样本；
3. 关闭 `integrity.enabled`；
4. 保留 DB 表和报告，不执行逆向删除迁移；
5. 恢复上一应用镜像并确认登录、历史查询和健康检查正常；
6. 记录事件和受影响任务。

---

## 24. V1.0 冻结实现决策

以下实现决策已经 M0-01 评审批准：

1. SQLite 允许用于小规模正式单机部署，标准生产必须使用 PostgreSQL；精确并发和数据量上限由 M7 性能验收结果冻结，不预先宣称未经验证的容量。
2. 主密钥文件或容器 Secret 是默认必备实现；KMS 仅为可选适配器。主密钥不得进入业务数据库、镜像或普通配置。
3. V1.0 默认将完整响应正文加密保存 30 天，并允许组织配置为 0～180 天；关闭正文留存不影响脱敏摘要和报告。
4. V1.0 基线由组织自行维护和审批，组织自行提供凭证并承担调用费用；不提供跨组织共享官方账号。
5. V1.0 交付多组织能力，首次初始化默认创建一个组织；Repository、中间件和 Job 始终要求 `organization_id`。
6. 模型档案允许组织维护整数微单位输入/输出单价；价格未知时只展示 Token 消耗，不阻塞检测。
7. V1.0 必须交付单机包和 Docker Compose；Kubernetes/Helm 列为 V1.1/P1。
8. V1.0 对规则、模板和 tokenizer 配置包强制校验 SHA-256；制品签名和包签名列为 P1 增强。
9. 失败或可疑探针复测属于 V1.0/P0；复测生成新任务或分析修订，不覆盖原始证据。
10. Redis、KMS 等发布前检查仅在相应可选适配器启用时生效，默认数据库 Job 和文件/容器 Secret 模式不得因此失败。
11. 独立产品的核心检测能力默认启用；灰度范围通过角色、环境和 Endpoint 策略控制。

---

## 附录 A：代码目录建议

```text
internal/integrity/
  api/
  domain/
  repository/
  secret/
  safehttp/
  adapter/
    openaichat/
  scheduler/
  worker/
  probe/
    templates/
    generator/
  tokenizer/
  feature/
  analyzer/
  scoring/
  baseline/
  report/
  audit/
  observability/
web/src/pages/Integrity/
web/src/components/Integrity/
tests/integrity/mockupstream/
tests/integrity/datasets/
```

避免把分析规则散落在 Handler、页面或 Adapter 中。Adapter 只负责协议，Probe 负责实验设计，Analyzer 负责判断，Scoring 负责聚合。

## 附录 B：规则输出示例

```json
{
  "rule_id": "token.plateau.v1",
  "status": "triggered",
  "risk_score": 88,
  "confidence": 91,
  "evidence_grade": "B",
  "statistics": {
    "requested_levels": [128, 256, 512, 1024],
    "median_observed": [121, 248, 257, 259],
    "high_level_growth_ratio": 1.008,
    "plateau_center": 258,
    "incomplete_rate": 0.83,
    "stream_and_nonstream_reproduced": true
  },
  "thresholds": {
    "max_growth_ratio": 1.20,
    "max_high_request_ratio": 0.70,
    "min_high_samples": 6
  },
  "alternative_explanations": [
    "模型自身存在公开的固定输出限制",
    "推理 Token 与可见 Token 共用预算",
    "协议适配层未正确支持请求参数"
  ],
  "sample_refs": [101, 102, 103, 107, 108, 109]
}
```

## 附录 C：工程完成定义

每个任务除代码完成外，还必须：

- 有单元/集成测试；
- 有结构化错误码；
- 有权限和组织隔离检查；
- 有敏感数据评估；
- 有指标、日志或可诊断状态；
- 文档同步更新；
- 数据迁移可前向执行；
- 具备功能开关或明确回滚路径；
- 对黑盒结论使用风险措辞；
- 不依赖任何其他业务项目即可安装、初始化、运行检测、生成报告和完成备份恢复。
