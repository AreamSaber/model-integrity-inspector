# 前端需求映射与剩余交互缺口（2026-09-07）

## 口径与快照

后续更新：`7f376a9` 已交付基线和人工复核页面；随后报告页面已接线并经真实浏览器生成/JSON与HTML验证下载。下文保留 `0565e83` 时点的缺口分析，不作为当前功能缺失的唯一依据；最新进度、限制与证据请以持续台账为准。当前矩阵已开始回填BASE/REP代码和测试，不再是全部空项；两Run比较正在开发，仍非差异报告导出。

本文件是开发过程中的只读需求核对，不是正式审核记录，不更改任何 Gate、需求优先级或既有批准。范围仅为前端、交互以及 REP/HIS 的可见交付；不重复审计分析算法、队列、加密、部署等后端实现。

核对基线：`requirements-v1.json` 全部 77 项、PRD 第 9～11 节、开发计划 M3-09/M4-09/M5-04～09/M6-01，以及 `INTERACTIONS-V1.0.md`。代码快照为 `codex/v1-integration`、HEAD `0565e83`（历史/结果/共享传输 checkpoint）；报告、基线、复核等并行未提交工作不算已经交付的页面。后续提交或新功能可能使本快照过时。

- 需求索引当前 77 项仍全部为 `implementation: not_started`，`code`、`tests` 全空。`REQ-*` 只是预留验收编号；不能据此说产品全部未开发，也不能当作已执行的验收测试。
- 持续台账已更新 M2-10、M3-09、M4-09、M5-04、M5-09 的真实读取闭环；其“进行中”准确，不应因出现页面就关闭整个里程碑。M1-08 行仍保留旧的 151 测试数量，应以台账末尾最新 checkpoint 为准。
- 本轮前端已有 309 项本地测试及 build/lint 通过的开发证据，其中传输边界 66 项。组件测试使用实际客户端和受控 Fetch 响应，不等于真实浏览器端到端验收。
- 台账另记 root 的真实受控 TLS 应用验证：浏览器登录→历史→结果总览/Token/行为/S1/Attempt→退出；初始化/预检/创建 Run 由真实 HTTP 测试完成。该证据不等于浏览器完成配置→确认→活动 SSE 故障→取消全流程，也不是付费模型兼容性、校准、生产或正式审核证据。本子任务没有重新执行该浏览器测试。

来源：[需求索引](requirements-v1.json)、[持续台账](V1.0-持续开发台账.md)、[交互设计](../design/INTERACTIONS-V1.0.md)、[PRD](../../模型真实性检测系统-PRD-V1.0.md)、[开发计划](../../模型真实性检测系统-开发计划与审核表-V1.0.md)。

## 已有实现的前端证据索引

下表编号供后文引用；“已接入”仅表示所述真实 API 路径/界面及局部测试存在，不代表覆盖该需求所有验收条件。

| 证据 | 实现路径 | 对应测试及可证明边界 |
|---|---|---|
| F1 身份与导航 | [App.tsx](../../web/src/App.tsx)、[AuthForms.tsx](../../web/src/components/AuthForms.tsx)、[AuthenticatedSession.tsx](../../web/src/components/AuthenticatedSession.tsx)、[SessionLayout.tsx](../../web/src/components/SessionLayout.tsx) | [App.test.tsx](../../web/src/App.test.tsx)：初始化、登录、当前会话退出、改密、组织切换、强制改密与过期门禁。导航项本身不证明业务页面存在。 |
| F2 管理 | [UsersPage.tsx](../../web/src/components/management/UsersPage.tsx)、[OrganizationsPage.tsx](../../web/src/components/management/OrganizationsPage.tsx)、[MembersPage.tsx](../../web/src/components/management/MembersPage.tsx)、[management-api.ts](../../web/src/management-api.ts) | [management.test.tsx](../../web/src/management.test.tsx)：组织/用户/成员、版本冲突、权限与撤销、0～180 天留存设置。内置角色目录不是当前用户的授权证明。 |
| F3 目录与目标 | [CatalogPage.tsx](../../web/src/components/catalog/CatalogPage.tsx)、[TargetForm.tsx](../../web/src/components/targets/TargetForm.tsx)、[TargetsPage.tsx](../../web/src/components/targets/TargetsPage.tsx)、[SecretForm.tsx](../../web/src/components/targets/SecretForm.tsx) | [catalog.test.tsx](../../web/src/catalog.test.tsx)、[catalog-api.test.ts](../../web/src/catalog-api.test.ts)、[targets.test.tsx](../../web/src/targets.test.tsx)：真实目录分页、CRUD/CAS、凭证仅写、掩码、精确价格、保留字段拒绝、跨组织取消。 |
| F4 预检与运行 | [PrecheckPanel.tsx](../../web/src/components/targets/PrecheckPanel.tsx)、[RunConfiguration.tsx](../../web/src/components/runs/RunConfiguration.tsx)、[RunQuote.tsx](../../web/src/components/runs/RunQuote.tsx)、[RunProgress.tsx](../../web/src/components/runs/RunProgress.tsx)、[run-events.ts](../../web/src/run-events.ts) | [prechecks.test.tsx](../../web/src/prechecks.test.tsx)、[runs.test.tsx](../../web/src/runs.test.tsx)、[runs-api.test.ts](../../web/src/runs-api.test.ts)、[run-events.test.ts](../../web/src/run-events.test.ts)：显式可能计费确认、固定 ID/版本、未知写结果不重放、SSE 有界重连、终态 GET 确认、撤权和组织切换。 |
| F5 历史 | [RunHistory.tsx](../../web/src/components/history/RunHistory.tsx)、[runs-history-api.ts](../../web/src/runs-history-api.ts) | [RunHistory.test.tsx](../../web/src/components/history/RunHistory.test.tsx)、[runs-history-api.test.ts](../../web/src/runs-history-api.test.ts)：服务端筛选分页、删除目标仍保留 ID、价格未知非零、无权限非空列表、Abort、只接受固定修订 1。 |
| F6 结果与 S1 | [ResultsPage.tsx](../../web/src/components/results/ResultsPage.tsx)、[ResultViews.tsx](../../web/src/components/results/ResultViews.tsx)、[results-api.ts](../../web/src/results-api.ts) | [ResultsPage.test.tsx](../../web/src/components/results/ResultsPage.test.tsx)、[results-api.test.ts](../../web/src/results-api.test.ts)：分母/缺失值、C/D、未校准声明、S1 Attempt、统计权限、403 清空、同修订变化拒绝、跨组织迟到响应丢弃、原文/非预期字段拒绝。 |
| F7 传输 | [api.ts](../../web/src/api.ts) | [api.test.ts](../../web/src/api.test.ts)：成功 8 MiB/错误 64 KiB、有界流读取、严格 UTF-8、45 秒 deadline、取消与认证错误闭合；不能替代服务端授权。 |
| B1 页面真实读契约 | [run_results.go](../../internal/integrity/api/run_results.go)、[history.go](../../internal/integrity/run/history.go)、[result.go](../../internal/integrity/run/result.go) | [run_results_test.go](../../internal/integrity/api/run_results_test.go)、[read_dto_test.go](../../tests/contracts/read_dto_test.go)：历史/结果/Finding/样本白名单 DTO。此处只作为页面可消费字段的证据，不重新评价后端算法。 |

## 身份、目标与运行需求

| 需求 / 优先级 | 前端真实映射 | 准确剩余边界 |
|---|---|---|
| SYS-001 / P0 | F1：一次性初始化组织/管理员并单独登录。 | 仍需正式安装与验收流程覆盖；不是只凭表单完成 SYS 全栈验收。 |
| SYS-002 / P0 | F1：本地登录、当前会话退出、改密使会话失效、强制改密/过期门禁。 | 交互稿的独立“退出所有会话”操作未提供；改密注销全部会话不能代替无需改密的会话管理入口。 |
| SYS-003 / P0 | F2：用户、组织、成员及内置角色/权限配置真实接入。 | 不存在自定义角色编辑页面；当前需求若只采用冻结的内置角色模型，不应额外发明自定义角色需求。已接界面仍需整体异常状态/可访问性验收。 |
| SYS-004、TAR-008 / P0 | F3：供应商/模型档案 CRUD、目标关联档案。 | 档案声明不能证明真实 tokenizer 已安装或模型真实性；目标列表仍缺“最近检测/最近风险”列（PRD 10.1）。 |
| SYS-005、SYS-006 / P0 的页面部分 | F4 展示单 Run 状态；F1 的 `#/system` 仍进入未接入页面。 | 无系统运行状态页：Worker/队列、版本/schema、数据库、审计完整性、密钥状态、报告存储/备份状态。单 Run 进度不能替代系统健康管理。 |
| SYS-008 / P0 的交互部分 | `#/system` 未接入。 | 无备份/恢复后的状态、完整性回执与失败处置界面；后端备份/部署本身不在本核对范围。SYS-007 纯部署项不重复评估。 |
| TAR-001、TAR-002 / P0 | F3：Endpoint、`openai_chat`、一个上游模型、组织/环境/渠道/档案/标签、CRUD/CAS。 | 协议选择限当前冻结 OpenAI Chat；不应把选择器存在算作支持全部协议。多模型增强另属 TAR-007。 |
| TAR-003、TAR-005 / P0 | F3/F7：凭证创建/轮换仅写，掩码/版本；自定义 Header 拒绝保留名，提交后清空，编辑不读取旧值。 | 浏览器字符串不能承诺物理内存清零；后端加密与密钥生命周期不以 UI 测试代替。 |
| TAR-004 / P0 | F4：真实异步预检，显式确认最多 3 次可能计费请求；读取冻结目标版本对应的分类结果。 | 通过预检只证明该项协议/连接观测，不证明身份/完整性；生产网络与真实付费协议兼容不由合成测试证明。 |
| RUN-001～RUN-003 / P0 | F4：四种检测包、自定义参数、重复/流式/预算/重试/并发，真实估算草稿→显式费用确认。 | 无基线选择；新浏览器全流程、未知结果恢复/活动取消故障仍需整体验证。估算时间与实际耗时不能混用。 |
| RUN-004、RUN-005 / P0 的交互部分 | F4：冻结 manifest hash、包版本与预算，确认只引用同一草稿；F6 保持固定结果修订。 | UI 不展示 nonce/seed 不算缺陷，它们是 S2；完整可审计复现入口仍属 REP-005。此处不重复验证生成器随机性。 |
| RUN-006 / P0 | F4：整体阶段、结束/有效样本计数、调用数、Token、费用和闭集错误摘要，真实 SSE。 | 缺每探针/家族进度、成功失败分母与阶段错误细分。总完成样本数不是调用成功率，重试数不是独立样本量。 |
| RUN-007 / P0 | F4：显式取消、当前权限/版本、GET 核对未知结果；导航离开不会伪称撤销后端任务。 | 真实浏览器 SSE 失联/终态竞争/取消全场景尚未完成；5 秒停止边界应由后端证据承担。 |
| RUN-008 / P0 | 无选择失败/疑似异常探针后复测的页面或调用。 | 需选择集、费用重新确认、创建新 Run/修订、链接原 Run，不能覆盖旧结论，也不能把一般“新建检测”当作选择性复测。 |

组织留存设置已有真实实现：F2 支持 `full_response_retention_days=0..180`，0 表示可关闭留存的配置值。该界面明确不声称历史数据立即清除。仍需把保存策略、证据到期、后台清理及删除回执串联验证；不能将“已有配置表单”与“生命周期全部兑现”划等号，也不能将其误列为完全没有设置。

## REP、HIS 与结果交互（重点）

| 需求 / 计划 | 当前可证明 | 剩余开发，不应标为完成 |
|---|---|---|
| REP-001 / P0；M5-09 | F6：四维与综合风险、置信度、证据 C/D、完整性、有效/计划样本分母、四版本和时间。未校准/公开开发模板/黑盒限制明确。 | 首屏还未直接突出“最严重的具体发现”并链接证据，不能用分数矩阵代替完整解释链。正式校准及 A/B 不是前端可自行补出的事实。 |
| REP-002 / P0；M5-04 | F6/B1：Finding 的规则/版本/统计/替代解释和样本 ID，样本列表可读取真实 Attempt 链。 | 目前 Finding 是四维聚合；样本引用为普通 ID 文本，未形成可点击且可跨页定位的结论→探针→样本路径。缺每规则阈值/实际量/效应与置信区间的完整细项、探针专页；“100% 下钻”尚不成立。 |
| REP-003 / P0；M5-04 | F6：请求上限、流式标志、部分结构/行为分类、Usage、finish、Attempt 状态/耗时/开始结束等 S1。 | 所有正文为 `content_state=redacted`；没有完整请求参数、授权脱敏请求/响应读取、上游 SSE 事件时间线、未留存/过期/删除原因，也没有正文读取审计反馈。前端进度 SSE 不等于上游响应事件证据。 |
| REP-004 / P0 | F6：限制、替代解释、缺失权重重归一、隐藏推理/分词/自然 EOS/合法网关等说明。 | 结果页已有；尚需原样随 JSON/HTML 报告、具体 Finding 和比较输出保留，不能只靠一段全局免责声明。 |
| REP-005 / P0；M5-08 | 尚无请求复现模板 API 客户端或页面。 | 需从冻结执行快照而不是当前目标重建；不含真实 Key/Header；使用占位符如 `${API_KEY}`，明确模板与实际已发请求差异、版本/参数、复制/下载和敏感级别。不能在普通结果 DTO 中直接回传 nonce/原文。 |
| REP-006 / P0；M5-08 | `#/reports` 只是已有 Run/分析修订列表，明确“报告生成、导出和正式审核尚未接入”。并行纯报告内核不等于用户可下载。 | 缺显式范围确认、权限、异步生成/状态、JSON/HTML 下载、重试/失败/到期状态、审计及不可变哈希展示。原结果应在报告失败后仍可读。 |
| REP-008 / 原 P1，基础哈希仍属 V1.0 | 固定 analysis revision 与 manifest hash 已有，但不是导出报告内容哈希。 | M5-08 基础 canonical hash/冻结内容校验必须交付；“完整版本链/后续修改新版本”仍保持原 future 分级，不能因为有一个 hash 字段就全完成。 |
| HIS-001 / P0；M5-09 | F5：按目标 ID 筛选，最近创建优先；历史风险/置信度/包/状态/计数/费用；固定结果入口。 | 缺每次真实调用成功率及其分母、延迟统计与口径；缺按目标的时序趋势。当前 API 无这些聚合字段，不能从完成样本/请求数自行伪造。 |
| HIS-002 / P0；M5-06/M5-09 | F5/F6 展示冻结版本，不会静默用最新版本替换旧分析。 | 缺跨次比较中的“算法/模板/tokenizer 变化，不能归因于行为变化”提示、同版本可比性分组和变化分解。显示两个版本号不等于完成变化归因；不得伪称已经排除算法因素。 |
| HIS-003 / P0 | F5：模型/渠道/创建日期/状态/目标/检测包/风险等级筛选和服务器分页。 | 模型/渠道搜索当前目标档案，不是历史冻结档案；UI 已明示。需求“风险项”若包含具体维度/规则，当前只有 `risk_level`，仍缺项筛选，不能宣称覆盖所有风险条件。 |
| 总览 / PRD 10.1；M5-09/M6-01 | F1 `Overview` 仅欢迎语、组织与真实历史入口，明确聚合统计未接。 | 缺组织目标数、近 7/30 天任务数、风险分布、异常趋势/成本聚合及对应分母、时区、无结果和跨版本口径；历史列表不是总览趋势。 |
| Token 页面 / M3-09 | F6：全 Run 档位中位数/MAD/稳健 CV、平台候选区间/独立组；当前页样本散点、y=x、本地/上游、流式形状、分词质量。 | 散点仅当前页，不能称全量分布；没有完整分系列中位数/平台区间叠加图、图点到样本下钻/全量受限查询。可信基线对比和正文细查未接。 |
| 行为页面 / M4-09 | F6：模式摘要指纹、家族/模板/语言数、配对效应与 BH 校正、分析分母、模型自述零权重隔离。 | 缺按探针/模板分组的详细命中率、成对样本原文对照、可信基线差异、直接引用定位。现探索性差分不是基线比较，不可当作校准结论。 |

当前 Token/行为页面对 PINJ-001～005、PINJ-008、MTOK-001～007、RINT-001～005 只提供上述已发布统计和 S1 投影；本文件不据此判定这些检测算法完成。尤其 RINT-005 的安全上游元数据/请求追踪标识不能由本地 HTTP 状态和 Attempt ID 代替；现页面没有完整该类元数据视图。

## 尚未接入的 P0 治理页面

| 需求 / 计划 | 当前边界 | 必需的下一交互单元 |
|---|---|---|
| BASE-001～BASE-005；M5-05 | `#/baselines` 仍是未接入页面，Run 配置无基线选择。 | 已审核 Run→基线、来源/适用范围/协议参数/区域/日期/版本、审批/到期/重新采样、官方或自身历史来源、无权不能覆盖、变更历史。`official` 只说明来源，不自动等于可信审批。 |
| CFG-001、CFG-002；M5-06 | 结果/报价已有不可变包版本，启动内置 bundle 不等于 UI 规则管理。`#/rules` 未接入。 | 只读规则/阈值/权重/内容 hash 和执行快照追溯；后续管理流程不能覆盖已执行版本。 |
| CFG-003、CFG-004、CFG-006；M5-06 | 无回放/发布/退役/变更对比/安全评审页面。 | 显示离线验收门禁、操作者/差异/发布时间、安全审查状态及权限；不能把公开开发模板自动写成已安全批准。 |
| PRD 9.7；M5-07（77 项没有独立“人工复核”ID） | 只有 `REVIEW_REQUIRED` 状态名称和文案建议，没有复核动作。 | 确认/误报/待观察/不适用、说明、历史和审计；算法原分与人工意见并列、修改产生新记录；报告同步展示。状态枚举不是人工复核功能。 |
| PRD 10.1/交互 audit；M1-07/M6-01 | `#/audit` 未接入。 | 组织内按操作者/动作/时间查询审计及完整性状态；正文读取、导出、复核、规则/基线、密钥和删除记录，不提供普通删除按钮。 |
| SYS-006/PRD 管理页面；M6-01 | `#/system` 未接入；组织留存设置已存在（见上）。 | 系统状态、配额/保留策略生效状态、备份/恢复/清理回执；不展示密钥或错误原文。 |

## 原 P1/P2：保留分级，不用 P0 读页面冒充增强已完成

需求索引目前有 17 项 P1、1 项 P2，均为 `release: future`。下列是前端关联的实际缺口；除 REP-008 基础哈希的既定例外，不在本文件中更改原发布分级。当前 Goal 已明确包含全部原 P1/P2，因此这些都仍是待开发工作，不能用“原来是 future”将其移出 Goal，也不能伪造为已完成。

| ID / 原优先级 | 当前界面边界与剩余能力 |
|---|---|
| SYS-009 / P1 | 仅本地用户名/密码；无 OIDC 按钮、提供方配置、回调/错误页、外部身份绑定/冲突流程或 SSO 登出联动。后续仍须保留不依赖 OIDC 的受控本地应急登录。 |
| SYS-010 / P1 | 前端自身调用 REST 不等于外部平台集成；无 API 客户端凭据/权限范围或 Webhook 配置、测试投递/失败审计页面。 |
| TAR-006 / P1 | 已有请求超时；TLS 校验强制开启。无代理/区域配置、多种受控 TLS 设置。不能为填勾选项而开放关闭校验或放宽 SSRF 边界。 |
| TAR-007 / P1 | 一个目标仅一个上游 model/档案；无多模型绑定、版本/预检与选择流程。 |
| RUN-009 / P1 | 无定时复检、时区、停用/错过策略、预算和通知设置。 |
| RUN-010 / P1 | 无多目标同策略选取、统一冻结估算/费用确认、分组进度与对照结果。 |
| PINJ-006 / P1；PINJ-007 / P2 | 当前页面只有已实现家族选择；无顺序/位置专项、工具契约专项配置/证据页面。现普通 differential 选择不能证明已完成这些增强。 |
| MTOK-008、MTOK-009 / P1 | 无上下文窗口专项或按账户/时间/请求类型变化的分段限制展示。模型档案 context window 字段不是实际窗口测试。 |
| RINT-006 / P1 | 无响应 JSON 字段删除/添加/类型变化的专属比较视图；正常响应解析不是字段改写检测。 |
| BASE-006 / P1 | 无同批可信基线随机变量/seed 配对界面及可比性说明；已有内部行为配对统计不能替代此项。 |
| REP-007 / P1 | 无 PDF/CSV 导出；HTML/JSON 仍在开发，也不能当作 PDF/CSV 已交付。 |
| REP-008 / P1 | 完整报告版本链未接；基础 canonical hash 仍必须随 V1.0 M5-08 交付。 |
| REP-009 / P1 | 无双 Run 差异报告/选择/不可比提示。一个 Run 内配对差分不是两个任务的差异报告。 |
| HIS-004 / P1 | 无历史原始证据在固定基线下重分析、新 revision 选择与旧 revision 浏览；当前路由仅接受 revision 1。 |
| HIS-005 / P1 | 无显著恶化通知中心、Webhook 订阅/投递状态/确认。风险标签不等于产生通知。 |
| CFG-005 / P1 | 无新规则灰度组织/目标范围、观察指标、暂停/回滚控制。 |

## 交付核对与推荐顺序

建议后续按可独立验证的功能闭环推进，顺序不是新增授权，也不是正式审核结论：

1. **先补结果到可交付证据/报告。** 对齐正在实现的报告 API，完成 REP-006/基础 REP-008：范围确认、授权、异步状态、JSON/HTML 下载/哈希。并行先做 REP-002 可点击引用/跨页样本定位；再在服务端有独立正文授权与审计后做 REP-003/REP-005。不要先把 S2 塞进共享 S1 统计响应。
2. **补运行的可操作性。** RUN-006 每探针阶段与分母、RUN-008 选择性复测且新 Run 不覆盖；补真实浏览器配置→预估→确认→活动 SSE→断网/撤权/取消→结果流程。
3. **补 P0 可信治理。** 基线审批/过期与选择、人工复核及双结论、规则回放/发布/审计。后端基线服务可与报告 UI 并行，界面只消费真实权限与状态，不虚构批准。
4. **补历史的指标语义和总览。** HIS-001 成功率/延迟明确分母、HIS-002 版本可比性、HIS-003 风险项，组织 7/30 天聚合及趋势。再做两 Run 比较/差异报告（REP-009 原 P1），不要从当前页数据拼装“全组织”趋势。
5. **完成管理与通用交互覆盖并继续原 P1/P2。** 系统状态、审计、保留策略生效/到期/删除回执、独立全会话退出；全 P0 页面逐项验证加载/空/失败/无权限/冲突/过期/部分完成、键盘焦点与窄屏。随后继续 Goal 已包含的 OIDC、通知、定时、多目标等原 P1/P2，实施前明确各增强自己的安全边界。

旧说明纠正（只改文案，不扩功能）：

- 经集成人授权，已纠正 [targets/README.md](../../web/src/components/targets/README.md)、[runs/README.md](../../web/src/components/runs/README.md) 和 [TargetsPage.tsx](../../web/src/components/targets/TargetsPage.tsx) 的旧说明：历史/分析结果已接；报告未接；运行进度使用有界 SSE 加 GET 核对，不再称每 5 秒轮询。
- [targets.test.tsx](../../web/src/targets.test.tsx) 增加实际结果/报告范围文字断言，不放宽原先“打开目标不触发写请求”的检查。
- 文案单元复验：使用仓库固定 Node `v24.19.0`/pnpm `11.19.0`，`pnpm test` 14 文件/309 测试通过，`pnpm build`、`pnpm lint` 通过；本文件 51 个本地链接全部存在，所改文件 `git diff --check` 通过。未重新执行浏览器测试。
- 后续由集成人将上表实现路径与具体测试回填 `requirements-v1.json`，保留部分实现状态，不能一次性把 77 项标为完成。持续台账、用户可见文案与需求索引应对应同一个已提交 checkpoint。

除上述获授权的旧文案及对应测试纠正外，本单元不修改业务功能、不触发任何付费调用或外部状态变更；不声称完成正式审核、全部 P0/P1/P2、独立盲测、生产发布或端到端性能验收。
