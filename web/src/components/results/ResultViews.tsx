import type { AnalysisResult, BehaviorAnalysis, Finding, Sample, TokenAnalysis } from '../../results-api'
import { riskLabels } from '../../runs-history-api'

export const measured = (value: number | null | undefined, digits = 2) => value == null ? '未测 / 不可估' : value.toLocaleString(undefined, { maximumFractionDigits: digits })
const yesNo = (value: boolean | null) => value === null ? '未测' : value ? '是' : '否'
export const qualityLabels: Record<string, string> = { exact: '精确', compatible: '兼容', heuristic: '启发式', unavailable: '不可用' }
const names: Record<string, string> = {
  sequence: '序列', jsonl: 'JSONL', format: '格式契约', neutral: '中性任务', differential: '差分', style: '风格', self_report: '模型自述',
  extra_prefix: '额外前缀', extra_suffix: '额外后缀', refusal_like: '拒答类线索', self_identity_like: '身份自称类线索',
  cross_family_repeat: '跨家族重复', insufficient_coverage: '覆盖不足', matches: '契约匹配', deviates: '契约偏离', not_applicable: '不适用', no_cue: '未检出线索',
  contract_deviation: '契约偏离率', extra_affix: '额外前后缀率', neutral_refusal_like: '中性任务拒答率', unsolicited_identity_like: '非请求身份自称率', descriptive_available: '描述性统计可用', insufficient_pairs: '有效配对不足', no_discordant_pairs: '无不一致配对',
}
export const label = (code: string) => names[code] ?? code
const limitations: Record<string, string> = {
  MI_PROBE_DEVELOPMENT_UNCALIBRATED: '探针开发版本尚未校准。', MI_TEMPLATE_PUBLIC_DEVELOPMENT_POOL: '使用公开开发模板。',
  development_uncalibrated: '开发评分尚未校准。', public_development_templates: '公开开发模板不构成独立验收集。',
  insufficient_samples: '有效样本不足。', partial_run: '检测不完整。', reasoning_unseparated: '上游未分离隐藏推理 Token，不能直接比较可见输出。',
  MI_DEVELOPMENT_RULES_UNCALIBRATED: '开发规则尚未校准。', MI_COMPONENTS_MISSING_RENORMALIZED: '部分维度缺失，按有效维度重新归一化权重。',
  MI_BASELINE_UNAVAILABLE: '未接入可信基线，不能做基线一致性结论。', MI_GATEWAY_EVIDENCE_UNAVAILABLE: '缺少网关直接证据，只能作黑盒观察。',
  MI_P_VALUE_NOT_RISK: 'P 值不是风险分数或模型真实性概率。', MI_MULTIPLE_COMPARISONS_EXPLORATORY: '多重比较仅作探索性分析。',
  MI_TOKENIZER_HEURISTIC_ONLY: '只有启发式分词计数，结论受限。', MI_TOKENIZER_HEURISTIC_LIMIT: '启发式分词降低证据强度。', MI_TOKENIZER_UNAVAILABLE: '分词器不可用，相应计数不能当作 0。',
  MI_REASONING_UNSEPARATED: '隐藏推理 Token 未单独报告，不能直接比较可见输出 Usage。', MI_NATURAL_EOS_ALTERNATIVE: '自然结束是输出平台的替代解释。',
  MI_PARTIAL_RESULT: '检测仅部分完成。', MI_INDEPENDENT_GROUPS_INSUFFICIENT: '独立随机组不足。', MI_BOOTSTRAP_GROUPS_INSUFFICIENT: '可重采样的独立组不足，区间不可用。',
  MI_DECLARED_MODEL_OUTPUT_LIMIT: '模型声明的输出上限也可能解释此现象。', MI_STREAM_MODES_NOT_COMPARABLE: '流式与非流式配置不可直接比较。',
  MI_USAGE_INSUFFICIENT: '有效 Usage 观测不足。', MI_PAIRED_SAMPLES_INSUFFICIENT: '有效配对样本不足。', MI_SINGLE_TIER_LIMIT: '只有一个输出档位，不能确认平台。',
  MI_VALID_SAMPLES_INSUFFICIENT: '有效样本不足。', MI_NO_VALID_SAMPLES: '没有有效样本。', MI_PARTIAL_CONFIDENCE_LIMIT: '部分执行限制置信度。',
  MI_UNCALIBRATED_CONFIDENCE_LIMIT: '未校准开发版本限制置信度。', MI_PROTOCOL_SCORE_NOT_PROVIDER_MISCONDUCT: '协议异常不能归因于供应商有意修改。',
  MI_BH_DEPENDENCE_ASSUMPTION: 'BH 多重比较解释受依赖性假设限制。', MI_IDENTITY_STYLE_ONLY: '身份自称和风格差异不是身份证明。',
  MI_REVIEW_OBSERVED_EVIDENCE: '由有权限的人员核对实际样本、错误类型与替代解释。', MI_REPEAT_WITH_TRUSTED_BASELINE: '建立获批准的可信基线后，再独立复测；本页不会自动发起调用。',
  ordinary_model_variation: '模型本身的正常变动也是替代解释。', capability_or_protocol_limits: '能力边界或协议兼容限制也是替代解释。',
}
export function Limitations({ codes, title = '限制与缺失项' }: { codes: string[]; title?: string }) {
  return codes.length > 0 ? <div className="result-limitations"><h4>{title}</h4><ul>{codes.map((code, i) => <li key={`${code}-${i}`}>{limitations[code] ?? `服务端限制标识：${code}`}</li>)}</ul></div> : <p className="field-help">此部分没有额外限制标识；不代表已排除所有替代解释。</p>
}
export function OverviewResult({ result }: { result: AnalysisResult }) {
  const scores: [string, number | null][] = [['综合风险信号', result.overall_risk], ['提示词影响', result.prompt_risk], ['输出预算 / Token', result.token_risk], ['响应处理', result.response_risk], ['协议证据', result.evidence_risk]]
  return <>
    <h3>修订 1 · 结果总览</h3><p className="result-risk">{riskLabels[result.risk_level]} · {result.completeness === 'full' ? '本次计划分析完整' : result.completeness === 'partial' ? '部分结果' : '证据不足'}</p>
    <p>本修订评分有效样本：{result.valid_samples} / {result.expected_samples} 个计划样本。排除项和自述辅助项不应解释为有效的零风险样本。</p>
    <dl className="run-metrics">{scores.map(([name, score]) => <div key={name}><dt>{name}</dt><dd>{measured(score, 1)}{score !== null && <small> / 100</small>}</dd></div>)}<div><dt>置信度</dt><dd>{result.confidence} / 100</dd></div><div><dt>证据等级</dt><dd>{result.evidence_grade}</dd></div></dl>
    <p className="notice warning">这些是未校准的黑盒统计风险信号，不是模型真假概率。缺失维度不记作 0 分；有效维度的权重会重新归一化。当前只允许 C / D 级证据，不能升级为 A / B 或直接证明供应商内部实现。</p>
    <p className="field-help">C / D 代表有限统计证据或证据不足。置信度不等于准确率；快速包、部分执行、缺测与低质量分词都会限制结论。</p>
    <Limitations codes={result.limitations} /><Limitations codes={result.recommendations} title="服务端建议标识" />
    <h4>替代解释与下一步</h4><p>模型自然差异、模板敏感性、采样随机性、隐藏推理、兼容网关、网络中断和分词误差均可能影响观测。先核对样本分母与 Tokenizer 质量，再由有权限的人员独立复测；不要仅凭本页停用生产渠道。</p>
    <dl className="run-versions"><dt>规则包</dt><dd>{result.versions.rule_bundle}</dd><dt>模板包</dt><dd>{result.versions.template_bundle}</dd><dt>评分版本</dt><dd>{result.versions.scoring}</dd><dt>Tokenizer 包</dt><dd>{result.versions.tokenizer_bundle}</dd><dt>生成时间</dt><dd><time dateTime={result.created_at}>{new Date(result.created_at).toLocaleString()}</time></dd></dl>
  </>
}
export function TokenResult({ data, samples }: { data: TokenAnalysis; samples: Sample[] }) {
  return <>
    <h3>Token 与输出预算分析</h3><p className="field-help">只分析最终有效 Attempt。真实请求含重试，不是独立样本量；隐藏推理未分离时 Usage 比较不适用。可见输出 Token 不等于上游全部计费 Token。</p>
    <dl className="run-metrics"><div><dt>Usage 比较样本分母</dt><dd>{data.usage_samples}</dd></div><div><dt>Usage 相对误差中位数</dt><dd>{data.usage_samples ? measured(data.usage_median_relative_error) : '未测 / 分母为 0'}</dd></div><div><dt>流式配对分母</dt><dd>{data.stream_pairs}</dd></div><div><dt>流式相对差异中位数</dt><dd>{data.stream_pairs ? measured(data.stream_median_relative_difference) : '未测 / 分母为 0'}</dd></div></dl>
    <TokenScatter samples={samples} />
    <h4>整次检测的档位统计</h4>{data.tiers.length === 0 ? <p className="empty-note">没有可用档位统计；不能推断存在或不存在平台。</p> : <div className="table-scroll"><table><caption className="sr-only">Token 档位中位数与离散度</caption><thead><tr><th>固定系列 / 家族</th><th>语言 / 请求上限</th><th>样本分母</th><th>输出中位数</th><th>MAD / 稳健 CV</th></tr></thead><tbody>{data.tiers.map((t, i) => <tr key={`${t.series_id}-${t.requested_max_tokens}-${i}`}><th scope="row"><abbr title={t.series_id}>{t.series_id.slice(0, 12)}</abbr> · {label(t.family)}</th><td>{t.language} · {t.requested_max_tokens}</td><td>{t.samples}</td><td>{measured(t.median)}</td><td>{measured(t.mad)} / {measured(t.robust_cv)}</td></tr>)}</tbody></table></div>}
    <h4>平台候选（不是内部限额证明）</h4>{data.plateaus.length === 0 ? <p className="empty-note">没有平台统计项。</p> : data.plateaus.map((p, i) => <article className="result-card" key={`${p.series_id}-${i}`}><h5>{label(p.family)} · 上限 {p.low_requested} → {p.high_requested}</h5><p>{p.candidate ? '平台候选信号' : '未达到候选条件'} · {p.limited ? '结论受限' : '统计条件可用'} · {p.paired ? '配对分析' : '非配对分析'} · 独立组 {p.independent_groups}</p><p>增长比 {measured(p.growth_ratio)} · 信号强度 {measured(p.strength)} · 区间 [{measured(p.lower)}, {measured(p.upper)}] · 引用样本 {p.sample_refs.length}</p><Limitations codes={p.limitations} /></article>)}
    <Limitations codes={data.limitations} />
  </>
}
function TokenScatter({ samples }: { samples: Sample[] }) {
  const points = samples.filter((s) => s.included && (s.local_completion_tokens !== null || s.reported_completion_tokens !== null))
  const max = Math.max(1, ...points.flatMap((s) => [s.requested_max_tokens, s.local_completion_tokens ?? 0, s.reported_completion_tokens ?? 0]))
  const x = (n: number) => 60 + n / max * 650
  const y = (n: number) => 300 - n / max * 250
  // SVG is a native vector image; replacing it with an HTML img would discard its accessible data points.
  // oxlint-disable-next-line jsx-a11y/prefer-tag-over-role
  return <figure className="token-chart"><figcaption>当前样本页散点（{points.length} 个有效样本；不是全量分布）</figcaption>{points.length === 0 ? <p className="empty-note">当前页没有可绘制的 Token 观测，未测值不会作为原点。</p> : <svg viewBox="0 0 780 360" role="img" aria-label="当前样本页请求上限与本地及上游 Token 散点，圆形非流式，方形流式。精确值在下方样本表。">
    <line x1="60" y1="300" x2="720" y2="300" className="chart-axis" /><line x1="60" y1="300" x2="60" y2="40" className="chart-axis" /><line x1="60" y1="300" x2="710" y2="50" className="chart-reference" /><text x="600" y="38">y = x 参考</text><text x="270" y="345">请求输出上限（Token）</text><text x="4" y="20">输出 Token</text><text x="38" y="320">0</text><text x="685" y="320">{max}</text><text x="3" y="55">{max}</text>
    {points.flatMap((s) => ([['本地', s.local_completion_tokens, 'chart-local'], ['上游', s.reported_completion_tokens, 'chart-reported']] as const).map(([name, n, css]) => n === null ? null : s.stream ? <rect key={`${s.id}-${name}`} x={x(s.requested_max_tokens) - 4} y={y(n) - 4} width="8" height="8" className={css}><title>样本 {s.id} · {name} {n} · 流式 · {qualityLabels[s.tokenizer_quality]}</title></rect> : <circle key={`${s.id}-${name}`} cx={x(s.requested_max_tokens)} cy={y(n)} r="4" className={css}><title>样本 {s.id} · {name} {n} · 非流式 · {qualityLabels[s.tokenizer_quality]}</title></circle>))}
  </svg>}<p className="field-help">蓝色：本地可见输出；橙色：上游 Usage。圆形：非流式；方形：流式。分词质量见样本表。不同系列不可混合解释；全量档位中位数另列，不跨系列连接趋势线。</p></figure>
}
export function BehaviorResult({ data }: { data: BehaviorAnalysis }) {
  return <><h3>行为与响应处理分析</h3><dl className="run-metrics"><div><dt>可分析样本</dt><dd>{data.analyzed_samples}</dd></div><div><dt>模型自述辅助样本（权重 0）</dt><dd>{data.auxiliary_samples}</dd></div></dl><p className="notice warning">自述不是身份证明，不进入真实性评分。契约偏离、额外文本或拒答类线索只能表示观察到的行为；安全对齐和合法网关包装也是替代解释。</p>
    <h4>重复模式（仅摘要指纹，无原文）</h4>{data.patterns.length === 0 ? <p className="empty-note">没有可展示的重复模式；不等于确认没有注入或改写。</p> : <div className="table-scroll"><table><caption className="sr-only">跨家族行为重复模式</caption><thead><tr><th>类型 / 状态</th><th>摘要指纹</th><th>家族 / 模板 / 语言数</th><th>引用样本分母</th></tr></thead><tbody>{data.patterns.map((p, i) => <tr key={`${p.fingerprint}-${i}`}><th scope="row">{label(p.kind)}<span className="cell-detail">{label(p.state)}</span></th><td className="result-hash">{p.fingerprint}</td><td>{p.family_count} / {p.template_count} / {p.language_count}</td><td>{p.sample_refs.length}</td></tr>)}</tbody></table></div>}
    <h4>探索性配对差分 · BH 多重比较校正</h4><p className="field-help">显著性不等于因果证据。差分受模板、语种、随机性与样本量影响；BH 校正值只能用于这次探索性比较，不能当作校准后的错误率或模型真假概率。</p>{data.differences.length === 0 ? <p className="empty-note">没有可用配对差分。</p> : <div className="table-scroll"><table><caption className="sr-only">行为配对差分与校正 P 值</caption><thead><tr><th>指标 / 状态</th><th>有效配对数</th><th>效应量</th><th>原始 P</th><th>BH 校正 P</th></tr></thead><tbody>{data.differences.map((d, i) => <tr key={`${d.metric}-${i}`}><th scope="row">{label(d.metric)}<span className="cell-detail">{label(d.state)}</span></th><td>{d.pairs}</td><td>{measured(d.effect_size, 4)}</td><td>{measured(d.p_value, 4)}</td><td>{measured(d.adjusted_p, 4)}</td></tr>)}</tbody></table></div>}<Limitations codes={data.limitations} /></>
}
export function Findings({ items }: { items: Finding[] }) {
  return <><h3>S1 证据发现</h3>{items.length === 0 ? <p className="empty-note">当前页没有发现项；不能据此认定模型真实或无风险。</p> : items.map((f) => <article key={f.id} className="result-card"><h4>{f.title}</h4><p>{f.summary}</p><p className="field-help">规则 {f.rule_id} / {f.rule_version} · {f.category} · 风险信号 {measured(f.risk_score, 1)} · 置信度 {f.confidence} · 证据 {f.evidence_grade}</p><dl className="run-metrics">{f.statistics.map((s, i) => <div key={`${s.name}-${i}`}><dt>{label(s.name)}（{s.unit}）</dt><dd>{measured(s.actual)}</dd></div>)}</dl><h5>替代解释</h5>{f.alternative_explanations.length ? <ul>{f.alternative_explanations.map((text, i) => <li key={i}>{text}</li>)}</ul> : <p>未提供专属解释列表，不代表替代解释已被排除。</p>}<p className="field-help">引用样本：{f.sample_refs.join('、') || '未提供'}。可在下方样本页读取 S1 元数据；没有响应正文入口。</p></article>)}</>
}
export function Samples({ items, onSelect }: { items: Sample[]; onSelect: (id: string) => void }) {
  return <><h4>最终样本 S1 元数据（当前页）</h4><p className="field-help">默认隐藏全部请求和响应正文，不存入浏览器持久缓存。重试不是额外独立样本；只有 Final Attempt 决定纳入情况。</p>{items.length === 0 ? <p className="empty-note">当前页无样本元数据。</p> : <div className="table-scroll"><table><caption className="sr-only">最终样本、Token 质量与行为分类</caption><thead><tr><th>样本 / 纳入</th><th>Token / 分词质量</th><th>协议 / 结构</th><th>行为分类</th><th>详情</th></tr></thead><tbody>{items.map((s) => <tr key={s.id}><th scope="row">{s.id}<span className="cell-detail">序号 {s.ordinal} · {label(s.family)} · {s.language}</span><span className="cell-detail">{s.auxiliary_only ? '仅自述辅助，权重 0' : s.included ? '纳入分析' : '排除，不作有效零值'} · {s.validity}</span></th><td>请求上限 {s.requested_max_tokens}<span className="cell-detail">本地 {measured(s.local_completion_tokens, 0)} / 上游 {measured(s.reported_completion_tokens, 0)}</span><span className="cell-detail">{qualityLabels[s.tokenizer_quality]} · {s.tokenizer_id || '无可用分词器'}</span></td><td>{s.stream ? '流式' : '非流式'} · finish {s.finish_reason ?? '未测'}<span className="cell-detail">结构完整 {yesNo(s.structure_complete)} / 硬截断 {yesNo(s.hard_truncation)}</span></td><td>契约 {s.contract ? label(s.contract) : '未测'}<span className="cell-detail">拒答 {s.refusal_class ? label(s.refusal_class) : '未测'} / 身份 {s.identity_class ? label(s.identity_class) : '未测'}</span></td><td><button onClick={() => onSelect(s.id)} aria-label={`读取样本 ${s.id} 的尝试记录`}>尝试记录</button></td></tr>)}</tbody></table></div>}</>
}
