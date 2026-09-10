import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { overviewApi, type Overview, type OverviewDays } from '../../overview-api'
import { packageLabels, riskLabels, riskLevels } from '../../runs-history-api'
import { runStatuses } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'
import { statusLabels } from '../runs/RunProgress'

const explanations: Record<string, string> = {
  MI_OVERVIEW_BUSY: '组织总览正在被读取。请稍后手动刷新，不会自动重试。',
  MI_OVERVIEW_LIMIT: '此窗口任务数、当前目标数或聚合大小超过开发保护上限，未返回任何截断统计。可尝试 7 天窗口或联系管理员。',
  MI_OVERVIEW_TIMEOUT: '总览查询超过 2 秒保护期限，未返回部分统计。请稍后手动刷新。',
  MI_OVERVIEW_TIMEZONE_INVALID: '组织时区配置无法稳定解析。请管理员选择 UTC 或明确 IANA 地区，不支持主机 Local。',
  MI_ANALYSIS_RESULT_INVALID: '服务端摘要校验失败，已停止展示总览；不能将损坏数据视为低风险。请联系管理员。',
  MI_PERMISSION_DENIED: '需要当前组织的 run.read 和 target.read 权限。权限不足或已撤销，已清空总览数据。',
  MI_INVALID_RESPONSE: '总览响应的组织、窗口或统计分母不一致，已清空数据；不会保留旧统计冒充新结果。',
}
export function OverviewPage(props: ReadContext) { return <OverviewScope key={`${props.organizationID}:${props.userID}`} {...props} /> }
function OverviewScope(context: ReadContext) {
  const [days, setDays] = useState<OverviewDays>(7), [reload, setReload] = useState(0), [data, setData] = useState<Overview | null>(null)
  const [loading, setLoading] = useState(true), [error, setError] = useState<unknown>(null)
  const onFailure = useFailure(context), heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => {
    const controller = new AbortController()
    void overviewApi.read(context.organizationID, context.userID, days, controller.signal).then((value) => {
      if (!controller.signal.aborted) { setData(value); heading.current?.focus() }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setData(null); if (!onFailure(failure)) setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, days, reload, onFailure])
  function reset() { setData(null); setError(null); setLoading(true) }
  const explanation = error instanceof ApiError ? explanations[error.code] : undefined
  return <section className="panel" aria-labelledby="overview-title">
    <div className="section-heading"><h2 ref={heading} tabIndex={-1} id="overview-title">组织检测统计</h2><a href="#/runs">查看任务历史 →</a></div>
    <div className="history-filters"><label htmlFor="overview-days">日历日窗口<select id="overview-days" value={days} onChange={(event) => { reset(); setDays(Number(event.target.value) as OverviewDays) }}><option value={7}>近 7 个日历日（含今日）</option><option value={30}>近 30 个日历日（含今日）</option></select></label><button disabled={loading} onClick={() => { reset(); setReload((n) => n + 1) }}>刷新组织总览</button></div>
    <p className="notice warning">完整组织窗口聚合，不是历史列表当前页。风险仅来自已发布修订 1，按冻结版本与检测包分层；开发规则未校准，正式审核未完成。</p>
    {loading && <Loading>正在验证组织权限并读取总览快照…</Loading>}
    <ErrorNotice error={explanation ?? error} id="overview-error" />
    {data && <OverviewData data={data} />}
    <section className="result-card" aria-labelledby="overview-basis"><h3 id="overview-basis">统计口径</h3><ul>
      <li>目标是当前未删除的目录记录，含禁用；不是可连通数。已删除目标的保留任务仍计入历史窗口。</li>
      <li>每个 Run 按创建时间只计一次。重试不增加任务数或独立样本；完成状态不是上游调用成功率或模型真实性结论。</li>
      <li>组织时区决定日界线，今日截到快照时间，是未完成日；DST 日可能为 23/25 小时，不能把今日少量直接解释为下降。</li>
      <li>风险分布分母为可估风险的已发布结果；未发布与已发布不可估分别计数，不作为低风险。置信度不是概率，此处不重算风险分。</li>
      <li>费用是已有派发阶段 USD 估算，不是账单。未知不补零，已知小计只代表已知部分；空窗口没有费用观测。</li>
    </ul></section>
    <div className="workflow-links"><a href="#/targets">目标与模型档案 →</a><a href="#/runs">检测任务 →</a><a href="#/reports">结果与报告 →</a><a href="#/trends">单目标调用成功率与延迟 →</a></div>
    <p className="field-help">按需读取，不自动监控、发起检测或导出报告。切换组织、账号、窗口或离开页面会取消读取并清空旧数据；手动刷新重新验证权限。初始保护上限为窗口任务和当前目标各 10,000，不是生产容量验收。</p>
  </section>
}
// Display integer micros without floating-point money rounding.
function usd(value: number | null) { if (value === null) return '未知 / 无观测'; const n = BigInt(value); return `$${n / 1000000n}.${(n % 1000000n).toString().padStart(6, '0')} USD` }
function OverviewData({ data: d }: { data: Overview }) {
  return <>
    <p className="field-help">组织时区：{d.window.timezone} · 快照 <time dateTime={d.window.as_of}>{d.window.as_of}</time><br />UTC 半开区间 [{d.window.start_utc}, {d.window.end_utc})</p>
    {d.runs.total === 0 && <p className="empty-note">本窗口没有任务。没有记录不代表风险或费用为零；可先管理目标，手动预检并确认检测费用。</p>}
    <dl className="run-metrics"><div><dt>当前目录目标（含禁用）</dt><dd>{d.targets.total}</dd><dd>启用 {d.targets.active} · 禁用 {d.targets.disabled}</dd></div><div><dt>窗口 Run 数</dt><dd>{d.runs.total}</dd><dd>每个任务只计一次</dd></div><div><dt>已发布 / 未发布</dt><dd>{d.runs.published_runs} / {d.runs.unpublished_runs}</dd><dd>可估 {d.runs.scored_runs} · 不可估 {d.runs.unscored_runs}</dd></div></dl>
    <section className="result-card" aria-labelledby="overview-cost"><h3 id="overview-cost">估算费用（非账单）</h3><p>已知部分小计：{usd(d.costs.known_subtotal_micros)}</p><p>完整窗口估算：{usd(d.costs.complete_total_micros)}</p><p className="field-help">费用已知 {d.costs.known_runs} 个 Run · 未知 {d.costs.unknown_runs} 个 Run</p></section>
    <div className="table-scroll"><table><caption>窗口任务状态（不是调用成功率）</caption><thead><tr><th scope="col">状态</th><th scope="col">Run 数</th></tr></thead><tbody>{runStatuses.map((s) => <tr key={s}><th scope="row">{statusLabels[s]}</th><td>{d.runs.by_status[s]}</td></tr>)}</tbody></table></div>
    <h3>固定修订风险分布</h3>
    {d.risk_cohorts.length === 0 && <p className="empty-note">尚无已发布修订 1 的结果，不显示风险占比。</p>}
    {d.risk_cohorts.length > 1 && <p className="notice warning">存在多个检测包或版本分层。组成或版本变化不能归因模型行为；同版本也不证明样本或配置可比，不作跨层平均或显著性判断。</p>}
    {d.risk_cohorts.map((c) => <section className="result-card" key={c.id} aria-labelledby={`overview-${c.id}`}><h4 id={`overview-${c.id}`}>{c.id} · {packageLabels[c.package]}</h4><p className="field-help">规则 {c.versions.rule_bundle} · 模板 {c.versions.template_bundle} · 评分 {c.versions.scoring} · Tokenizer {c.versions.tokenizer_bundle}</p><p>已发布 {c.published_runs} · 可估分母 {c.scored_runs} · 不可估 {c.unscored_runs}</p><ul>{riskLevels.map((level) => <li key={level}>{riskLabels[level]}：{c.distribution[level]} / {c.scored_runs}（{c.scored_runs === 0 ? '无可估分母' : `${(100 * c.distribution[level] / c.scored_runs).toFixed(1)}%`}）</li>)}</ul></section>)}
    <div className="table-scroll"><table><caption>按当地日历日统计（今日未完成）</caption><thead><tr><th scope="col">日期 / UTC 半开区间</th><th scope="col">Run 数</th><th scope="col">各版本分层的风险计数</th></tr></thead><tbody>{d.daily.map((day) => <tr key={day.local_date}><th scope="row">{day.local_date}{day.partial ? '（未完成日）' : ''}<span className="cell-detail">[{day.start_utc}, {day.end_utc})</span></th><td>{day.run_count}</td><td>{day.risk_cohorts.length === 0 ? '无已发布结果' : day.risk_cohorts.map((c) => <p key={c.cohort_id}>{c.cohort_id} · 已发布 {c.published_runs} · 可估 {c.scored_runs} · 不可估 {c.unscored_runs}<span className="cell-detail">{riskLevels.map((level) => `${riskLabels[level]} ${c.distribution[level]}`).join(' · ')}</span></p>)}</td></tr>)}</tbody></table></div>
    <p className="field-help">c1/c2 等编号仅在当前响应中标识分层，不是跨窗口稳定身份、可信基线或授权凭据。每日计数是描述性信号，不是异常趋势预测。</p>
  </>
}
