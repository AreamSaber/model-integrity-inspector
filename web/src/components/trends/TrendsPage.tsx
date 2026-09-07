import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { packageLabels, riskLabels } from '../../runs-history-api'
import { packages, runStatuses, type Versions } from '../../runs-api'
import { trendInstant, trendsApi, trendsHref, trendsQuery, utcFilterInput, type TrendsFilters, type TrendsPage as TrendData } from '../../trends-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'
import { statusLabels } from '../runs/RunProgress'

type Props = ReadContext & { targetID?: string }
type Pointer = { cursor: string; before?: { created: string; id: string } }
export function TrendsPage(props: Props) { return <TrendsScope key={`${props.organizationID}:${props.userID}:${props.targetID ?? ''}`} {...props} /> }
function TrendsScope({ targetID, ...context }: Props) {
  const onFailure = useFailure(context), heading = useRef<HTMLHeadingElement>(null)
  const [target, setTarget] = useState(targetID ?? ''), [filters, setFilters] = useState<TrendsFilters | null>(targetID ? { target_id: targetID } : null)
  const [pointers, setPointers] = useState<Pointer[]>([{ cursor: '' }]), [reload, setReload] = useState(0)
  const [data, setData] = useState<TrendData | null>(null), [error, setError] = useState<unknown>(null), [formError, setFormError] = useState('')
  const [loading, setLoading] = useState(Boolean(targetID)), [blocked, setBlocked] = useState(false)
  const current = pointers[pointers.length - 1]
  useEffect(() => {
    if (!filters || blocked) return
    const controller = new AbortController()
    void trendsApi.list(context.organizationID, context.userID, filters, current.cursor, controller.signal).then((result) => {
      if (controller.signal.aborted) return
      if (result.next_cursor && pointers.some((p) => p.cursor === result.next_cursor)) throw new ApiError('MI_INVALID_RESPONSE')
      const first = result.items[0]?.run
      if (first && current.before) {
        const instant = trendInstant(first.created_at)!, bound = trendInstant(current.before.created)!
        if (instant > bound || (instant === bound && BigInt(first.id) >= BigInt(current.before.id))) throw new ApiError('MI_INVALID_RESPONSE')
      }
      setData(result); heading.current?.focus()
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      // Stop before clearing cursor/anchor state; clearing must not itself issue
      // an automatic retry after permission denial or an invalid response.
      setBlocked(true); setData(null); setPointers([{ cursor: '' }]); setLoading(false)
      if (!onFailure(failure)) setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [filters, blocked, current, pointers, context.organizationID, context.userID, reload, onFailure])
  function reset() { setData(null); setError(null); setFormError(''); setLoading(true); setBlocked(false) }
  function chooseTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const href = trendsHref(target)
      if (target === targetID) { if (loading) return; reset(); setPointers([{ cursor: '' }]); setReload((value) => value + 1) }
      else { setData(null); setError(null); setFormError(''); window.location.hash = href }
    } catch { setFormError('目标 ID 必须是无前导零、无空格的正十进制整数，最大为 9223372036854775807。') }
  }
  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!targetID) return
    const form = new FormData(event.currentTarget)
    try {
      const next = { target_id: targetID, status: String(form.get('status') ?? ''), package: String(form.get('package') ?? ''), date_from: utcFilterInput(String(form.get('date_from') ?? '')), date_to: utcFilterInput(String(form.get('date_to') ?? '')) } as TrendsFilters
      trendsQuery(next); reset(); setFilters(next); setPointers([{ cursor: '' }])
    } catch { setFormError('筛选无效：请选择受支持的状态和检测包，并使用有效的 UTC 日期时间（精确到秒，起止顺序正确）。') }
  }
  const versionsDiffer = data && new Set(data.items.map(({ run }) => JSON.stringify(run.versions, ['rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle']))).size > 1
  return <section className="panel" aria-labelledby="trends-title">
    <div className="section-heading"><h2 ref={heading} tabIndex={-1} id="trends-title">单目标调用与风险趋势</h2><a href="#/runs">← 返回检测历史</a></div>
    <p className="notice warning">按 Run 创建时间倒序展示当前筛选页，不是全目标或全组织汇总。每条调用统计来自真实服务端同一读取快照；不拼接页面计算总成功率，不自动扫描历史或触发检测。</p>
    <form className="history-filters" aria-label="选择趋势目标" onSubmit={chooseTarget} noValidate>
      <label htmlFor="trends-target">目标 ID<input id="trends-target" inputMode="numeric" maxLength={19} value={target} onChange={(event) => setTarget(event.target.value)} /></label><div className="form-actions"><button type="submit">读取目标趋势</button></div>
    </form>
    <p className="field-help">切换目标会清空筛选、页游标及旧数据。目标已删除仍可用原 ID 读取保留的历史；不从当前目标名称或模型反推历史配置。</p>
    {targetID && <form className="history-filters" aria-label="筛选目标趋势" onSubmit={search} noValidate>
      <label>任务状态<select name="status"><option value="">全部状态</option>{runStatuses.map((status) => <option key={status} value={status}>{statusLabels[status]}</option>)}</select></label>
      <label>检测包<select name="package"><option value="">全部检测包</option>{packages.map((kind) => <option key={kind} value={kind}>{packageLabels[kind]}</option>)}</select></label>
      <label>创建时间起（UTC，精确到秒）<input name="date_from" type="datetime-local" step="1" /></label><label>创建时间止（UTC，精确到秒）<input name="date_to" type="datetime-local" step="1" /></label>
      <div className="form-actions"><button type="submit" disabled={loading}>应用趋势筛选</button><button type="button" disabled={loading} onClick={() => { reset(); setReload((value) => value + 1) }}>刷新当前页</button></div>
    </form>}
    {formError && <p role="alert" className="field-error">{formError}</p>}
    {filters && <p className="field-help">已应用：目标 {filters.target_id} · {filters.status ? statusLabels[filters.status] : '全部状态'} · {filters.package ? packageLabels[filters.package] : '全部检测包'} · UTC 起 {filters.date_from || '不限'} / 止 {filters.date_to || '不限'}（两端包含）。输入框修改后需点击应用。</p>}
    <ErrorNotice error={error} id="trends-error" />
    {loading && <Loading>正在验证当前组织权限并读取这一页趋势…</Loading>}
    {!targetID && <p className="empty-note">先选择一个目标 ID。未选择时不读取趋势或权限数据。</p>}
    {!loading && !error && data?.items.length === 0 && <p className="empty-note">当前筛选页没有可读取的 Run。没有记录不代表调用成功率或风险为 0。</p>}
    {error instanceof ApiError && error.status === 403 && <p className="notice warning">读取权限不足或已撤销，已清空数据、游标及分页锚点。请确认当前组织权限后手动重读。</p>}
    {error instanceof ApiError && error.code === 'MI_INVALID_RESPONSE' && <p className="notice warning">趋势响应的目标、统计分母、顺序或游标不一致，已停止显示。不会保留旧页冒充新数据。</p>}
    {versionsDiffer && <p className="notice warning">本页冻结版本不同：规则、模板、评分或 Tokenizer 变化与行为变化无法据此拆分，不能直接归因模型行为恶化。</p>}
    <section className="result-card" aria-labelledby="trend-basis"><h3 id="trend-basis">统计口径与解释限制</h3><ul>
      <li>调用成功率 = 已确认成功次数 / 全部派发次数。分母包括失败、未知和在途；未知不归类为失败，在途不是已完成。</li>
      <li>逻辑样本数与重试次数单列；重试是同一逻辑样本的再次派发，不增加独立样本量。调用成功不等于模型真实或低风险。</li>
      <li>延迟只含有已观测耗时的已结束调用，包括成功与失败；不含未知恢复记录、在途或缺失耗时。有效 n 单列，未测保持空值，不补 0。</li>
      <li>风险是已发布修订 1 的开发摘要；置信度是指数而非概率。执行有效样本数不冒充分析纳入样本数（自述等可能被排除）。</li>
      <li>不同检测包、冻结版本、预算或随机变量可能不可比；同一目标 ID 也不能证明配置等价。没有显著性、因果或趋势预测结论，开发结果未校准。</li>
    </ul></section>
    {data && data.items.length > 0 && <TrendTable value={data} />}
    {targetID && <div className="pagination"><button disabled={loading || blocked || pointers.length === 1} onClick={() => { reset(); setPointers((old) => old.slice(0, -1)) }}>上一页</button><span>第 {pointers.length} 页 · 仅本页 {data?.items.length ?? '—'} 条</span><button disabled={loading || blocked || !data?.next_cursor || pointers.length >= 1000} onClick={() => {
      const last = data?.items.at(-1)?.run
      if (data?.next_cursor && last) { const next = data.next_cursor; reset(); setPointers((old) => [...old, { cursor: next, before: { created: last.created_at, id: last.id } }]) }
    }}>下一页</button></div>}
    {pointers.length >= 1000 && <p className="notice warning">已达手动分页浏览上限，请缩小日期范围后重新查询；不会自动遍历剩余历史。</p>}
    <p className="field-help">页面是按需读取快照，不是实时监控。在途任务可能继续变化；刷新每次重新验证权限。离开页面、切换组织、账号或目标时取消读取并清除本地缓存。正式审核未完成。</p>
  </section>
}
function measured(value: number | null, unit: string) { return value === null ? '未测' : `${value.toFixed(2)} ${unit}` }
const versionNames: Record<keyof Versions, string> = { rule_bundle: '规则', template_bundle: '模板', scoring: '评分', tokenizer_bundle: 'Tokenizer' }
function TrendTable({ value }: { value: TrendData }) {
  return <div className="table-scroll"><table><caption>当前页按创建时间倒序的逐 Run 趋势（不跨页汇总）</caption><thead><tr><th scope="col">时间 / Run</th><th scope="col">状态 / 冻结配置</th><th scope="col">机器风险摘要</th><th scope="col">样本与重试</th><th scope="col">调用成功率</th><th scope="col">调用状态</th><th scope="col">已观测延迟</th></tr></thead><tbody>{value.items.map(({ run, attempts: a }) => <tr key={run.id}>
    <th scope="row"><time dateTime={run.created_at}>{run.created_at}</time><span className="cell-detail"><a href={`#/runs/${run.id}`}>Run {run.id}</a></span><span className="cell-detail">目标 {run.target_id}</span></th>
    <td>{statusLabels[run.status]} · {packageLabels[run.package]}<details><summary>冻结版本</summary><ul>{(Object.keys(versionNames) as (keyof Versions)[]).map((key) => <li key={key}>{versionNames[key]}：{run.versions[key]}</li>)}</ul></details></td>
    <td>{run.result ? <><a href={`#/results/${run.id}/1`}>修订 1 · {riskLabels[run.result.risk_level]}</a><span className="cell-detail">风险 {run.result.overall_risk === null ? '未测' : run.result.overall_risk.toFixed(1)} · 置信指数 {run.result.confidence} / 100</span><span className="cell-detail">证据 {run.result.evidence_grade} · {{ full: '完整', partial: '部分', insufficient: '证据不足' }[run.result.completeness]}</span></> : '尚无已发布分析（不是 0 分）'}</td>
    <td>逻辑样本 {a.logical_samples} · 重试 {a.retry_attempts}<span className="cell-detail">派发 {a.dispatched} 次</span><span className="cell-detail">执行有效 {run.valid_sample_count} · 已结束 {run.completed_samples} / 计划 {run.planned_samples}</span></td>
    <td>{measured(a.success_rate_percent, '%')}<span className="cell-detail">成功 {a.succeeded} / 派发 {a.success_rate_denominator}</span></td>
    <td>成功 {a.succeeded} · 失败 {a.failed}<span className="cell-detail">未知 {a.uncertain} · 在途 {a.in_flight}</span></td>
    <td>均值 {measured(a.latency_mean_ms, 'ms')}<span className="cell-detail">范围 {a.latency_min_ms === null ? '未测' : `${a.latency_min_ms}–${a.latency_max_ms} ms`}</span><span className="cell-detail">延迟有效 n = {a.latency_samples}</span></td>
  </tr>)}</tbody></table></div>
}
