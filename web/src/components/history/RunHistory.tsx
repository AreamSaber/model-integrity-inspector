import { useEffect, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { historyApi, historyQuery, packageLabels, riskLabels, riskLevels, type HistoryFilters, type ReadPage, type RunHistoryItem } from '../../runs-history-api'
import { packages, runStatuses, runsApi, type Run } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import { useFailure } from '../management/shared'
import { RunProgress, statusLabels } from '../runs/RunProgress'
import { cost } from '../runs/RunQuote'
import type { TargetCallbacks } from '../targets/TargetForm'
import { comparisonHref } from '../../comparison-api'
import { trendsHref } from '../../trends-api'

export type ReadContext = TargetCallbacks & { userID: string }
export function RunHistory(context: ReadContext & { resultsOnly?: boolean }) { return <RunHistoryScope key={`${context.organizationID}-${context.userID}-${context.resultsOnly}`} {...context} /> }
function RunHistoryScope(context: ReadContext & { resultsOnly?: boolean }) {
  const onFailure = useFailure(context)
  const [filters, setFilters] = useState<HistoryFilters>({})
  const [cursors, setCursors] = useState([''])
  const [reload, setReload] = useState(0)
  const [result, setResult] = useState<ReadPage<RunHistoryItem> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [filterError, setFilterError] = useState('')
  const [compareLeft, setCompareLeft] = useState(''), [compareRight, setCompareRight] = useState('')
  const cursor = cursors[cursors.length - 1]
  useEffect(() => {
    const controller = new AbortController()
    void historyApi.list(context.organizationID, filters, cursor, controller.signal).then((data) => {
      if (!controller.signal.aborted) setResult(data)
    }).catch((failure: unknown) => { if (!controller.signal.aborted) { setResult(null); setCompareLeft(''); setCompareRight(''); if (!onFailure(failure)) setError(failure) } }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, filters, cursor, reload, onFailure])
  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const next = Object.fromEntries([...form.entries()].map(([key, value]) => [key, String(value).trim()])) as HistoryFilters
    try {
      for (const key of ['date_from', 'date_to'] as const) if (next[key]) next[key] = new Date(next[key]).toISOString()
      historyQuery(next); reset(); setFilters(next); setCursors(['']); setFilterError('')
    } catch { setFilterError('筛选字段格式无效：ID 必须是十进制整数，日期范围需正序，文本最多 128 字节。') }
  }
  function reset() { setLoading(true); setResult(null); setError(null) }
  return <section className="panel" aria-labelledby="history-title">
    <div className="section-heading"><h2 id="history-title">{context.resultsOnly ? '历史检测与已有结果' : '检测任务历史'}</h2><div className="form-actions"><a href="#/compare">输入两个任务进行对比 →</a><a href="#/trends">按目标读取趋势 →</a><a href="#/targets">从目标创建检测 →</a></div></div>
    {context.resultsOnly && <p className="notice warning">此处读取已有分析修订；结果页已支持显式生成和下载脱敏 S1 JSON/HTML 报告。正式审核尚未完成，报告不代表软件获批。</p>}
    <p className="muted">服务端组织范围分页，按创建时间由近到远。搜索、模型和渠道筛选使用当前目标档案，不能当作历史快照；已删除目标的任务仍保留目标 ID。</p>
    <form className="history-filters" aria-label="筛选检测历史" onSubmit={search}>
      <label>搜索目标或模型<input name="q" type="search" maxLength={128} /></label>
      <label>目标 ID<input name="target_id" inputMode="numeric" maxLength={19} /></label>
      <label>任务状态<select name="status"><option value="">全部状态</option>{runStatuses.map((status) => <option key={status} value={status}>{statusLabels[status]}</option>)}</select></label>
      <label>检测包<select name="package"><option value="">全部检测包</option>{packages.map((kind) => <option key={kind} value={kind}>{packageLabels[kind]}</option>)}</select></label>
      <label>当前模型<input name="model" maxLength={128} /></label><label>当前渠道<input name="channel_id" maxLength={128} /></label>
      <label>风险信号<select name="risk_level"><option value="">全部风险信号</option>{riskLevels.map((risk) => <option key={risk} value={risk}>{riskLabels[risk]}</option>)}</select></label>
      <label>创建时间起（本地时间）<input name="date_from" type="datetime-local" /></label><label>创建时间止（本地时间）<input name="date_to" type="datetime-local" /></label>
      <div className="form-actions"><button type="submit" disabled={loading}>应用筛选</button><button type="button" disabled={loading} onClick={() => { reset(); setReload((v) => v + 1) }}>刷新历史</button></div>
    </form>
    {filterError && <p role="alert" className="field-error">{filterError}</p>}
    {loading && <Loading>正在读取检测历史…</Loading>}<ErrorNotice error={error} />
    {error instanceof ApiError && error.status === 403 && <p className="notice warning">任务读取权限不可用，已清除本页缓存。请联系组织管理员。</p>}
    {!loading && !error && result?.items.length === 0 && <p className="empty-note">没有符合条件的检测任务。未返回记录不代表风险为零。</p>}
    {result && result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">检测历史与分析修订</caption><thead><tr><th>任务 / 目标</th><th>状态 / 检测包</th><th>采样与费用</th><th>已发布机器分析</th><th>创建时间</th></tr></thead><tbody>{result.items.map((item) => <tr key={item.id}>
      <th scope="row"><a href={`#/runs/${item.id}`}>Run {item.id}</a><span className="cell-detail">目标 ID {item.target_id}</span><span className="cell-detail"><a href={trendsHref(item.target_id)}>目标 {item.target_id} 趋势</a></span><span className="cell-detail">评分版本 {item.versions.scoring}</span></th>
      <td>{statusLabels[item.status]}<span className="cell-detail">{packageLabels[item.package]}</span></td>
      <td>结束 {item.completed_samples} / {item.planned_samples} · 有效 {item.valid_sample_count}<span className="cell-detail">请求 {item.request_count}（含重试） · Token {item.token_count}</span><span className="cell-detail">{cost(item.estimated_cost_micros)}</span></td>
      <td>{item.result ? <><a href={`#/results/${item.id}/1`}>修订 1 · {riskLabels[item.result.risk_level]}</a><span className="cell-detail">风险 {item.result.overall_risk === null ? '不可估' : item.result.overall_risk.toFixed(1)} · 置信度 {item.result.confidence.toFixed(0)} / 100 · 等级 {item.result.evidence_grade}</span><div className="form-actions"><button onClick={() => setCompareLeft(item.id)} aria-label={`将 Run ${item.id} 选为对比左侧`}>选为左侧</button><button onClick={() => setCompareRight(item.id)} aria-label={`将 Run ${item.id} 选为对比右侧`}>选为右侧</button></div></> : '尚无可读取的分析修订'}</td>
      <td><time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time></td>
    </tr>)}</tbody></table></div>}
    {(compareLeft || compareRight) && <section className="result-card" aria-labelledby="history-comparison-title"><h3 id="history-comparison-title">两任务对比选择</h3><p>左侧：{compareLeft || '未选择'} · 右侧：{compareRight || '未选择'}</p><p className="field-help">只保留两个已选 ID，可跨当前筛选页选择；打开后将重新读取它们在当前组织的真实固定修订，不使用列表摘要冒充对比数据。</p>{compareLeft && compareRight && compareLeft !== compareRight ? <a className="button-link" href={comparisonHref(compareLeft, compareRight)}>读取所选两个固定修订 →</a> : <p className="empty-note">请选择两个不同的、有已发布结果的 Run。</p>}<button onClick={() => { setCompareLeft(''); setCompareRight('') }}>清除对比选择</button></section>}
    <div className="pagination"><button disabled={loading || cursors.length === 1} onClick={() => { reset(); setCursors((v) => v.slice(0, -1)) }}>上一页</button><span>第 {cursors.length} 页</span><button disabled={loading || Boolean(error) || !result?.next_cursor || cursors.length >= 1000 || (result?.next_cursor ? cursors.includes(result.next_cursor) : false)} onClick={() => { if (result?.next_cursor) { const next = result.next_cursor; reset(); setCursors((v) => [...v, next]) } }}>下一页</button></div>
    <p className="field-help">开发分析尚未校准，使用公开开发模板，只支持 C / D 级证据；不能由分数判断模型真假。缺失结果不是 0 分。</p>
  </section>
}

export function HistoricalRun(context: ReadContext & { runID: string }) { return <HistoricalRunScope key={`${context.organizationID}-${context.userID}-${context.runID}`} {...context} /> }
function HistoricalRunScope({ runID, ...context }: ReadContext & { runID: string }) {
  const onFailure = useFailure(context)
  const [value, setValue] = useState<{ run: Run; permissions: string[] } | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    void runsApi.permissions(context.organizationID, context.userID, controller.signal).then(async (granted) => {
      if (controller.signal.aborted) return
      if (!granted.permissions.includes('run.read')) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const run = await runsApi.get(context.organizationID, runID, controller.signal)
      if (!controller.signal.aborted) setValue({ run, permissions: granted.permissions })
    }).catch((failure: unknown) => { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, runID, reload, onFailure])
  return <section className="panel"><a href="#/runs">← 返回检测历史</a>{loading && <Loading>正在读取固定检测及权限…</Loading>}<ErrorNotice error={error} />{Boolean(error) && <button onClick={() => { setValue(null); setError(null); setLoading(true); setReload((v) => v + 1) }}>重新读取检测</button>}{value && <RunProgress key={`${context.organizationID}-${runID}`} {...context} initial={value.run} initialPermissions={value.permissions} />}</section>
}
