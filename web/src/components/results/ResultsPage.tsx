import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { resultsApi, type AnalysisResult, type Finding, type Sample, type SampleDetail } from '../../results-api'
import type { ReadPage } from '../../runs-history-api'
import { runsApi } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'
import { BehaviorResult, Findings, Limitations, measured, OverviewResult, Samples, TokenResult } from './ResultViews'
import { ReviewPanel } from './ReviewPanel'
import { ReportsPanel } from './ReportsPanel'

type Tab = 'overview' | 'token' | 'behavior' | 'evidence' | 'review' | 'reports'
type Data = { result: AnalysisResult; samples?: ReadPage<Sample>; findings?: ReadPage<Finding> }
function pin(result: AnalysisResult) {
  const { token_analysis: _token, behavior_analysis: _behavior, ...summary } = result
  return JSON.stringify(Object.entries(summary).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, key === 'versions' ? Object.entries(result.versions).sort(([a], [b]) => a.localeCompare(b)) : value]))
}
export function ResultsPage(context: ReadContext & { runID: string }) { return <ResultsScope key={`${context.organizationID}-${context.userID}-${context.runID}`} {...context} /> }
function ResultsScope({ runID, ...context }: ReadContext & { runID: string }) {
  const onFailure = useFailure(context)
  const [tab, setTab] = useState<Tab>('overview')
  const [permissions, setPermissions] = useState<string[] | null>(null)
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)
  const [cursors, setCursors] = useState([''])
  const [findingCursors, setFindingCursors] = useState([''])
  const [sampleID, setSampleID] = useState<string | null>(null)
  const pinned = useRef<{ scope: string; summary: string } | null>(null)
  const cursor = cursors[cursors.length - 1], findingCursor = findingCursors[findingCursors.length - 1]
  useEffect(() => {
    const controller = new AbortController()
    void (async () => {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      setPermissions(granted.permissions)
      const statistics = tab === 'token' || tab === 'behavior' || tab === 'evidence'
      if (!granted.permissions.includes('run.read') || (statistics && !granted.permissions.includes('evidence.read')) || (tab === 'reports' && (!granted.permissions.includes('evidence.read') || !granted.permissions.includes('report.export')))) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const [result, samples, findings] = await Promise.all([
        resultsApi.get(context.organizationID, runID, statistics, controller.signal),
        statistics ? resultsApi.samples(context.organizationID, runID, cursor, controller.signal) : undefined,
        tab === 'evidence' ? resultsApi.findings(context.organizationID, runID, findingCursor, controller.signal) : undefined,
      ])
      if (controller.signal.aborted) return
      const scope = `${context.organizationID}:${runID}:1`, summary = pin(result)
      if (pinned.current?.scope === scope && pinned.current.summary !== summary) throw new ApiError('MI_INVALID_RESPONSE')
      pinned.current = { scope, summary }; setData({ result, samples, findings })
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (!onFailure(failure)) setError(failure)
      setData(null); setLoading(false)
      if (failure instanceof ApiError && failure.status === 403) setPermissions(null)
      controller.abort()
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, runID, tab, reload, cursor, findingCursor, onFailure])
  function reset() { setLoading(true); setData(null); setError(null); setSampleID(null) }
  function select(next: Tab) { if (next === tab) return; reset(); setTab(next); setCursors(['']); setFindingCursors(['']) }
  const denied = useCallback((failure: unknown) => { setData(null); setSampleID(null); setPermissions(null); setError(failure) }, [])
  return <section className="panel" aria-labelledby="result-title">
    <div className="section-heading"><h2 id="result-title">Run {runID} · 分析修订 1</h2><a href="#/runs">← 检测历史</a></div>
    <p className="notice warning">开发结果 · 未校准 · 公开开发模板。无法据此判定模型真假，也不能证明上游内部意图。机器分析可读取不等于已获人工审核批准。</p>
    <p className="field-help">固定来源：此 Run 的不可覆盖修订 1。刷新仅重新读取同一修订，不触发上游调用、重新评分或报告生成。</p>
    <nav className="result-tabs" aria-label="分析结果视图">
      <button aria-current={tab === 'overview' ? 'page' : undefined} onClick={() => select('overview')}>结果总览</button>
      {permissions?.includes('evidence.read') && permissions.includes('run.read') && <><button aria-current={tab === 'token' ? 'page' : undefined} onClick={() => select('token')}>Token 分析</button><button aria-current={tab === 'behavior' ? 'page' : undefined} onClick={() => select('behavior')}>行为分析</button><button aria-current={tab === 'evidence' ? 'page' : undefined} onClick={() => select('evidence')}>S1 证据</button></>}
      {permissions?.includes('run.read') && <button aria-current={tab === 'review' ? 'page' : undefined} onClick={() => select('review')}>人工复核</button>}
      {permissions?.includes('run.read') && permissions.includes('evidence.read') && permissions.includes('report.export') && <button aria-current={tab === 'reports' ? 'page' : undefined} onClick={() => select('reports')}>报告</button>}
      <button disabled={loading} onClick={() => { reset(); setReload((n) => n + 1) }}>重新读取结果与权限</button>
    </nav>
    {loading && <Loading>正在读取固定修订与当前权限…</Loading>}<ErrorNotice error={error} />
    {error instanceof ApiError && error.status === 404 && <p className="empty-note">该组织下尚无可读取的修订 1：任务可能仍在分析、结果未发布或资源不存在。不会将其显示为 0 分。</p>}
    {error instanceof ApiError && error.status === 403 && <p className="notice warning">当前权限不足或已撤销，已清除结果与证据缓存。可返回总览重新核验只读权限。</p>}
    {error instanceof ApiError && ['MI_ANALYSIS_RESULT_INVALID', 'MI_INVALID_RESPONSE'].includes(error.code) && <p className="notice warning">结果结构、资源上限或固定修订一致性校验未通过，已停止展示；请联系管理员。</p>}
    {permissions?.includes('run.read') && !permissions.includes('evidence.read') && <p className="field-help">当前仅有任务读取权限。Token、行为统计和 S1 样本需要额外 evidence.read 权限。</p>}
    {data && <>{tab === 'overview' ? <OverviewResult result={data.result} /> : tab === 'token' && data.result.token_analysis ? <TokenResult data={data.result.token_analysis} samples={data.samples?.items ?? []} /> : tab === 'behavior' && data.result.behavior_analysis ? <BehaviorResult data={data.result.behavior_analysis} /> : tab === 'evidence' && data.findings ? <><Findings items={data.findings.items} /><PageButtons label="发现" cursors={findingCursors} next={data.findings.next_cursor} onChange={(next) => { reset(); setFindingCursors(next) }} /></> : null}
      {data.samples && <><Samples items={data.samples.items} onSelect={setSampleID} /><PageButtons label="样本" cursors={cursors} next={data.samples.next_cursor} onChange={(next) => { reset(); setCursors(next) }} /></>}
      {sampleID && <SampleInspect key={`${context.organizationID}-${runID}-${sampleID}`} {...context} runID={runID} sampleID={sampleID} onClose={() => setSampleID(null)} onDenied={denied} />}
      {tab === 'review' && <ReviewPanel {...context} runID={runID} analysisRevision={data.result.analysis_revision} onDenied={denied} />}
      {tab === 'reports' && <ReportsPanel {...context} runID={runID} analysisRevision={data.result.analysis_revision} onDenied={denied} />}
    </>}
    <p className="field-help">原始请求、响应、随机变量和凭证不在本页读取范围。有完整导出权限时，可在报告页显式生成脱敏 JSON/HTML 文件；原文导出、修订比较和重新分析尚未接入本页。</p>
  </section>
}
function PageButtons({ label, cursors, next, onChange }: { label: string; cursors: string[]; next: string | null; onChange: (value: string[]) => void }) {
  return <div className="pagination"><button disabled={cursors.length === 1} onClick={() => onChange(cursors.slice(0, -1))}>{label}上一页</button><span>{label}第 {cursors.length} 页</span><button disabled={!next || cursors.length >= 1000 || cursors.includes(next)} onClick={() => { if (next) onChange([...cursors, next]) }}>{label}下一页</button></div>
}
function SampleInspect({ runID, sampleID, onClose, onDenied, ...context }: ReadContext & { runID: string; sampleID: string; onClose: () => void; onDenied: (failure: unknown) => void }) {
  const onFailure = useFailure(context)
  const [data, setData] = useState<SampleDetail | null>(null), [error, setError] = useState<unknown>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  useEffect(() => {
    const controller = new AbortController()
    void resultsApi.sample(context.organizationID, runID, sampleID, controller.signal).then((result) => { if (!controller.signal.aborted) setData(result) }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof ApiError && failure.status === 403) onDenied(failure)
      else if (!onFailure(failure)) setError(failure)
    })
    return () => controller.abort()
  }, [context.organizationID, runID, sampleID, onFailure, onDenied])
  return <section className="result-card" aria-labelledby="sample-detail-title"><div className="section-heading"><h4 ref={heading} tabIndex={-1} id="sample-detail-title">样本 {sampleID} · 尝试记录</h4><button onClick={onClose}>关闭样本详情</button></div><ErrorNotice error={error} id="sample-read-error" />{!data && !error && <Loading>正在读取已脱敏的 S1 尝试元数据…</Loading>}{data && <><p>最终 Attempt：{data.sample.final_attempt_id ?? '尚无'} · 正文状态：已隐藏</p><p className="result-hash">响应摘要：{data.sample.response_hash ?? '未提供'}</p><div className="table-scroll"><table><caption className="sr-only">样本各次尝试，不包含原文</caption><thead><tr><th>Attempt</th><th>有效性 / HTTP</th><th>已记录 Token</th><th>耗时与时间</th></tr></thead><tbody>{data.attempts.map((a) => <tr key={a.id}><th scope="row">{a.id}<span className="cell-detail">第 {a.attempt_no} 次{a.id === data.sample.final_attempt_id ? ' · 最终选择' : ' · 不作为独立样本'}</span></th><td>{a.validity} · {a.http_status ?? '未测'}<span className="cell-detail">{a.error_code ?? '无错误分类'}</span></td><td>输入 {measured(a.prompt_tokens, 0)} / 输出 {measured(a.completion_tokens, 0)} / 总计 {measured(a.total_tokens, 0)}</td><td>{measured(a.duration_ms, 0)} ms<span className="cell-detail">{a.started_at ? new Date(a.started_at).toLocaleString() : '未开始'} → {a.finished_at ? new Date(a.finished_at).toLocaleString() : '未结束'}</span></td></tr>)}</tbody></table></div><Limitations codes={data.sample.limitations} /></>}</section>
}
