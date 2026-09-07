import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { downloadReport } from '../../report-download'
import { reportsApi, reportFormats, reportStatusLabels, reportUpdate, type Report, type ReportFormat, type ReportInput } from '../../reports-api'
import { runsApi } from '../../runs-api'
import type { ReadPage } from '../../runs-history-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'

type Context = ReadContext & { runID: string; analysisRevision: number; onDenied: (failure: unknown) => void }
type Submission = { body: Readonly<ReportInput>; key: string }
const required = ['run.read', 'evidence.read', 'report.export']
const canExport = (permissions: string[] | null) => permissions !== null && required.every((permission) => permissions.includes(permission))
const activeStatus = (value: Report) => value.status === 'queued' || value.status === 'generating'
const unknownOutcome = (failure: unknown) => !(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500
function problem(failure: unknown) {
  const messages: Record<string, string> = { MI_REPORT_CONFLICT: '提交标识与既有报告不一致，未创建新报告；请联系管理员。', MI_REPORT_LIMIT: '报告生成或下载数量已达上限，请稍后再试。', MI_REPORT_NOT_READY: '该报告尚不可下载，请读取同一报告的状态。', MI_REPORT_FILE_UNAVAILABLE: '报告文件缺失、损坏或不可安全读取；原分析结果仍保留。', MI_EXECUTION_NOT_READY: '报告 Worker 尚未就绪，未创建报告。', MI_REPORT_INVALID: '报告固定修订或输入校验失败，请联系管理员。' }
  return failure instanceof ApiError ? messages[failure.code] ?? failure : failure
}
export function ReportsPanel(props: Context) { return <ReportsScope key={`${props.organizationID}:${props.userID}:${props.runID}:${props.analysisRevision}`} {...props} /> }
function ReportsScope({ runID, analysisRevision, onDenied, ...context }: Context) {
  const onFailure = useFailure(context)
  const [permissions, setPermissions] = useState<string[] | null>(null)
  const [page, setPage] = useState<ReadPage<Report> | null>(null)
  const [cursors, setCursors] = useState(['']), [reload, setReload] = useState(0)
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [downloading, setDownloading] = useState(false)
  const [error, setError] = useState<unknown>(null), [notice, setNotice] = useState('')
  const [format, setFormat] = useState<ReportFormat>('json'), [confirmed, setConfirmed] = useState(false)
  const [pending, setPending] = useState<Submission | null>(null)
  const [selected, setSelected] = useState<Report | null>(null), [polling, setPolling] = useState(false), [pollEpoch, setPollEpoch] = useState(0)
  const selection = useRef<Report | null>(null), active = useRef(false)
  const operation = useRef<AbortController | null>(null), pollingRequest = useRef<AbortController | null>(null)
  const heading = useRef<HTMLHeadingElement>(null), objectURLs = useRef(new Map<string, ReturnType<typeof setTimeout>>())
  const cursor = cursors[cursors.length - 1]
  const fail = useCallback((failure: unknown) => {
    if (onFailure(failure) || (failure instanceof ApiError && (failure.status === 401 || failure.status === 403))) {
      operation.current?.abort(); pollingRequest.current?.abort()
      setPermissions(null); setPage(null); setPending(null); setSelected(null); selection.current = null
      setConfirmed(false); setNotice(''); setPolling(false); setBusy(false); setDownloading(false)
      for (const [url, timer] of objectURLs.current) { clearTimeout(timer); URL.revokeObjectURL(url) }
      objectURLs.current.clear(); onDenied(failure)
    }
    setError(failure)
  }, [onFailure, onDenied])
  const refreshPermissions = useCallback(async (signal: AbortSignal) => {
    const granted = await runsApi.permissions(context.organizationID, context.userID, signal)
    if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
    setPermissions(granted.permissions)
    if (!canExport(granted.permissions)) throw new ApiError('MI_PERMISSION_DENIED', 403)
  }, [context.organizationID, context.userID])
  useEffect(() => {
    const urls = objectURLs.current
    return () => {
      operation.current?.abort(); pollingRequest.current?.abort()
      for (const [url, timer] of urls) { clearTimeout(timer); URL.revokeObjectURL(url) }
      urls.clear()
    }
  }, [])
  const selectedID = selected?.id
  useEffect(() => { if (selectedID) heading.current?.focus() }, [selectedID])
  useEffect(() => {
    const controller = new AbortController()
    void (async () => {
      await refreshPermissions(controller.signal)
      const result = await reportsApi.list(context.organizationID, runID, analysisRevision, cursor, controller.signal)
      if (!controller.signal.aborted) setPage(result)
    })().catch((failure: unknown) => { if (!controller.signal.aborted) { setPage(null); fail(failure) } }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, runID, analysisRevision, cursor, reload, refreshPermissions, fail])
  useEffect(() => {
    const initial = selection.current
    if (!polling || !initial || !selectedID) return
    const controller = new AbortController()
    pollingRequest.current = controller
    let timer: ReturnType<typeof setTimeout> | undefined, reads = 0, previous = initial
    const limit = setTimeout(() => { controller.abort(); setPolling(false); setNotice('本页自动读取已达 5 分钟上限，请手动读取同一报告。') }, 300000)
    const read = async () => {
      try {
        await refreshPermissions(controller.signal)
        const next = reportUpdate(previous, await reportsApi.get(context.organizationID, runID, analysisRevision, selectedID, controller.signal))
        if (controller.signal.aborted) return
        previous = next; selection.current = next; setSelected(next)
        setPage((current) => current && { ...current, items: current.items.map((item) => item.id === next.id ? next : item) })
        if (activeStatus(next) && ++reads < 150) timer = setTimeout(() => void read(), 2000)
        else { setPolling(false); if (activeStatus(next)) setNotice('本页自动读取已达到次数上限，请手动读取同一报告。') }
      } catch (failure) { if (!controller.signal.aborted) { setPolling(false); fail(failure) } }
    }
    void read()
    return () => { controller.abort(); clearTimeout(limit); if (timer) clearTimeout(timer) }
  }, [polling, selectedID, pollEpoch, context.organizationID, runID, analysisRevision, refreshPermissions, fail])
  function readPage(next: string[]) { setPage(null); setError(null); setLoading(true); setCursors(next); setReload((value) => value + 1) }
  function inspect(value: Report) {
    if (active.current || pending) return
    pollingRequest.current?.abort(); setError(null); setNotice('')
    selection.current = value; setSelected(value); setPolling(true); setPollEpoch((value) => value + 1)
  }
  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault()
    if (active.current || loading || !canExport(permissions)) return
    if (!confirmed) { setError('请确认只生成脱敏 S1 报告，且本报告不纳入人工复核快照。'); return }
    if (analysisRevision !== 1) { setError(new ApiError('MI_INVALID_REQUEST')); return }
    const controller = new AbortController()
    operation.current = controller; active.current = true; setBusy(true); setError(null); setNotice('')
    pollingRequest.current?.abort(); setPolling(false)
    const body: ReportInput = pending?.body ?? { format, analysis_revision: 1, include_restricted_content: false }
    let dispatched = false
    try {
      await refreshPermissions(controller.signal)
      const frozen = pending ?? { body: Object.freeze(body), key: crypto.randomUUID() }
      setPending(frozen); dispatched = true
      const result = await reportsApi.create(context.organizationID, runID, context.csrfToken, frozen.body, frozen.key, controller.signal)
      if (controller.signal.aborted) return
      setPending(null); setConfirmed(false); selection.current = result; setSelected(result)
      setPolling(activeStatus(result)); setPollEpoch((value) => value + 1)
      setNotice('报告请求已确认。生成状态以服务端为准，不代表新的模型检测或人工审核批准。')
      readPage([''])
    } catch (failure) {
      if (controller.signal.aborted) return
      setConfirmed(false)
      if (!(pending || dispatched) || !unknownOutcome(failure)) setPending(null)
      fail(failure)
    } finally { if (operation.current === controller) { active.current = false; if (!controller.signal.aborted) setBusy(false) } }
  }
  async function save(value: Report) {
    if (active.current || pending || !canExport(permissions)) return
    const controller = new AbortController()
    operation.current = controller; active.current = true; setBusy(true); setDownloading(true); setError(null); setNotice('')
    pollingRequest.current?.abort(); setPolling(false)
    try {
      await refreshPermissions(controller.signal)
      const current = reportUpdate(value, await reportsApi.get(context.organizationID, runID, analysisRevision, value.id, controller.signal))
      if (current.status !== 'ready') throw new ApiError('MI_REPORT_NOT_READY')
      const file = await downloadReport(context.organizationID, current, controller.signal)
      if (controller.signal.aborted) return
      const url = URL.createObjectURL(file.blob), anchor = document.createElement('a')
      try {
        anchor.href = url; anchor.download = file.filename; anchor.rel = 'noopener'; anchor.className = 'sr-only'
        document.body.append(anchor); anchor.click()
      } finally {
        anchor.remove()
        objectURLs.current.set(url, setTimeout(() => { URL.revokeObjectURL(url); objectURLs.current.delete(url) }, 1000))
      }
      selection.current = current; setSelected(current)
      setPage((page) => page && { ...page, items: page.items.map((item) => item.id === current.id ? current : item) })
      setNotice('文件长度与 SHA-256 校验通过，已请求浏览器保存；是否落盘取决于浏览器下载设置。')
      heading.current?.focus()
    } catch (failure) { if (!controller.signal.aborted) fail(failure) }
    finally { if (operation.current === controller) { active.current = false; if (!controller.signal.aborted) { setBusy(false); setDownloading(false) } } }
  }
  const enabled = canExport(permissions)
  return <section className="review-panel" aria-labelledby="reports-title">
    <h3 id="reports-title">脱敏报告 · 分析修订 {analysisRevision}</h3>
    <p className="notice warning">仅导出已发布的 S1 统计、样本引用与免责声明，不包含原始请求/响应、凭证或敏感端点。当前报告未纳入人工复核快照，不表示此 Run 从未被复核，也不代表软件获批或结果已校准。</p>
    <p className="field-help">JSON 与 HTML 都是下载文件；HTML 不在本页预览或执行。生成不触发模型调用，不重新分析。内容哈希用于规范化内容，文件哈希用于实际下载字节，两者不能混用。</p>
    <ErrorNotice error={problem(error)} id="report-error" />
    {notice && <output className="notice success">{notice}</output>}
    {downloading && <div className="form-actions"><Loading>正在校验并下载文件（最多 60 秒）…</Loading><button onClick={() => { operation.current?.abort(); operation.current = null; active.current = false; setBusy(false); setDownloading(false); setNotice('本次下载已取消，未请求浏览器保存文件。') }}>取消本次报告下载</button></div>}
    {loading && <Loading>正在读取报告列表与当前导出权限…</Loading>}
    {!loading && !enabled && <p className="empty-note">读取、生成和下载报告均需 run.read、evidence.read 与 report.export；当前没有可用的完整权限。</p>}
    {page && <p className="field-help">列表是最近读取的快照；仅显式选中的报告自动更新状态，其他报告可手动刷新。下载前始终重新读取权限和精确报告状态。</p>}
    {page && <>{page.items.length ? <ol className="review-history" aria-label="固定修订报告列表">{page.items.map((value) => <li key={value.id} className="result-card"><h4>{value.format.toUpperCase()} · 报告 {value.id} · 报告修订 {value.revision}</h4><p>{reportStatusLabels[value.status]} · <time dateTime={value.created_at}>{new Date(value.created_at).toLocaleString()}</time></p><div className="form-actions"><button disabled={busy || Boolean(pending)} onClick={() => inspect(value)}>读取报告 {value.id}</button><button disabled={busy || Boolean(pending) || value.status !== 'ready' || !enabled} onClick={() => void save(value)}>下载 {value.format.toUpperCase()} 报告 {value.id}</button></div></li>)}</ol> : <p className="empty-note">此分析修订尚无报告。需要显式选择格式并确认生成，不会自动导出。</p>}</>}
    <div className="pagination"><button disabled={loading || busy || Boolean(pending) || cursors.length === 1} onClick={() => readPage(cursors.slice(0, -1))}>报告上一页</button><span>报告第 {cursors.length} 页</span><button disabled={loading || busy || Boolean(pending) || !page?.next_cursor || cursors.length >= 1000 || (page?.next_cursor ? cursors.includes(page.next_cursor) : false)} onClick={() => { if (page?.next_cursor) readPage([...cursors, page.next_cursor]) }}>报告下一页</button><button disabled={loading || busy || Boolean(pending)} onClick={() => readPage([''])}>刷新报告列表与权限</button></div>
    {selected && <section className="result-card" aria-labelledby="report-selected-title">
      <h4 id="report-selected-title" ref={heading} tabIndex={-1}>报告 {selected.id} · {reportStatusLabels[selected.status]}</h4>
      <p>精确报告修订 {selected.revision} · {selected.format.toUpperCase()} · 本报告未纳入人工复核快照</p>
      {selected.content_hash && <p className="result-hash">规范化内容哈希：{selected.content_hash}</p>}
      {selected.file_hash && <p className="result-hash">文件字节哈希：{selected.file_hash}</p>}
      {selected.file_size !== undefined && <p>文件大小：{selected.file_size} 字节</p>}
      {selected.status === 'failed' && <p className="notice warning">生成失败，原分析结果仍保留；不会自动重新生成。</p>}
      {selected.status === 'expired' && <p className="empty-note">报告已过期，不可下载。</p>}
      <button disabled={busy || Boolean(pending)} onClick={() => inspect(selected)}>手动读取同一报告</button>
      {polling && <><output>正在每 2 秒读取此报告；最多 5 分钟，不混入其他报告。</output><button onClick={() => { pollingRequest.current?.abort(); setPolling(false) }}>停止自动读取报告</button></>}
      <button disabled={busy || Boolean(pending) || selected.status !== 'ready' || !enabled} onClick={() => void save(selected)}>下载当前 {selected.format.toUpperCase()} 报告</button>
    </section>}
    {pending ? <section className="result-card"><h4>报告创建结果尚未确认</h4><p className="notice warning">服务端可能已接受此请求。本页保留原格式、固定修订与同一提交标识，只能手动恢复同一次创建，不能自动新建或重新发送新标识。</p><label className="grant-option"><input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认仅恢复原报告请求，不新建另一份报告。</span></label><button disabled={busy || !enabled} onClick={() => void submit()}>{busy ? '正在确认原报告请求…' : '手动恢复同一次报告创建'}</button></section> : enabled && !loading && <form aria-label="生成脱敏报告" onSubmit={(event) => void submit(event)} noValidate><fieldset disabled={busy}><legend>生成新的不可覆盖报告</legend><label htmlFor="report-format">报告文件格式</label><select id="report-format" value={format} onChange={(event) => setFormat(event.target.value as ReportFormat)}>{reportFormats.map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}</select><label className="grant-option"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认仅生成脱敏 S1 报告，且本报告不纳入人工复核快照。</span></label><button type="submit">{busy ? '正在确认报告请求…' : '确认生成报告'}</button></fieldset></form>}
    <p className="field-help">离开、切换组织/账号/Run/分析修订会取消本页读取和下载、清空内存缓存与未确认标识，但不会撤销已被服务端接受的生成任务。创建结果不确定时请先恢复，避免重复创建。</p>
  </section>
}
