import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { reviewsApi, reviewConclusions, reviewExplanation, reviewLabels, type Review, type ReviewConclusion, type ReviewInput } from '../../reviews-api'
import type { ReadPage } from '../../runs-history-api'
import { runsApi } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'

type Context = ReadContext & { runID: string; analysisRevision: number; onDenied: (failure: unknown) => void }
type Submission = { body: Readonly<ReviewInput>; key: string }
const unknownOutcome = (failure: unknown) => !(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500

export function ReviewPanel(props: Context) { return <ReviewScope key={`${props.organizationID}:${props.userID}:${props.runID}:${props.analysisRevision}`} {...props} /> }
function ReviewScope({ runID, analysisRevision, onDenied, ...context }: Context) {
  const onFailure = useFailure(context)
  const [permissions, setPermissions] = useState<string[] | null>(null)
  const [page, setPage] = useState<ReadPage<Review> | null>(null)
  const [latest, setLatest] = useState<string | null | undefined>(undefined)
  const [cursors, setCursors] = useState([''])
  const [reload, setReload] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [conclusion, setConclusion] = useState<ReviewConclusion>('watch')
  const [explanation, setExplanation] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [pending, setPending] = useState<Submission | null>(null)
  const [receipt, setReceipt] = useState<Review | null>(null)
  const active = useRef(false)
  const operation = useRef<AbortController | null>(null)
  const cursor = cursors[cursors.length - 1]

  function clearProtected() { setPermissions(null); setPage(null); setLatest(undefined); setExplanation(''); setConfirmed(false); setPending(null); setReceipt(null) }
  function fail(failure: unknown) {
    if (onFailure(failure) || (failure instanceof ApiError && failure.status === 403)) { clearProtected(); onDenied(failure) }
    setError(failure)
  }
  // The scope key unmounts all notes and retry identities on user/org/Run/revision
  // changes. Aborting a fetch never claims to undo a server-accepted review.
  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => {
    const controller = new AbortController()
    void (async () => {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      setPermissions(granted.permissions)
      if (!granted.permissions.includes('review.write')) { setExplanation(''); setConfirmed(false); setPending(null) }
      if (!granted.permissions.includes('run.read')) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const result = await reviewsApi.list(context.organizationID, runID, analysisRevision, cursor, controller.signal)
      if (controller.signal.aborted) return
      setPage(result); setLatest(cursor === '' ? result.items[0]?.id ?? null : undefined)
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setPage(null); setLatest(undefined)
      if (onFailure(failure) || (failure instanceof ApiError && failure.status === 403)) {
        setPermissions(null); setExplanation(''); setConfirmed(false); setPending(null); setReceipt(null); onDenied(failure)
      }
      setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, runID, analysisRevision, cursor, reload, onFailure, onDenied])

  function read(next: string[]) { setPage(null); setLatest(undefined); setError(null); setLoading(true); setConfirmed(false); setCursors(next); setReload((value) => value + 1) }
  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault()
    if (active.current || loading || !permissions?.includes('run.read') || !permissions.includes('review.write')) return
    if (!confirmed) { setError('请明确确认：这是人工业务判断，不修改机器分析，也不代表正式批准。'); return }
    if (!pending && (latest === undefined || !reviewExplanation(explanation))) { setError('请先读取最新复核；说明必填，UTF-8 不超过 4096 字节，不含不可见控制字符（允许换行和制表符）。'); return }
    const controller = new AbortController()
    operation.current = controller; active.current = true; setBusy(true); setError(null)
    let dispatched = false
    // Capture before asynchronous permission reads; never rebuild an uncertain
    // request from edited form values or a newer history item.
    const body: ReviewInput = pending?.body ?? { analysis_revision: analysisRevision, conclusion, explanation, ...(latest ? { previous_review_id: latest } : {}) }
    try {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      setPermissions(granted.permissions)
      if (!granted.permissions.includes('run.read') || !granted.permissions.includes('review.write')) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const frozen = pending ?? { body: Object.freeze(body), key: crypto.randomUUID() }
      setPending(frozen); dispatched = true
      const result = await reviewsApi.append(context.organizationID, runID, context.csrfToken, context.userID, frozen.body, frozen.key, controller.signal)
      if (controller.signal.aborted) return
      setPending(null); setExplanation(''); setConfirmed(false); setReceipt(result)
      // A recovered receipt may precede somebody else's newer review. It is a
      // submission receipt, never the next previous_review_id or a latest claim.
      read([''])
    } catch (failure) {
      if (controller.signal.aborted) return
      setConfirmed(false)
      // A failed permission GET during manual recovery says nothing about the
      // previous POST. Keep its identity on transient failures; only a definite
      // rejection or the authorization gate can clear it.
      if (!(pending || dispatched) || !unknownOutcome(failure)) { setPending(null); setLatest(undefined) }
      fail(failure)
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  const canWrite = permissions?.includes('run.read') && permissions.includes('review.write')
  return <section className="review-panel" aria-labelledby="review-title">
    <h3 id="review-title">人工复核 · 分析修订 {analysisRevision}</h3>
    <p className="notice warning">人工复核是业务判断，不修改原始机器分数；不代表软件正式审核批准，也不能证明供应商内部配置或模型真假。新记录只追加，旧记录不可编辑或删除。</p>
    <p className="field-help">说明仅填复核理由，不得填入 API Key、鉴权 Header、请求/响应原文或真实业务正文。记录按当前 Run 与固定分析修订隔离，按时间由近到远；时间使用浏览器本地时区。</p>
    <ErrorNotice error={error} id="review-error" />
    {error instanceof ApiError && error.code === 'MI_REVIEW_CONFLICT' && <p className="notice warning">最新复核已变化或提交标识发生冲突。本次未确认追加成功；请重新读取最新复核，核对后再显式提交，不会自动覆盖或重试。</p>}
    {error instanceof ApiError && error.status === 404 && <p className="empty-note">当前组织下没有可复核的已发布修订，不能追加复核。</p>}
    {loading && <Loading>正在读取最新权限与复核历史…</Loading>}
    {receipt && <output className="notice success">本次提交收据：复核 {receipt.id} · {reviewLabels[receipt.conclusion]}。记录已确认保存；该收据不一定是当前最新复核。</output>}
    {page && <>{page.items.length ? <ol className="review-history" aria-label="不可覆盖的人工复核历史">{page.items.map((item) => <li key={item.id} className="result-card"><h4>{reviewLabels[item.conclusion]} · 复核 {item.id}</h4><p className="field-help">复核人 ID {item.created_by} · <time dateTime={item.created_at}>{new Date(item.created_at).toLocaleString()}</time> · 修订 {item.analysis_revision}</p><p className="review-explanation">{item.explanation}</p></li>)}</ol> : <p className="empty-note">尚无人工复核记录，不代表机器结论已经获批。</p>}</>}
    <div className="pagination"><button disabled={loading || busy || Boolean(pending) || cursors.length === 1} onClick={() => read(cursors.slice(0, -1))}>复核上一页</button><span>复核第 {cursors.length} 页</span><button disabled={loading || busy || Boolean(pending) || !page?.next_cursor || cursors.length >= 1000 || (page?.next_cursor ? cursors.includes(page.next_cursor) : false)} onClick={() => { if (page?.next_cursor) read([...cursors, page.next_cursor]) }}>复核下一页</button><button disabled={loading || busy || Boolean(pending)} onClick={() => read([''])}>重新读取最新复核</button></div>
    {!loading && permissions?.includes('run.read') && !canWrite && <p className="field-help">当前只有复核读取能力；追加记录还需要 review.write 权限。</p>}
    {pending ? <section className="result-card"><h4>提交结果尚未确认</h4><p className="notice warning">服务端可能已经保存本次复核。本页保留原提交内容和同一提交标识；不能编辑或创建新提交，只能手动恢复同一次提交。恢复成功也可能返回较早的原收据。</p><label className="grant-option"><input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认只恢复原提交，不创建另一条复核。</span></label><button disabled={busy || !canWrite} onClick={() => void submit()}>{busy ? '正在核对原提交…' : '手动恢复同一次复核'}</button></section> : canWrite && latest !== undefined && !loading && <form aria-label="追加人工复核" onSubmit={(event) => void submit(event)} noValidate><fieldset disabled={busy}><legend>追加新复核（不覆盖历史）</legend><p className="field-help">基于最新已读复核：{latest ?? '当前无复核，首次追加'}。若其他人已更新，服务端将拒绝过时提交。</p><label htmlFor="review-conclusion">人工结论</label><select id="review-conclusion" value={conclusion} onChange={(event) => setConclusion(event.target.value as ReviewConclusion)}>{reviewConclusions.map((item) => <option key={item} value={item}>{reviewLabels[item]}</option>)}</select><label htmlFor="review-explanation">复核说明</label><textarea id="review-explanation" value={explanation} onChange={(event) => setExplanation(event.target.value)} maxLength={4096} rows={5} aria-describedby="review-note-limit" /><p id="review-note-limit" className="field-help">{new TextEncoder().encode(explanation).length} / 4096 UTF-8 字节；仅当前页面内存保存，不写入浏览器持久存储。</p><label className="grant-option"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认追加人工业务判断，不修改机器分数，不代表正式批准。</span></label><button type="submit">{busy ? '正在追加复核…' : '确认追加复核'}</button></fieldset></form>}
    <p className="field-help">离开此页、切换组织/账号/Run/修订会清除未提交说明和未确认提交标识，只取消本页请求处理，不会撤销已保存记录。提交结果不确定时请先恢复；重新进入后不要未经核对重复提交。</p>
  </section>
}
