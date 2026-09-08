import { useEffect, useId, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { responseRetentionApi, type ResponseRetentionSummary } from '../../response-retention-api'
import { runsApi } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'

type Context = ReadContext & { runID: string; analysisRevision: number; onDenied: (failure: unknown) => void }

export function ResponseRetentionPanel(props: Context) {
  return <ResponseRetentionScope key={`${props.organizationID}:${props.userID}:${props.runID}:${props.analysisRevision}`} {...props} />
}

function ResponseRetentionScope({ onDenied, ...context }: Context) {
  const onFailure = useFailure(context)
  const [data, setData] = useState<ResponseRetentionSummary | null>(null), [error, setError] = useState<unknown>(null)
  const [opened, setOpened] = useState(false), [busy, setBusy] = useState(false), [denied, setDenied] = useState(false)
  const operation = useRef<AbortController | null>(null), active = useRef(false), heading = useRef<HTMLHeadingElement>(null)
  const titleID = useId(), errorID = useId()
  useEffect(() => () => { operation.current?.abort(); active.current = false }, [])
  useEffect(() => { if (data) heading.current?.focus() }, [data])
  function clear() {
    operation.current?.abort(); operation.current = null; active.current = false
    setData(null); setError(null); setOpened(false); setBusy(false)
  }
  async function read() {
    if (active.current || denied) return
    const controller = new AbortController()
    operation.current = controller; active.current = true
    setData(null); setError(null); setOpened(true); setBusy(true)
    try {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      if (!['run.read', 'evidence.read'].every((permission) => granted.permissions.includes(permission))) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const value = await responseRetentionApi.get(context.organizationID, context.runID, context.analysisRevision, controller.signal)
      if (!controller.signal.aborted && operation.current === controller) setData(value)
    } catch (failure) {
      if (controller.signal.aborted || operation.current !== controller) return
      setData(null); setError(failure)
      if (onFailure(failure) || failure instanceof ApiError && (failure.status === 401 || failure.status === 403)) {
        controller.abort(); setDenied(true); setBusy(false); onDenied(failure)
      }
    } finally {
      if (operation.current === controller) { active.current = false; if (!controller.signal.aborted) setBusy(false) }
    }
  }
  return <section className="result-card" aria-labelledby={titleID}>
    <div className="section-heading"><h4 id={titleID} ref={heading} tabIndex={-1}>当前响应正文保留状态</h4>{opened && <button onClick={clear}>{busy ? '取消并清除保留状态读取' : '清除保留状态'}</button>}</div>
    <p className="field-help">动态观察，不改变旧报告文件/哈希。这里只读取 S1 保留与删除摘要，不读取正文，不触发清理，不自动轮询。</p>
    {!denied && <button disabled={busy} onClick={() => { void read() }}>{opened ? '刷新当前正文保留状态' : '读取当前正文保留状态'}</button>}
    {busy && <Loading>正在核验只读权限并读取当前保留状态…</Loading>}
    <ErrorNotice error={error} id={errorID} />
    {denied ? <p className="notice warning">当前会话或读取权限已失效，已清除保留状态并停止读取。</p> : !busy && !data && <p className="empty-note">{error ? '当前保留状态未知；读取失败不代表计数为 0，也不代表清理成功。' : '尚未读取当前保留状态；没有数据不等于正文未删除。'}</p>}
    {data && <>
      <p>Run {data.run_id} · 分析修订 {data.analysis_revision} · 政策版本 {data.policy_version}</p>
      <p>观察时间：<time dateTime={data.observed_at}>{data.observed_at}</time>；这是本次成功读取的快照，后续变化需手动刷新。</p>
      <dl className="run-metrics">
        <div><dt>当前响应保留策略</dt><dd>{data.policy_days} 天</dd></div>
        <div><dt>本 Run Attempt 总数</dt><dd>{data.attempt_count}</dd></div>
        <div><dt>原始分析副本已删除</dt><dd>{data.raw_deleted_count}</dd></div>
        <div><dt>展示副本已删除</dt><dd>{data.display_deleted_count}</dd></div>
        <div><dt>展示副本已过期或不再允许保留</dt><dd>{data.display_expired_count}</dd></div>
        <div><dt>展示副本仍在保留窗口</dt><dd>{data.display_retained_count}</dd></div>
      </dl>
      <p>最近删除时间：{data.last_deleted_at === null ? '未记录删除时间' : <time dateTime={data.last_deleted_at}>{data.last_deleted_at}</time>}</p>
      <p className="field-help">展示副本的已删除、已过期和仍保留计数互斥；未捕获或未留存的 Attempt 不一定进入这三类。原始分析副本是独立维度，不与展示副本计数相加。仍在保留窗口也不代表已获得正文读取权限。</p>
      {data.policy_days === 0 && <p className="notice warning">当前已关闭响应正文留存；不能据此推断物理删除已全部完成，删除状态以服务端验证的记录为准。</p>}
    </>}
  </section>
}
