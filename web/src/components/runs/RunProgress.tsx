import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { runMessages, runsApi, type Run, type RunStatus } from '../../runs-api'
import { Loading } from '../Feedback'
import { useFailure } from '../management/shared'
import type { TargetCallbacks } from '../targets/TargetForm'
import { RunError } from './RunFeedback'
import { cost, FrozenVersions } from './RunQuote'
import { watchRun, type RunConnection } from '../../run-events'

export const statusLabels: Record<RunStatus, string> = { DRAFT: '草稿', PRECHECKING: '预检阶段', QUEUED: '已排队', RUNNING: '采样执行中', ANALYZING: '分析中', COMPLETED: '已完成', PARTIAL: '部分完成', FAILED: '失败', REVIEW_REQUIRED: '需要人工复核', CANCELLING: '正在取消', CANCELLED: '已取消' }
const terminal = (record: Run) => ['COMPLETED', 'PARTIAL', 'FAILED', 'REVIEW_REQUIRED', 'CANCELLED'].includes(record.status)
function canCancel(record: Run, userID: string, permissions: string[]) {
  return (record.status === 'QUEUED' || record.status === 'RUNNING') && record.execution_closed_at === null &&
    (permissions.includes('run.cancel-any') || (record.created_by === userID && permissions.includes('run.cancel-own')))
}
function validatePinned(initial: Run, current: Run, result: Run) {
  if (result.id !== initial.id || result.target_id !== initial.target_id || result.manifest_hash !== initial.manifest_hash || result.created_by !== initial.created_by || result.package !== initial.package || result.planned_samples !== initial.planned_samples ||
    (Object.keys(initial.versions) as (keyof Run['versions'])[]).some((key) => result.versions[key] !== initial.versions[key]) || result.version < current.version || result.completed_samples < current.completed_samples) throw new ApiError('MI_INVALID_RESPONSE')
}
export function RunProgress({ initial, userID, initialPermissions, ...context }: TargetCallbacks & { initial: Run; userID: string; initialPermissions: string[] }) {
  const onFailure = useFailure(context)
  const [record, setRecord] = useState(initial)
  const [permissions, setPermissions] = useState<string[] | null>(initialPermissions)
  const [error, setError] = useState<unknown>(null)
  const [polling, setPolling] = useState(!terminal(initial))
  const [paused, setPaused] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [busy, setBusy] = useState(false)
  const [cancelUncertain, setCancelUncertain] = useState(false)
  const [connection, setConnection] = useState<RunConnection>('checking')
  const current = useRef(initial)
  const active = useRef(false)
  const mutation = useRef<AbortController | null>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); return () => mutation.current?.abort() }, [])
  useEffect(() => {
    if (!polling || busy || !permissions?.includes('run.read')) return
    const controller = new AbortController()
    void watchRun({ organizationID: context.organizationID, initial: current.current, signal: controller.signal, onConnection: (next) => { if (!controller.signal.aborted) setConnection(next) }, onSnapshot: (result) => {
      if (controller.signal.aborted) return
      validatePinned(initial, current.current, result)
      // A terminal event is a notification, not the final authoritative GET.
      // Keep the last nonterminal view until watchRun confirms it successfully.
      if (terminal(result)) return
      current.current = result; setRecord(result); setCancelUncertain(false)
    } }).then((result) => { if (!controller.signal.aborted) {
      if (result.reason === 'terminal') { validatePinned(initial, current.current, result.record); current.current = result.record; setRecord(result.record); setCancelUncertain(false) }
      setPolling(false); setPaused(result.reason === 'limit')
    } }).catch((failure: unknown) => {
      if (!controller.signal.aborted && !onFailure(failure)) { setError(failure); setPolling(false); if (failure instanceof ApiError && failure.status === 403) setPermissions(null) }
    })
    return () => controller.abort()
  }, [context.organizationID, initial, onFailure, polling, busy, attempt, permissions])

  async function cancel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (active.current || cancelUncertain || !permissions || !canCancel(current.current, userID, permissions)) return
    if (new FormData(event.currentTarget).get('confirm_cancel') !== 'on') { setError('请先确认停止继续采样；已发生的调用、费用和样本不会被抹除。'); return }
    const controller = new AbortController(); mutation.current = controller; active.current = true; setBusy(true); setPolling(false); setError(null)
    let dispatched = false
    try {
      const granted = await runsApi.permissions(context.organizationID, userID, controller.signal)
      if (controller.signal.aborted) return
      setPermissions(granted.permissions)
      if (!canCancel(current.current, userID, granted.permissions)) throw new ApiError('MI_PERMISSION_DENIED', 403)
      dispatched = true
      const result = await runsApi.cancel(context.organizationID, context.csrfToken, current.current, controller.signal)
      if (controller.signal.aborted) return
      validatePinned(initial, current.current, result); current.current = result; setRecord(result); setCancelUncertain(false); setPolling(!terminal(result))
    } catch (failure) {
      if (!controller.signal.aborted && !onFailure(failure)) {
        setError(failure)
        if (!dispatched || (failure instanceof ApiError && failure.status === 403)) setPermissions(null)
        const unknown = dispatched && (!(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500)
        if (unknown) { setCancelUncertain(true); setPolling(true) }
      }
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  async function refreshPermissions() {
    if (active.current) return
    const controller = new AbortController(); mutation.current = controller; active.current = true; setBusy(true); setError(null)
    try { const result = await runsApi.permissions(context.organizationID, userID, controller.signal); if (!controller.signal.aborted) setPermissions(result.permissions) }
    catch (failure) { if (!controller.signal.aborted && !onFailure(failure)) { setError(failure); setPermissions(null) } }
    finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  if (!permissions?.includes('run.read')) return <section aria-label="检测读取权限不可用"><RunError error={error} id="run-progress-error" /><p className="notice warning">当前任务读取权限不足或已撤销，已停止显示检测状态。后台任务不会因此自动取消。</p><button disabled={busy} onClick={() => void refreshPermissions()}>重新读取取消权限</button><a href="#/runs">返回检测历史</a></section>
  return <section aria-labelledby="run-progress-title">
    <h3 id="run-progress-title" ref={heading} tabIndex={-1} aria-live="polite" aria-atomic="true">本次检测：{statusLabels[record.status]}</h3>
    <p className="cell-detail">Run ID {record.id} · 记录版本 {record.version} · 创建人 ID {record.created_by}</p>
    <div className="run-progress"><label htmlFor="run-progress-meter">已结束样本 {record.completed_samples} / {record.planned_samples}</label><progress id="run-progress-meter" max={record.planned_samples} value={record.completed_samples} /></div>
    <dl className="run-metrics"><div><dt>实际请求计数</dt><dd>{record.request_count.toLocaleString()}</dd></div><div><dt>已记录 Token</dt><dd>{record.token_count.toLocaleString()}</dd></div><div><dt>有效样本</dt><dd>{record.valid_sample_count} / {record.planned_samples}</dd></div><div><dt>累计估算费用</dt><dd>{cost(record.estimated_cost_micros)}</dd></div></dl>
    <p className="field-help">请求计数包含重试，不等于独立样本量；有效样本数不代表通过真实性检查。已记录费用不等于上游最终账单。</p>
    {record.status === 'ANALYZING' && <p className="notice warning">采样已进入分析阶段，分析尚未完成，不能据此查看最终结论或报告。</p>}
    {record.status === 'CANCELLING' && <p className="notice warning">服务端正在停止后续采样；在途请求仍可能完成并计费。当前不是“已取消”状态。</p>}
    {record.execution_closed_at && <p className="field-help">执行阶段已经关闭，不再允许本页发起取消操作。已发生的请求和样本仍然保留。</p>}
    {record.error_summary.length > 0 && <ul className="run-warnings">{record.error_summary.map((item, index) => <li key={`${item.code}-${index}`}>{runMessages[item.code] ?? '服务端记录了一类执行问题，请联系管理员查看授权范围内的诊断信息。'}（{item.count} 次）</li>)}</ul>}
    <dl className="precheck-times"><dt>创建时间</dt><dd>{new Date(record.created_at).toLocaleString()}</dd><dt>开始时间</dt><dd>{record.started_at ? new Date(record.started_at).toLocaleString() : '尚未开始'}</dd><dt>完成时间</dt><dd>{record.finished_at ? new Date(record.finished_at).toLocaleString() : '尚未完成'}</dd></dl>
    <FrozenVersions versions={record.versions} hash={record.manifest_hash} />
    <RunError error={error} id="run-progress-error" />
    {polling && !busy && <Loading>{`${connection === 'live' ? '已连接状态事件流' : connection === 'reconnecting' ? '状态事件流断开，正在只读核对并有限重连' : connection === 'connecting' ? '正在连接状态事件流' : '正在核对此固定 Run ID'}；不会重新创建或执行检测…`}</Loading>}
    {paused && <p className="empty-note">已达到本页自动读取上限，暂停更新；不代表后台检测失败。可手动继续读取。</p>}
    {Boolean(error) && <p className="empty-note">当前保留最后一次成功读取的状态，不会把读取错误当成检测失败或成功。</p>}
    {cancelUncertain && <p className="notice warning">取消请求结果不确定，正在只读核对同一 Run；不会自动重发取消请求。</p>}
    <div className="form-actions"><button disabled={polling || busy} onClick={() => { setError(null); setPaused(false); setPolling(true); setAttempt((value) => value + 1) }}>重新读取此检测</button><button disabled={busy} onClick={() => void refreshPermissions()}>重新读取取消权限</button></div>
    {permissions && canCancel(record, userID, permissions) ? <form aria-label="取消检测" onSubmit={cancel}><fieldset disabled={busy || cancelUncertain}><legend className="sr-only">停止采样确认</legend><label className="grant-option"><input type="checkbox" name="confirm_cancel" /><span>我确认停止后续采样；已有样本和可能产生的费用仍会保留。</span></label><button className="danger-button" type="submit" disabled={busy || cancelUncertain}>{busy ? '正在提交取消…' : '确认取消检测'}</button></fieldset></form> : <p className="field-help">当前状态或有效权限不允许取消；取消自己的任务与取消他人任务分别由服务端授权。</p>}
    <div className="form-actions">{permissions?.includes('run.read') && terminal(record) ? <a className="button-link" href={`#/results/${record.id}/1`}>读取已有分析修订 1</a> : <span className="field-help">结果入口将在任务终态与读取权限可用后显示；有无结果以服务端为准。</span>}<a href="#/runs">检测历史</a><button disabled>检测报告（尚未接入）</button></div>
  </section>
}
