import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { runsApi, type EstimateInput, type Quote, type Run } from '../../runs-api'
import type { Target } from '../../targets-api'
import { Loading } from '../Feedback'
import { useFailure } from '../management/shared'
import type { TargetCallbacks } from '../targets/TargetForm'
import { canConfigure, RunConfiguration } from './RunConfiguration'
import { RunQuote } from './RunQuote'
import { RunProgress } from './RunProgress'
import { RunError } from './RunFeedback'
export function RunWorkflow({ current, userID, onCancel, ...context }: TargetCallbacks & { current: Target; userID: string; onCancel: () => void }) {
  const onFailure = useFailure(context)
  const [permissions, setPermissions] = useState<string[] | null>(null)
  const [permissionAttempt, setPermissionAttempt] = useState(0)
  const [permissionLoading, setPermissionLoading] = useState(true)
  const [permissionError, setPermissionError] = useState<unknown>(null)
  const [input, setInput] = useState<EstimateInput>()
  const [quote, setQuote] = useState<Quote | null>(null)
  const [record, setRecord] = useState<Run | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [uncertain, setUncertain] = useState(false)
  const [estimateUncertain, setEstimateUncertain] = useState(false)
  const active = useRef(false)
  const operation = useRef<AbortController | null>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const title = record ? '检测进度' : quote ? '确认检测预估' : '配置检测'
  useEffect(() => { const previous = document.title; return () => { document.title = previous; operation.current?.abort() } }, [])
  useEffect(() => { document.title = `${title} · Model Integrity Inspector`; heading.current?.focus(); heading.current?.scrollIntoView?.({ block: 'start' }) }, [title])
  useEffect(() => {
    const controller = new AbortController()
    void runsApi.permissions(context.organizationID, userID, controller.signal).then((result) => { if (!controller.signal.aborted) setPermissions(result.permissions) }).catch((failure: unknown) => {
      if (!controller.signal.aborted && !onFailure(failure)) { setPermissionError(failure); setPermissions(null) }
    }).finally(() => { if (!controller.signal.aborted) setPermissionLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, userID, onFailure, permissionAttempt])

  async function authorize(value: EstimateInput, signal: AbortSignal) {
    let result: Awaited<ReturnType<typeof runsApi.permissions>>
    try { result = await runsApi.permissions(context.organizationID, userID, signal) }
    catch (failure) { if (!signal.aborted) { setPermissions(null); setPermissionError(failure) }; throw failure }
    if (signal.aborted) return false
    setPermissions(result.permissions)
    if (!canConfigure(result.permissions, value.package, value.options)) throw new ApiError('MI_PERMISSION_DENIED', 403)
    return true
  }
  async function estimate(value: EstimateInput) {
    if (active.current || uncertain || !permissions) return
    const controller = new AbortController(); operation.current = controller; active.current = true; setBusy(true); setError(null); setEstimateUncertain(false); setInput(value)
    let dispatched = false
    try {
      if (!await authorize(value, controller.signal)) return
      dispatched = true
      const result = await runsApi.estimate(context.organizationID, context.csrfToken, value, controller.signal)
      if (!controller.signal.aborted) { setQuote(result); setUncertain(false) }
    } catch (failure) {
      if (!controller.signal.aborted && !onFailure(failure)) { setError(failure); if (dispatched && failure instanceof ApiError && failure.status === 403) setPermissions(null); if (dispatched && unknownOutcome(failure)) setEstimateUncertain(true) }
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  async function confirm(acknowledged: boolean) {
    if (active.current || !quote || !input || !permissions) return
    if (!acknowledged) { setError('请先勾选费用确认；预估本身不会启动检测。'); return }
    if (!uncertain && Date.now() >= Date.parse(quote.expires_at)) { setError(new ApiError('MI_RUN_ESTIMATE_EXPIRED', 409)); return }
    const controller = new AbortController(); operation.current = controller; active.current = true; setBusy(true); setError(null)
    let dispatched = false
    try {
      if (!await authorize(input, controller.signal)) return
      if (!uncertain && Date.now() >= Date.parse(quote.expires_at)) throw new ApiError('MI_RUN_ESTIMATE_EXPIRED', 409)
      dispatched = true
      const result = await runsApi.create(context.organizationID, context.csrfToken, quote, controller.signal)
      if (result.created_by !== userID) throw new ApiError('MI_INVALID_RESPONSE')
      if (!controller.signal.aborted) { setRecord(result); setUncertain(false) }
    } catch (failure) {
      if (!controller.signal.aborted && !onFailure(failure)) {
        setError(failure)
        if (dispatched && failure instanceof ApiError && failure.status === 403) setPermissions(null)
        if (dispatched && unknownOutcome(failure)) setUncertain(true)
        // The backend returns an existing Run even after expiry; explicit expiry
        // therefore establishes that this draft did not create a Run.
        if (failure instanceof ApiError && failure.code === 'MI_RUN_ESTIMATE_EXPIRED') setUncertain(false)
      }
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  function reloadPermissions() { setPermissions(null); setPermissionError(null); setPermissionLoading(true); setPermissionAttempt((value) => value + 1) }
  return <section className="panel target-editor" aria-labelledby="run-workflow-title">
    <h2 id="run-workflow-title" ref={heading} tabIndex={-1}>{title}：{current.name}</h2><p className="cell-detail">目标 ID {current.id} · 配置版本 {current.version} · {current.model}</p>
    {record ? <RunProgress initial={record} {...context} userID={userID} initialPermissions={permissions ?? []} /> : <>
      <RunError error={permissionError} id="run-permission-error" />
      {permissionLoading && <Loading>正在读取当前组织的有效执行权限…</Loading>}
      {!permissionLoading && !permissions && <p className="empty-note">无法确认当前有效权限，写操作已禁用。不会把角色目录或系统管理员标记当作组织授权。</p>}
      <RunError error={error} />
      {estimateUncertain && <p className="notice warning">预估响应不确定，服务端可能已保留一个短期草稿，但没有因此向上游发起检测。本页不会自动重新预估。</p>}
      {permissions && (quote ? <RunQuote quote={quote} busy={busy || permissionLoading} uncertain={uncertain} authorized={Boolean(input && canConfigure(permissions, input.package, input.options))} onConfirm={(checked) => void confirm(checked)} onReconfigure={() => { setQuote(null); setError(null); setEstimateUncertain(false) }} /> : <RunConfiguration current={current} permissions={permissions} busy={busy || permissionLoading} initial={input} onEstimate={(value) => void estimate(value)} onError={setError} />)}
      {busy && <Loading>正在处理当前检测动作，请勿重复提交…</Loading>}
      <div className="form-actions"><button disabled={busy || permissionLoading} onClick={reloadPermissions}>重新读取执行权限</button></div>
      {error instanceof ApiError && ['MI_PRECHECK_REQUIRED', 'MI_PRECHECK_STALE'].includes(error.code) && <p className="empty-note">请返回目标列表，主动打开“预检”并确认可能产生的费用。此页面不会自动运行预检。</p>}
    </>}
    <div className="form-actions"><button disabled={busy || uncertain} onClick={onCancel}>返回目标列表</button></div>
    <p className="field-help">离开或切换组织只停止本页读取，不会撤销后台已提交的任务。检测结果和报告只有真实接口接入后才会开放。</p>
  </section>
}
function unknownOutcome(failure: unknown) {
  // This explicit preflight error guarantees that no Run was created. Other
  // 5xx responses may have lost an accepted submission and remain uncertain.
  if (failure instanceof ApiError && failure.code === 'MI_EXECUTION_NOT_READY') return false
  return !(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500
}
