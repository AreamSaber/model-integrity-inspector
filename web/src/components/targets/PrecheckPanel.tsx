import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { precheckErrors, prechecksApi, type Precheck } from '../../prechecks-api'
import type { Target } from '../../targets-api'
import { ErrorNotice, Loading } from '../Feedback'
import { useFailure } from '../management/shared'
import type { TargetCallbacks } from './TargetForm'

const labels: Record<Precheck['checks'][number]['name'], string> = { network: '网络连接', authentication: '上游认证', model: '模型可用性', nonstream: '非流式响应', stream: '流式响应', parameters: '输出参数兼容性' }
const statuses: Record<Precheck['status'] | 'unsupported', string> = { queued: '已排队', running: '执行中', passed: '通过', failed: '失败', unsupported: '不支持' }
const running = (record: Precheck) => record.status === 'queued' || record.status === 'running'
export function PrecheckPanel({ current, onCancel, onReload, ...context }: TargetCallbacks & { current: Target; onCancel: () => void; onReload: () => void }) {
  const onFailure = useFailure(context)
  const [record, setRecord] = useState<{ value: Precheck; source: 'submitted' | 'latest' } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [uncertain, setUncertain] = useState(false)
  const [empty, setEmpty] = useState(false)
  const key = useRef<string | null>(null)
  const controller = useRef<AbortController | null>(null)
  const active = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); return () => controller.current?.abort() }, [])
  async function enqueue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (active.current || record) return
    if (!uncertain && new FormData(event.currentTarget).get('confirm_cost') !== 'on') { setError('请先确认预检会向该目标发起请求，且可能产生上游费用。'); return }
    const request = new AbortController()
    controller.current = request; active.current = true; setBusy(true); setError(null); setEmpty(false)
    let dispatched = false
    try {
      // One logical action retains its key even when the HTTP result is unknown.
      key.current ??= `mii-${crypto.randomUUID()}`
      dispatched = true
      const result = await prechecksApi.enqueue(context.organizationID, context.csrfToken, current.id, current.version, key.current, request.signal)
      if (!request.signal.aborted) setRecord({ value: result, source: 'submitted' })
    } catch (failure) {
      if (!request.signal.aborted && !onFailure(failure)) {
        setError(failure)
        if (dispatched && (!(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500)) setUncertain(true)
      }
    } finally { active.current = false; if (!request.signal.aborted) setBusy(false) }
  }
  async function latest() {
    if (active.current || uncertain) return
    const request = new AbortController(); controller.current = request; active.current = true; setBusy(true); setError(null); setEmpty(false)
    try { const result = await prechecksApi.latest(context.organizationID, current.id, request.signal); if (!request.signal.aborted) setRecord({ value: result, source: 'latest' }) }
    catch (failure) {
      if (!request.signal.aborted && !onFailure(failure)) {
        if (failure instanceof ApiError && failure.code === 'MI_NOT_FOUND') setEmpty(true)
        else setError(failure)
      }
    } finally { active.current = false; if (!request.signal.aborted) setBusy(false) }
  }
  return <section className="panel target-editor" aria-labelledby="precheck-title"><h2 id="precheck-title" ref={heading} tabIndex={-1}>目标预检：{current.name}</h2>
    <p className="muted">目标 ID {current.id} · 配置版本 {current.version} · {current.endpoint}</p>
    <p className="notice warning">预检最多发起 3 次上游请求，可能产生费用。通过仅说明该版本配置的连接、认证、协议与参数能力，不代表模型真实性或完整性检测通过。</p>
    {record ? <TrackedPrecheck key={record.value.id} initial={record.value} source={record.source} targetVersion={current.version} organizationID={context.organizationID} onFailure={onFailure} /> : <>
      <ErrorNotice error={error} id="precheck-error" />
      {empty && <p className="empty-note">未找到该目标可读取的预检记录；本次查看不会发起上游请求。</p>}
      {uncertain && <p className="notice warning">提交结果不确定，服务端可能已经创建任务。不会自动重发；下方重试使用同一请求标识与相同版本，不会静默创建新动作。不要通过重新打开页面反复发起预检。</p>}
      <form aria-label="确认目标预检" onSubmit={enqueue}><fieldset disabled={busy || current.status !== 'active'}><legend className="sr-only">预检提交确认</legend>
        {!uncertain && <label className="grant-option"><input type="checkbox" name="confirm_cost" /><span>我确认向此目标发起最多 3 次请求，并接受可能产生的费用。</span></label>}
        <button type="submit" className="primary-button">{busy ? '正在提交…' : uncertain ? '使用同一请求标识重试确认' : '确认发起预检'}</button>
      </fieldset></form>
      {current.status !== 'active' && <p className="empty-note">目标未启用，不能发起新预检。</p>}
      <div className="form-actions"><button disabled={busy || uncertain} onClick={() => void latest()}>查看最近一次预检（只读）</button>
        {!uncertain && error instanceof ApiError && error.status === 409 && <button disabled={busy} onClick={onReload}>重新读取目标版本</button>}
      </div>
      {busy && <Loading>正在处理预检请求…</Loading>}
    </>}
    <div className="form-actions"><button onClick={onCancel}>返回目标列表</button></div><p className="field-help">离开此页会停止本页读取，不会取消已提交的后台任务。发起新预检始终需要重新确认；正式检测须返回目标列表，另行配置并确认费用。</p>
  </section>
}

function TrackedPrecheck({ initial, source, targetVersion, organizationID, onFailure }: { initial: Precheck; source: 'submitted' | 'latest'; targetVersion: number; organizationID: string; onFailure: (failure: unknown) => boolean }) {
  const [record, setRecord] = useState(initial)
  const [error, setError] = useState<unknown>(null)
  const [reading, setReading] = useState(running(initial))
  const [paused, setPaused] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const current = useRef(initial)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  useEffect(() => {
    if (!running(current.current) && attempt === 0) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let reads = 0
    async function read() {
      try {
        const result = await prechecksApi.get(organizationID, initial.target_id, initial.id, controller.signal)
        if (controller.signal.aborted) return
        // Pin the job and configuration too; a server/proxy response cannot move
        // this panel to another logical request or regress its version.
        if (result.job_id !== initial.job_id || result.target_version !== initial.target_version || result.version < current.current.version) throw new ApiError('MI_INVALID_RESPONSE')
        current.current = result; setRecord(result)
        reads += 1
        if (running(result) && reads < 300) timer = setTimeout(() => void read(), 3000)
        else { setReading(false); setPaused(running(result)) }
      } catch (failure) {
        if (!controller.signal.aborted && !onFailure(failure)) { setError(failure); setReading(false) }
      }
    }
    void read()
    return () => { controller.abort(); if (timer !== undefined) clearTimeout(timer) }
  }, [initial.id, initial.job_id, initial.target_id, initial.target_version, organizationID, onFailure, attempt])
  return <section aria-labelledby="precheck-result-title"><h3 id="precheck-result-title" ref={heading} tabIndex={-1} aria-live="polite" aria-atomic="true">{source === 'submitted' ? '本次提交的预检' : '最近记录（非本次提交）'}：{statuses[record.status]}</h3>
    <p className="cell-detail">预检 ID {record.id} · 任务 ID {record.job_id} · 目标版本 {record.target_version} · 记录版本 {record.version}</p>
    <p>已记录上游请求：{record.request_count} / 3</p>
    {source === 'latest' && <p className="field-help">“最近”仅指主动打开时读取到的记录。现在只跟踪此固定 ID，不会自动切换到更新的他人请求。</p>}
    {record.target_version !== targetVersion && <p className="notice warning">此记录对应不同目标版本，不能作为本页配置的预检结果；请重新读取目标。</p>}
    {record.status === 'passed' && <p className="notice success">预检能力检查通过，不是模型真实性或完整性结论。</p>}
    {record.error_code && <p className="notice warning">{precheckErrors[record.error_code]}</p>}
    {record.max_output_parameter && <p>识别到的输出参数：{record.max_output_parameter}</p>}
    {record.checks.length > 0 ? <div className="table-scroll"><table><caption className="sr-only">预检能力检查结果</caption><thead><tr><th scope="col">检查项</th><th scope="col">状态</th><th scope="col">说明</th></tr></thead><tbody>{record.checks.map((check) => <tr key={check.name}><th scope="row">{labels[check.name]}</th><td>{statuses[check.status]}</td><td>{check.error_code ? precheckErrors[check.error_code] : '未报告错误'}</td></tr>)}</tbody></table></div> : <p className="empty-note">尚未返回能力检查项，不表示检查通过。</p>}
    <dl className="precheck-times"><dt>创建时间</dt><dd>{new Date(record.created_at).toLocaleString()}</dd><dt>开始时间</dt><dd>{record.started_at ? new Date(record.started_at).toLocaleString() : '未记录开始时间'}</dd><dt>结束时间</dt><dd>{record.checked_at ? new Date(record.checked_at).toLocaleString() : '未记录结束时间'}</dd></dl>
    <p className="field-help">时间以浏览器本地时区显示。</p>
    <ErrorNotice error={error} id="precheck-poll-error" />
    {reading && <Loading>正在跟踪此预检 ID；每次读取不会重新执行预检…</Loading>}
    {paused && <p className="empty-note">已达到本页自动读取次数上限，暂停读取；这不表示后台失败。</p>}
    {Boolean(error) && <p className="empty-note">状态停止更新，当前显示的是最后一次成功读取的记录；不会改用其他人的最近请求。</p>}
    <button disabled={reading} onClick={() => { setError(null); setPaused(false); setReading(true); setAttempt((value) => value + 1) }}>重新读取此预检</button>
  </section>
}
