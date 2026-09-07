import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError } from '../../api'
import { catalogApi, catalogText } from '../../catalog-api'
import { ErrorNotice, Loading } from '../Feedback'
import { useFailure } from '../management/shared'

export interface CatalogContext { organizationID: string; userID: string; csrfToken: string; onSignedOut: (notice: string) => void; onPasswordRequired: () => void }
export function useCatalogPermission(context: CatalogContext) {
  const onFailure = useFailure(context)
  const [allowed, setAllowed] = useState(false), [loading, setLoading] = useState(true), [error, setError] = useState<unknown>(null), [attempt, setAttempt] = useState(0)
  const authorize = useCallback(async (signal: AbortSignal) => {
    try {
      const result = await catalogApi.permissions(context.organizationID, context.userID, signal)
      if (signal.aborted) return
      const permitted = result.permissions.includes('catalog.write')
      setAllowed(permitted)
      if (!permitted) throw new ApiError('MI_PERMISSION_DENIED', 403)
    } catch (failure) { if (!signal.aborted) setAllowed(false); throw failure }
  }, [context.organizationID, context.userID])
  useEffect(() => {
    const controller = new AbortController()
    void catalogApi.permissions(context.organizationID, context.userID, controller.signal).then((result) => { if (!controller.signal.aborted) setAllowed(result.permissions.includes('catalog.write')) }).catch((failure: unknown) => { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, onFailure, attempt])
  return { allowed, loading, error, authorize, deny: () => setAllowed(false), reload: () => { setAllowed(false); setLoading(true); setError(null); setAttempt((value) => value + 1) } }
}
export type CatalogPermission = ReturnType<typeof useCatalogPermission>
export function CatalogError({ error, id = 'catalog-error' }: { error: unknown; id?: string }) {
  const conflict = error instanceof ApiError && error.code === 'MI_VERSION_CONFLICT'
  return <><ErrorNotice error={conflict ? '记录版本或关联约束冲突：供应商可能仍被模型／目标引用，模型标识修改或删除可能被目标引用保护。请重新读取并检查关联，不会自动覆盖或级联删除。' : error} id={id} />{conflict && error.requestID && <p className="request-id">请求编号：{error.requestID}</p>}</>
}
export function CatalogMutation({ title, context, gate, prepare, onSaved, onCancel, children, destructive = false }: {
  title: string; context: CatalogContext; gate: CatalogPermission; prepare: (form: HTMLFormElement) => (signal: AbortSignal) => Promise<unknown>; onSaved: () => void; onCancel: () => void; children: ReactNode; destructive?: boolean
}) {
  const onFailure = useFailure(context)
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [uncertain, setUncertain] = useState(false)
  const active = useRef(false), request = useRef<AbortController | null>(null), heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); heading.current?.scrollIntoView?.({ block: 'start' }); return () => request.current?.abort() }, [])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (active.current || uncertain || !gate.allowed || gate.loading) return
    const controller = new AbortController(); request.current = controller; active.current = true; setBusy(true); setError(null)
    let dispatched = false
    try {
      const write = prepare(event.currentTarget)
      await gate.authorize(controller.signal)
      if (controller.signal.aborted) return
      dispatched = true
      await write(controller.signal)
      if (!controller.signal.aborted) onSaved()
    } catch (failure) {
      if (!controller.signal.aborted && !onFailure(failure)) {
        setError(failure)
        if (failure instanceof ApiError && failure.status === 403) gate.deny()
        if (dispatched && (!(failure instanceof ApiError) || ['MI_NETWORK_ERROR', 'MI_INVALID_RESPONSE'].includes(failure.code) || failure.status >= 500)) setUncertain(true)
      }
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  return <section className="panel target-editor" aria-labelledby="catalog-form-title"><h2 ref={heading} tabIndex={-1} id="catalog-form-title">{title}</h2><CatalogError error={error} /><CatalogError error={gate.error} id="catalog-permission-error" />
    {uncertain && <p className="notice warning">提交结果不确定，变更可能已经保存。本页不会自动重试；请返回列表核对并重新读取，避免重复创建或覆盖。</p>}
    {!gate.allowed && <p className="empty-note">当前有效权限不足或未知，写操作已禁用；需要 catalog.write。</p>}
    <form aria-label={title} noValidate onSubmit={submit}><fieldset disabled={busy || uncertain || !gate.allowed || gate.loading}><legend className="sr-only">{title}</legend>{children}<button type="submit" className={destructive ? 'danger-button' : 'primary-button'} disabled={busy || uncertain || !gate.allowed || gate.loading}>{busy ? '正在保存…' : destructive ? '确认删除档案' : '保存档案'}</button></fieldset></form>
    {busy && <Loading>正在验证权限并保存档案…</Loading>}
    <div className="form-actions"><button disabled={busy} onClick={onCancel}>{uncertain || (error instanceof ApiError && error.status === 409) ? '返回列表并重新读取' : '返回档案列表'}</button><button disabled={busy || gate.loading} onClick={gate.reload}>重新读取目录权限</button></div>
  </section>
}
export function value(form: HTMLFormElement, name: string) { return String(new FormData(form).get(name) ?? '') }
export function fieldText(form: HTMLFormElement, name: string, limit: number, required = false) { const result = value(form, name); if (!catalogText(result, limit, required)) throw `文字字段不得包含控制字符，且须满足字符数量限制（最多 ${limit} 个字符）。`; return result }
export function fieldStatus(form: HTMLFormElement): 'active' | 'disabled' { const result = value(form, 'status'); if (result !== 'active' && result !== 'disabled') throw '请选择有效档案状态。'; return result }
export function CatalogField({ name, label, initial = '', max = 128, help }: { name: string; label: string; initial?: string; max?: number; help?: string }) { return <div className="field"><label htmlFor={`catalog-${name}`}>{label}</label><input id={`catalog-${name}`} name={name} defaultValue={initial} maxLength={max} aria-describedby={help ? `catalog-${name}-help` : undefined} />{help && <p className="field-help" id={`catalog-${name}-help`}>{help}</p>}</div> }
export function CatalogStatusField({ initial = 'active' }: { initial?: 'active' | 'disabled' }) { return <div className="field"><label htmlFor="catalog-status">档案状态</label><select id="catalog-status" name="status" defaultValue={initial}><option value="active">启用</option><option value="disabled">停用</option></select></div> }
