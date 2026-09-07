import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, passwordChangeRequired, sessionInvalid } from '../../api'
import type { Page } from '../../targets-api'
import { ErrorNotice, Loading } from '../Feedback'

export interface ManagementContext { csrfToken: string; userID: string; systemAdmin: boolean; onSignedOut: (notice: string) => void; onPasswordRequired: () => void }
export function useFailure(context: Pick<ManagementContext, 'onSignedOut' | 'onPasswordRequired'>) {
  const { onSignedOut, onPasswordRequired } = context
  return useCallback((error: unknown) => {
    if (sessionInvalid(error)) { onSignedOut('会话已失效，请重新登录。'); return true }
    if (passwordChangeRequired(error)) { onPasswordRequired(); return true }
    return false
  }, [onSignedOut, onPasswordRequired])
}

export function useManagementList<T>(load: (cursor: string, q: string, signal: AbortSignal) => Promise<Page<T>>, onFailure: (failure: unknown) => boolean) {
  const [result, setResult] = useState<Page<T> | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [cursor, setCursor] = useState('')
  const [query, setQuery] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    void load(cursor, query, controller.signal).then((data) => { if (!controller.signal.aborted) setResult(data) }).catch((failure: unknown) => {
      if (!controller.signal.aborted && !onFailure(failure)) setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [load, cursor, query, attempt, onFailure])
  function refresh() { setLoading(true); setError(null); setAttempt((value) => value + 1) }
  function search(value: string) { setQuery(value); setCursor(''); setHistory([]); setResult(null); refresh() }
  function next() { if (result?.next_cursor) { setHistory((old) => [...old, cursor]); setCursor(result.next_cursor); setResult(null); refresh() } }
  function previous() { if (history.length) { setCursor(history[history.length - 1]); setHistory((old) => old.slice(0, -1)); setResult(null); refresh() } }
  return { result, error, loading, query, pageNumber: history.length + 1, canPrevious: history.length > 0, refresh, search, next, previous }
}
export function ListControls({ list, label }: { list: { loading: boolean; search: (query: string) => void; refresh: () => void }; label: string }) {
  const [error, setError] = useState('')
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const value = String(new FormData(event.currentTarget).get('q') ?? '').trim()
    if (new TextEncoder().encode(value).length > 128 || /\p{Cc}/u.test(value)) { setError('搜索内容不得超过 128 字节或包含控制字符。'); return }
    setError('')
    list.search(value)
  }
  return <><form className="management-search" onSubmit={submit} aria-label={`搜索${label}`}><label htmlFor={`search-${label}`}>服务端搜索{label}</label><input id={`search-${label}`} name="q" type="search" maxLength={128} /><button disabled={list.loading} type="submit">搜索</button><button disabled={list.loading} type="button" onClick={list.refresh}>刷新列表</button></form>{error && <p className="field-error">{error}</p>}</>
}
export function Pagination({ list }: { list: { loading: boolean; error: unknown; result: { next_cursor: string | null } | null; pageNumber: number; canPrevious: boolean; next: () => void; previous: () => void } }) {
  return <div className="pagination"><button disabled={list.loading || !list.canPrevious} onClick={list.previous}>上一页</button><span>第 {list.pageNumber} 页</span><button disabled={list.loading || Boolean(list.error) || !list.result?.next_cursor} onClick={list.next}>下一页</button></div>
}
export function ListFeedback({ list, label }: { list: { loading: boolean; error: unknown; result: { items: unknown[] } | null }; label: string }) {
  return <>{list.loading && <Loading>{`正在读取${label}…`}</Loading>}<ErrorNotice error={list.error} />{Boolean(list.error) && list.result && <p className="empty-note">读取失败，下方为上次成功加载的数据，可能过期；请刷新后再修改。</p>}{!list.loading && !list.error && list.result?.items.length === 0 && <p className="empty-note">没有符合条件的{label}。</p>}</>
}

export function ManagedForm<T>({ title, description, children, submit, onSaved, onCancel, onFailure, onConflict }: {
  title: string; description: string; children: ReactNode; submit: (form: HTMLFormElement, signal: AbortSignal) => Promise<T>
  onSaved: (result: T) => void; onCancel: () => void; onFailure: (failure: unknown) => boolean; onConflict?: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const active = useRef(false)
  const request = useRef<AbortController | null>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); return () => request.current?.abort() }, [])
  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (active.current) return
    const form = event.currentTarget
    const controller = new AbortController()
    request.current = controller
    active.current = true
    setBusy(true)
    setError(null)
    try {
      const result = await submit(form, controller.signal)
      if (!controller.signal.aborted) onSaved(result)
    } catch (failure) {
      if (!controller.signal.aborted && !onFailure(failure)) setError(failure)
    } finally {
      form.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach((input) => { input.value = '' })
      active.current = false
      if (!controller.signal.aborted) setBusy(false)
    }
  }
  return <section className="panel target-editor" aria-labelledby="management-form-title"><h2 id="management-form-title" ref={heading} tabIndex={-1}>{title}</h2><p className="muted">{description}</p><ErrorNotice error={error} id="management-form-error" />
    {error instanceof ApiError && error.status === 409 && onConflict && <div><p className="field-help">重新读取会丢弃未保存编辑；不会自动重试刚才的操作。</p><button disabled={busy} onClick={onConflict}>返回并刷新列表</button></div>}
    <form aria-label={title} onSubmit={handleSubmit} noValidate><fieldset disabled={busy}><legend className="sr-only">{title}</legend>{children}<div className="form-actions"><button className="primary-button" type="submit">{busy ? '正在提交…' : '确认提交'}</button><button type="button" onClick={onCancel}>取消</button></div>{busy && <Loading>正在保存管理变更…</Loading>}</fieldset></form>
  </section>
}
export function Field({ name, label, value = '', type = 'text', help, maxLength = 128 }: { name: string; label: string; value?: string; type?: 'text' | 'password' | 'number'; help?: string; maxLength?: number }) {
  return <div className="field"><label htmlFor={name}>{label}</label><input id={name} name={name} type={type} defaultValue={value} maxLength={maxLength} autoComplete={type === 'password' ? 'new-password' : 'off'} aria-describedby={help ? `${name}-help` : undefined} />{help && <p id={`${name}-help`} className="field-help">{help}</p>}</div>
}
export function StatusField({ value, selfProtected = false }: { value: 'active' | 'disabled'; selfProtected?: boolean }) {
  return <div className="field"><label htmlFor="status">状态</label><select id="status" name="status" defaultValue={value}><option value="active">启用</option><option value="disabled" disabled={selfProtected}>停用</option></select>{selfProtected && <p className="field-help">不能停用当前登录账号或自己的成员资格。</p>}</div>
}
export function formValue(form: HTMLFormElement, key: string) { return String(new FormData(form).get(key) ?? '') }
export function formStatus(form: HTMLFormElement): 'active' | 'disabled' {
  const value = formValue(form, 'status')
  if (value !== 'active' && value !== 'disabled') throw new ApiError('MI_INVALID_REQUEST')
  return value
}
export function requireText(value: string, max: number, required = true) {
  if (new TextEncoder().encode(value).length > max || /\p{Cc}/u.test(value) || (required && !value.trim())) throw '请输入符合长度要求、且不含控制字符的字段内容。'
  return value
}
export function temporaryPassword(form: HTMLFormElement) {
  const password = formValue(form, 'password')
  if ([...password].length < 12 || new TextEncoder().encode(password).length > 256 || password.includes('\0')) throw '临时密码至少 12 个字符，UTF-8 编码不超过 256 字节。'
  if (password !== formValue(form, 'confirm_password')) throw '两次临时密码输入不一致。'
  return password
}
