import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, passwordChangeRequired, sessionInvalid } from '../../api'
import { targetsApi, type Target } from '../../targets-api'
import { ErrorNotice, Loading } from '../Feedback'
import { CredentialFields } from './CredentialFields'
import { clearCredentials, readCredentials, type FieldErrors } from './validation'
import type { TargetCallbacks } from './TargetForm'

export function SecretForm({ organizationID, csrfToken, current, onSaved, onCancel, onReload, onSignedOut, onPasswordRequired }: TargetCallbacks & {
  current: Target; onSaved: (target: Target) => void; onCancel: () => void; onReload: () => void
}) {
  const [error, setError] = useState<unknown>(null)
  const [fields, setFields] = useState<FieldErrors>({})
  const [saving, setSaving] = useState(false)
  const request = useRef<AbortController | null>(null)
  const active = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); return () => request.current?.abort() }, [])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (active.current) return
    const form = event.currentTarget
    const { auth, errors } = readCredentials(form)
    setFields(errors)
    setError(null)
    if (!auth) {
      const control = form.elements.namedItem(Object.keys(errors)[0])
      if (control instanceof HTMLElement) control.focus()
      return
    }
    const controller = new AbortController()
    request.current = controller
    active.current = true
    setSaving(true)
    try {
      const result = await targetsApi.rotate(organizationID, csrfToken, current.id, current.version, current.secret.version, auth, controller.signal)
      if (!controller.signal.aborted) onSaved(result)
    } catch (failure) {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setError(failure)
    } finally {
      clearCredentials(form)
      active.current = false
      if (!controller.signal.aborted) setSaving(false)
    }
  }
  return <section className="panel target-editor" aria-labelledby="secret-form-title">
    <div className="section-heading"><h2 ref={heading} tabIndex={-1} id="secret-form-title">轮换目标凭证</h2><button disabled={saving} onClick={onCancel}>返回列表</button></div>
    <p className="muted">目标：{current.name}。当前凭证 {current.secret.mask}，版本 {current.secret.version}。请输入完整的新认证配置；未填写旧请求头不会被沿用。空 Key 不会删除现有凭证。</p>
    <ErrorNotice error={error} id="rotate-error" />
    {error instanceof ApiError && (error.status === 409 || error.status === 404) && <button disabled={saving} onClick={onReload}>重新读取目标</button>}
    <form aria-label="轮换目标凭证" onSubmit={submit} noValidate><fieldset disabled={saving}><legend className="sr-only">新凭证配置</legend><CredentialFields errors={fields} /><div className="form-actions"><button type="submit" className="primary-button">{saving ? '正在轮换…' : '确认轮换凭证'}</button><button type="button" onClick={onCancel}>取消</button></div>{saving && <Loading>正在替换加密凭证…</Loading>}</fieldset></form>
  </section>
}
