import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, ApiError, passwordChangeRequired, sessionInvalid, type Session } from '../api'
import { ErrorNotice } from './Feedback'

type Mode = 'setup' | 'login' | 'password'
type Fields = Record<string, string>
const passwordHelp = '至少 12 个字符，UTF-8 编码不超过 256 字节。'
function validPassword(value: string) {
  return [...value].length >= 12 && new TextEncoder().encode(value).length <= 256 && !value.includes('\0')
}
export function AuthForm({ mode, session, onSession, onSignedOut, onInitialized, onSetupConflict, onPasswordRequired, notice }: {
  mode: Mode; session?: Session; onSession?: (value: Session) => void; onSignedOut?: (message: string) => void
  onInitialized?: () => void; onSetupConflict?: () => void; onPasswordRequired?: () => void; notice?: string
}) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [fields, setFields] = useState<Fields>({})
  const [retryUntil, setRetryUntil] = useState(0)
  const [now, setNow] = useState(() => Date.now())
  const activeRequest = useRef<AbortController | null>(null)
  const submitting = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  useEffect(() => () => activeRequest.current?.abort(), [])
  useEffect(() => {
    if (!retryUntil) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [retryUntil])
  const remaining = Math.max(0, Math.ceil((retryUntil - now) / 1000))
  const title = mode === 'setup' ? '初始化工作空间' : mode === 'login' ? '登录工作空间' : '修改密码'
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting.current || remaining) return
    const form = event.currentTarget
    const values = new FormData(form)
    const value = (name: string) => String(values.get(name) ?? '')
    const username = value('username').trim()
    const password = value('password')
    const errors: Fields = {}
    if (mode !== 'password' && !/^[a-zA-Z0-9._-]{3,64}$/.test(username)) errors.username = '用户名为 3～64 位字母、数字、点、下划线或短横线。'
    if (mode === 'setup') {
      const org = value('organization_name').trim()
      if (!org || new TextEncoder().encode(org).length > 128) errors.organization_name = '请输入组织名称（UTF-8 编码不超过 128 字节）。'
      if (value('setup_token') && !/^[\x21-\x7e]{1,256}$/.test(value('setup_token'))) errors.setup_token = '请输入管理员提供的一次性初始化令牌，不含空白或换行。'
    }
    if (mode !== 'login' && !validPassword(password)) errors.password = passwordHelp
    if (mode === 'login' && !password) errors.password = '请输入密码。'
    if (mode !== 'login' && password !== value('confirm_password')) errors.confirm_password = '两次密码输入不一致。'
    if (mode === 'password' && !value('current_password')) errors.current_password = '请输入当前密码。'
    setFields(errors)
    setError(null)
    if (Object.keys(errors).length) {
      const input = form.elements.namedItem(Object.keys(errors)[0])
      if (input instanceof HTMLElement) input.focus()
      return
    }
    const controller = new AbortController()
    activeRequest.current = controller
    submitting.current = true
    setPending(true)
    try {
      if (mode === 'setup') {
        await api.initialize({ organization_name: value('organization_name').trim(), username, password }, value('setup_token'), controller.signal)
        if (!controller.signal.aborted) onInitialized?.()
      } else if (mode === 'login') {
        const result = await api.login({ username, password }, controller.signal)
        if (!controller.signal.aborted) onSession?.(result)
      } else if (session) {
        await api.changePassword({ current_password: value('current_password'), new_password: password }, session.csrf_token, controller.signal)
        if (!controller.signal.aborted) onSignedOut?.('密码已修改，所有会话已失效。请使用新密码登录。')
      }
    } catch (failure) {
      if (controller.signal.aborted) return
      if (mode === 'setup' && failure instanceof ApiError && failure.code === 'MI_SETUP_CLOSED') onSetupConflict?.()
      else if (mode === 'password' && sessionInvalid(failure)) onSignedOut?.('会话已失效或安全校验未通过，请重新登录。')
      else if (mode === 'password' && passwordChangeRequired(failure) && onPasswordRequired) onPasswordRequired()
      else {
        setError(failure)
        if (failure instanceof ApiError && failure.retryAfter) {
          setNow(Date.now())
          setRetryUntil(Date.now() + failure.retryAfter * 1000)
        }
      }
    } finally {
      form.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach((input) => { input.value = '' })
      submitting.current = false
      if (!controller.signal.aborted) setPending(false)
    }
  }
  function field(name: string, label: string, type: 'text' | 'password', autoComplete: string, help?: string, required = true) {
    return <div className="field">
      <label htmlFor={name}>{label}{!required && <span className="optional">（可选）</span>}</label>
      <input id={name} name={name} type={type} autoComplete={autoComplete} required={required}
        maxLength={name === 'username' ? 64 : 256} aria-invalid={Boolean(fields[name])}
        aria-describedby={[help ? `${name}-help` : '', fields[name] ? `${name}-error` : ''].filter(Boolean).join(' ') || undefined} />
      {help && <p id={`${name}-help`} className="field-help">{help}</p>}
      {fields[name] && <p id={`${name}-error`} className="field-error">{fields[name]}</p>}
    </div>
  }
  return <section className="auth-card" aria-labelledby="form-title">
    <p className="eyebrow">{mode === 'setup' ? '首次使用 · 01 / 02' : mode === 'login' ? '身份验证' : '账号安全'}</p>
    <h1 id="form-title" ref={heading} tabIndex={-1}>{title}</h1>
    <p className="muted">{mode === 'setup' ? '建立第一个组织与系统管理员。完成后需单独登录。' : mode === 'login' ? '使用组织账号继续。检测数据始终受组织权限约束。' : '修改成功会注销所有会话，包括当前会话。'}</p>
    {notice && <output className="notice success">{notice}</output>}
    <ErrorNotice error={error} />
    <form onSubmit={submit} noValidate aria-label={title}>
      <fieldset disabled={pending}>
        <legend className="sr-only">{title}</legend>
        {mode === 'setup' && field('organization_name', '组织名称', 'text', 'organization')}
        {mode !== 'password' && field('username', mode === 'setup' ? '管理员用户名' : '用户名', 'text', 'username')}
        {mode === 'password' && field('current_password', '当前密码', 'password', 'current-password')}
        {field('password', mode === 'password' ? '新密码' : '密码', 'password', mode === 'login' ? 'current-password' : 'new-password', mode === 'login' ? undefined : passwordHelp)}
        {mode !== 'login' && field('confirm_password', '确认密码', 'password', 'new-password')}
        {mode === 'setup' && field('setup_token', '一次性初始化令牌', 'password', 'off', '远程 HTTPS 初始化需要管理员提供令牌；仅保留在当前表单内存中，不会保存到浏览器存储。', false)}
        <button className="primary-button" type="submit" disabled={remaining > 0}>{pending ? '正在提交…' : remaining ? `${remaining} 秒后可重试` : mode === 'setup' ? '创建组织和管理员' : mode === 'login' ? '登录' : '修改密码并重新登录'}</button>
      </fieldset>
      {(pending || remaining > 0) && <output className="field-help">{pending ? '请求处理中，请勿重复提交。' : `请等待 ${remaining} 秒后重试。`}</output>}
    </form>
  </section>
}
