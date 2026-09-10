import { useCallback, useEffect, useRef, useState } from 'react'
import { api, sessionInvalid, type Session } from '../api'
import { AuthForm } from './AuthForms'
import { ErrorNotice, Loading } from './Feedback'
import { SessionLayout } from './SessionLayout'
import { SessionSecurity } from './SessionSecurity'

// A password-required response removes the complete business subtree before
// refreshing /auth/me. No original request is replayed, including read requests.
export function AuthenticatedSession({ initialSession, onSignedOut }: { initialSession: Session; onSignedOut: (notice: string) => void }) {
  const [session, setSession] = useState(initialSession)
  const [gate, setGate] = useState<'normal' | 'required' | 'recovering' | 'recovery-error'>(initialSession.user.must_change_password ? 'required' : 'normal')
  const [error, setError] = useState<unknown>(null)
  const [logoutPending, setLogoutPending] = useState(false)
  const request = useRef<AbortController | null>(null)
  const logoutActive = useRef(false)
  useEffect(() => () => request.current?.abort(), [])
  useEffect(() => {
    if (gate !== 'normal') document.title = '必须修改密码 · Model Integrity Inspector'
  }, [gate])
  useEffect(() => {
    const remaining = Date.parse(session.expires_at) - Date.now()
    const timer = window.setTimeout(() => onSignedOut('会话已过期，请重新登录。'), Math.max(0, Math.min(remaining, 2_147_483_647)))
    return () => window.clearTimeout(timer)
  }, [session.expires_at, onSignedOut])

  const recoverSession = useCallback(() => {
    if (logoutActive.current) return
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setGate('recovering')
    setError(null)
    void api.me(controller.signal).then((result) => {
      if (controller.signal.aborted) return
      setSession(result)
      // An inconsistent response must not silently reopen previously denied UI.
      if (!result.user.must_change_password) {
        setError('服务要求修改密码，但会话状态尚未同步。请重试读取会话，或退出后重新登录。')
        setGate('recovery-error')
      } else setGate('required')
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else { setError(failure); setGate('recovery-error') }
    })
  }, [onSignedOut])

  async function logout() {
    if (logoutActive.current) return
    logoutActive.current = true
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setLogoutPending(true)
    setError(null)
    try {
      await api.logout(session.csrf_token, controller.signal)
      if (!controller.signal.aborted) onSignedOut('已退出当前会话。')
    } catch (failure) {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else {
        setError(failure)
        if (gate === 'recovering') setGate('recovery-error')
      }
    } finally {
      logoutActive.current = false
      if (!controller.signal.aborted) setLogoutPending(false)
    }
  }

  if (gate === 'normal') return <SessionLayout session={session} onSignedOut={onSignedOut} onPasswordRequired={recoverSession} />
  return <main className="auth-shell password-gate" id="main-content">
    <div className="brand-block"><span className="brand-mark" aria-hidden="true">M</span><span>Model Integrity Inspector<small>账号安全校验</small></span></div>
    <output className="notice warning">当前账号必须先修改临时密码。完成之前仅可修改密码或退出登录。</output>
    <p className="muted">当前账号：{session.user.display_name || session.user.username}（{session.user.username}）</p>
    <ErrorNotice error={error} id="password-gate-error" />
    {gate === 'required' ? <AuthForm mode="password" session={session} onSignedOut={onSignedOut} onPasswordRequired={recoverSession} /> :
      <section className="auth-card"><h1>读取账号安全状态</h1>{gate === 'recovering' ? <Loading>正在重新读取会话…</Loading> : <button disabled={logoutPending} onClick={recoverSession}>重新读取会话</button>}</section>}
    <button className="gate-logout" disabled={logoutPending} onClick={() => void logout()}>{logoutPending ? '正在退出…' : '退出登录'}</button>
    <SessionSecurity session={session} onSignedOut={onSignedOut} disabled={logoutPending || gate === 'recovering'} />
  </main>
}
