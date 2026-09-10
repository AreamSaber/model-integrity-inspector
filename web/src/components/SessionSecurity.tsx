import { useEffect, useRef, useState } from 'react'
import { api, ApiError, sessionInvalid, type Session } from '../api'

const uncertainNotice = '退出所有会话的结果未确认。请求可能已经生效，也可能未生效；此页不会自动重试。请重新登录后核实账号安全状态。'

// Global self-service action: no organization, role, password, user ID or token
// is sent in the body. A failed/lost response is not a revocation receipt.
type SessionSecurityProps = {
  session: Session; onSignedOut: (notice: string) => void; disabled?: boolean
}
export function SessionSecurity(props: SessionSecurityProps) {
  const { session } = props
  const [scope, setScope] = useState({ userID: session.user.id, csrfToken: session.csrf_token, generation: 0 })
  // Reset the subtree before a changed identity is committed. The key is a
  // local counter, never a session/CSRF token exposed as an element identity.
  if (scope.userID !== session.user.id || scope.csrfToken !== session.csrf_token) {
    setScope({ userID: session.user.id, csrfToken: session.csrf_token, generation: scope.generation + 1 })
  }
  return <SessionRevocation key={scope.generation} {...props} />
}

function SessionRevocation({ session, onSignedOut, disabled = false }: SessionSecurityProps) {
  const [phase, setPhase] = useState<'idle' | 'confirm' | 'pending' | 'unknown' | 'complete'>('idle')
  const [confirmed, setConfirmed] = useState(false)
  const active = useRef<AbortController | null>(null)
  const submitting = useRef(false)
  const confirmation = useRef<HTMLHeadingElement>(null)
  const start = useRef<HTMLButtonElement>(null)
  const alert = useRef<HTMLDivElement>(null)
  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => {
    if (phase === 'confirm') confirmation.current?.focus()
    if (phase === 'unknown') alert.current?.focus()
  }, [phase])

  async function submit() {
    if (disabled || phase !== 'confirm' || !confirmed || submitting.current) return
    submitting.current = true
    const controller = new AbortController()
    active.current = controller
    setPhase('pending')
    setConfirmed(false)
    try {
      await api.logoutAll(session.csrf_token, controller.signal)
      if (controller.signal.aborted || active.current !== controller) return
      setPhase('complete')
      onSignedOut('已退出此账号的所有会话（包括当前会话）。密码未修改，请重新登录。')
    } catch (failure) {
      if (controller.signal.aborted || active.current !== controller) return
      if (sessionInvalid(failure) || (failure instanceof ApiError && (failure.status === 401 || failure.status === 403))) {
        setPhase('complete')
        onSignedOut('会话已失效或安全校验未通过。退出所有会话的结果未确认，请重新登录。')
      } else setPhase('unknown')
    } finally {
      if (active.current === controller) submitting.current = false
    }
  }

  return <section className="auth-card" aria-labelledby="session-security-title">
    <p className="eyebrow">账号安全 · 会话管理</p>
    <h2 id="session-security-title">退出所有会话</h2>
    <p className="muted">退出此账号在所有浏览器和设备上的会话，包括当前会话。不修改密码，也不影响其他账号；之后仍可使用现有密码重新登录。</p>
    {phase === 'idle' && <button ref={start} type="button" disabled={disabled} onClick={() => { setConfirmed(false); setPhase('confirm') }}>退出所有会话</button>}
    {(phase === 'confirm' || phase === 'pending') && <div>
      <h3 ref={confirmation} tabIndex={-1}>确认退出此账号的所有会话？</h3>
      <p className="notice warning">当前页面也会退出，未保存的表单内容将丢失。此操作不能撤回，但不会修改密码。</p>
      <label><input type="checkbox" checked={confirmed} disabled={disabled || phase === 'pending'} onChange={(event) => setConfirmed(event.target.checked)} />我确认退出所有会话，包括当前会话，且密码保持不变。</label>
      <div className="section-heading">
        <button type="button" disabled={disabled || phase === 'pending' || !confirmed} onClick={() => void submit()}>{phase === 'pending' ? '正在退出所有会话…' : '确认退出所有会话'}</button>
        <button type="button" disabled={disabled || phase === 'pending'} onClick={() => { setConfirmed(false); setPhase('idle'); queueMicrotask(() => start.current?.focus()) }}>暂不退出</button>
      </div>
      {phase === 'pending' && <output className="field-help">正在等待服务端确认，请勿重复提交。离开页面只会停止本页等待，不保证服务端尚未执行。</output>}
    </div>}
    {phase === 'unknown' && <div className="notice warning" role="alert" tabIndex={-1} ref={alert}>
      <p>{uncertainNotice}</p>
      <button type="button" disabled={disabled} onClick={() => { setPhase('complete'); onSignedOut(`本页已返回登录界面。${uncertainNotice}`) }}>返回登录（结果未确认）</button>
    </div>}
    {phase === 'complete' && <output className="field-help">正在关闭当前会话界面…</output>}
  </section>
}
