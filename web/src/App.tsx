import { useCallback, useEffect, useState } from 'react'
import { api, sessionInvalid, type Session } from './api'
import { AuthForm } from './components/AuthForms'
import { ErrorNotice, Loading } from './components/Feedback'
import { AuthenticatedSession } from './components/AuthenticatedSession'

type State = { view: 'loading' } | { view: 'error'; error: unknown } | { view: 'setup' } | { view: 'login'; notice?: string } | { view: 'session'; session: Session }

export function App() {
  const [state, setState] = useState<State>({ view: 'loading' })
  const [attempt, setAttempt] = useState(0)
  const [startupNotice, setStartupNotice] = useState('')
  const signedOut = useCallback((notice: string) => setState({ view: 'login', notice }), [])
  useEffect(() => {
    if (state.view !== 'session') document.title = `${state.view === 'setup' ? '初始化' : state.view === 'login' ? '登录' : '连接工作空间'} · Model Integrity Inspector`
  }, [state.view])
  useEffect(() => {
    const controller = new AbortController()
    void (async () => {
      try {
        const status = await api.setupStatus(controller.signal)
        if (controller.signal.aborted) return
        if (!status.initialized) { setState({ view: 'setup' }); return }
        try {
          const session = await api.me(controller.signal)
          if (!controller.signal.aborted) setState({ view: 'session', session })
        } catch (error) {
          if (controller.signal.aborted) return
          if (sessionInvalid(error)) setState({ view: 'login', notice: startupNotice })
          else throw error
        }
      } catch (error) {
        if (!controller.signal.aborted) setState({ view: 'error', error })
      }
    })()
    return () => controller.abort()
  }, [attempt, startupNotice])
  if (state.view === 'session') return <AuthenticatedSession key={state.session.user.id} initialSession={state.session} onSignedOut={signedOut} />
  return <main className="auth-shell" id="main-content">
    <div className="brand-block"><span className="brand-mark" aria-hidden="true">M</span><span>Model Integrity Inspector<small>模型 API 完整性检测</small></span></div>
    {state.view === 'loading' && <section className="auth-card"><Loading>正在检查初始化和会话状态…</Loading></section>}
    {state.view === 'error' && <section className="auth-card"><h1>暂时无法打开工作空间</h1><ErrorNotice error={state.error} /><button onClick={() => { setState({ view: 'loading' }); setAttempt((value) => value + 1) }}>重试连接</button></section>}
    {state.view === 'setup' && <AuthForm key="setup" mode="setup" onInitialized={() => signedOut('初始化成功。请使用刚创建的管理员账号登录。')} onSetupConflict={() => { setState({ view: 'loading' }); setStartupNotice('系统已完成初始化。请使用已有账号登录。'); setAttempt((value) => value + 1) }} />}
    {state.view === 'login' && <AuthForm key="login" mode="login" notice={state.notice} onSession={(session) => setState({ view: 'session', session })} />}
    <p className="auth-footer">独立部署 · 组织隔离 · 证据可追溯</p>
  </main>
}
