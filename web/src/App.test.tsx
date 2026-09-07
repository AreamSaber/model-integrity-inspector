import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { type Session } from './api'
import { StrictMode } from 'react'

const password = 'synthetic-password-123'
const session: Session = {
  user: { id: '9007199254740993', username: 'review-admin', display_name: 'Review Admin', version: 1, status: 'active', system_admin: true, must_change_password: false },
  organizations: [
    { id: '9007199254740995', name: 'Alpha', status: 'active', timezone: 'UTC' },
    { id: '9007199254740997', name: 'Beta', status: 'active', timezone: 'Asia/Shanghai' },
  ],
  csrf_token: 'synthetic-csrf-token', expires_at: new Date(Date.now() + 3600_000).toISOString(),
}
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'request-123' }, { status }) }
function fail(code: string, status: number, headers?: HeadersInit) {
  return Response.json({ error: { code, message: 'PRIVATE-SERVER-DETAIL-never-display' }, request_id: 'request-error' }, { status, headers })
}
function network(handler?: (url: string, options: RequestInit) => Response | Promise<Response> | undefined, authenticated = false) {
  const fetchMock = vi.fn<typeof fetch>(async (input: RequestInfo | URL, options: RequestInit = {}) => {
    const url = String(input)
    const response = handler?.(url, options)
    if (response) return response
    if (url.endsWith('/setup/status')) return ok({ initialized: true })
    if (url.endsWith('/auth/me')) return authenticated ? ok(session) : fail('MI_SESSION_REQUIRED', 401)
    if (url.endsWith('/auth/login')) return ok(session)
    if (url.endsWith('/roles')) return ok({ items: [{ name: 'viewer', permissions: ['target.read'] }], next_cursor: null })
    throw new Error('Unexpected test request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
async function login() {
  const user = userEvent.setup()
  await screen.findByRole('heading', { name: '登录工作空间' })
  await user.type(screen.getByLabelText('用户名'), 'review-admin')
  await user.type(screen.getByLabelText('密码'), password)
  await user.click(screen.getByRole('button', { name: '登录' }))
  await screen.findByRole('heading', { name: '检测总览' })
  return user
}
async function fillSetup() {
  const user = userEvent.setup()
  await screen.findByRole('heading', { name: '初始化工作空间' })
  await user.type(screen.getByLabelText('组织名称'), 'New Org')
  await user.type(screen.getByLabelText('管理员用户名'), 'first-admin')
  await user.type(screen.getByLabelText('密码', { exact: true }), password)
  await user.type(screen.getByLabelText('确认密码'), password)
  return user
}

describe('real API interaction boundary', () => {
  it('initializes with the one-time header, then requires a separate login', async () => {
    const calls = network((url) => {
      if (url.endsWith('/setup/status')) return ok({ initialized: false })
      if (url.endsWith('/setup/initialize')) return ok({ ok: true }, 201)
    })
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    render(<App />)
    const user = await fillSetup()
    expect(document.title).toBe('初始化 · Model Integrity Inspector')
    await user.type(screen.getByLabelText(/一次性初始化令牌/), 'synthetic-setup-token')
    await user.click(screen.getByRole('button', { name: '创建组织和管理员' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(screen.getByRole('status').textContent).toContain('初始化成功')
    expect(document.title).toBe('登录 · Model Integrity Inspector')
    expect(calls).toHaveBeenCalledTimes(2)
    const options = calls.mock.calls[1][1]!
    expect(JSON.parse(options.body as string)).toEqual({ organization_name: 'New Org', username: 'first-admin', password })
    expect(new Headers(options.headers).get('X-Setup-Token')).toBe('synthetic-setup-token')
    expect((screen.getByLabelText('密码') as HTMLInputElement).value).toBe('')
    expect(storage).not.toHaveBeenCalled()
    expect(window.location.href).not.toContain('synthetic')
  })

  it('rechecks initialization after a concurrent setup conflict', async () => {
    let statusCalls = 0
    const calls = network((url) => {
      if (url.endsWith('/setup/status')) return ok({ initialized: statusCalls++ > 0 })
      if (url.endsWith('/setup/initialize')) return fail('MI_SETUP_CLOSED', 409)
    })
    render(<App />)
    const user = await fillSetup()
    await user.click(screen.getByRole('button', { name: '创建组织和管理员' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(statusCalls).toBe(2)
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/setup/initialize'))).toHaveLength(1)
  })

  it('validates password confirmation and byte limits without a write request', async () => {
    const calls = network((url) => url.endsWith('/setup/status') ? ok({ initialized: false }) : undefined)
    render(<App />)
    await fillSetup()
    fireEvent.change(screen.getByLabelText('组织名称'), { target: { value: '中'.repeat(50) } })
    fireEvent.change(screen.getByLabelText('确认密码'), { target: { value: 'different' } })
    fireEvent.submit(screen.getByRole('form', { name: '初始化工作空间' }))
    expect(await screen.findByText('两次密码输入不一致。')).toBeTruthy()
    expect(screen.getByLabelText('组织名称').getAttribute('aria-invalid')).toBe('true')
    expect(document.activeElement).toBe(screen.getByLabelText('组织名称'))
    expect(calls).toHaveBeenCalledTimes(1)
  })

  it('logs in and logs out with cookie credentials and session-bound CSRF', async () => {
    const calls = network((url) => url.endsWith('/auth/logout') ? ok({ ok: true }) : undefined)
    render(<App />)
    const user = await login()
    expect((screen.getByLabelText('当前组织') as HTMLSelectElement).value).toBe('9007199254740995')
    await user.click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    const options = calls.mock.calls.find(([url]) => String(url).endsWith('/auth/logout'))![1]!
    expect(options.credentials).toBe('same-origin')
    expect(options.redirect).toBe('error')
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(session.csrf_token)
    expect(new Headers(options.headers).has('Origin')).toBe(false)
    expect(new Headers(options.headers).has('Authorization')).toBe(false)
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0)
  })

  it('recovers an existing session without submitting credentials and preserves safe navigation', async () => {
    window.history.replaceState(null, '', '/#/reports')
    const calls = network((url) => url === '/api/v1/runs?limit=25' ? ok({ items: [], next_cursor: null }) : undefined, true)
    render(<App />)
    await screen.findByRole('heading', { name: '结果与报告' })
    await screen.findByText(/没有符合条件的检测任务/)
    expect(screen.getByText(/报告生成、导出和正式审核尚未接入/)).toBeTruthy()
    expect(calls).toHaveBeenCalledTimes(3)
    const read = calls.mock.calls.find(([url]) => String(url).startsWith('/api/v1/runs?'))![1]!
    expect(read.method).toBe('GET')
    expect(new Headers(read.headers).get('X-Organization-ID')).toBe(session.organizations[0].id)
  })

  it('sanitizes login failures, clears the password, and displays retry-after', async () => {
    network((url) => url.endsWith('/auth/login') ? fail('MI_RATE_LIMITED', 429, { 'Retry-After': '60' }) : undefined)
    render(<App />)
    const user = userEvent.setup()
    await screen.findByRole('heading', { name: '登录工作空间' })
    await user.type(screen.getByLabelText('用户名'), 'review-admin')
    await user.type(screen.getByLabelText('密码'), password)
    await user.click(screen.getByRole('button', { name: '登录' }))
    expect((await screen.findByRole('alert')).textContent).toContain('请求过于频繁')
    expect(document.body.textContent).not.toContain('PRIVATE-SERVER-DETAIL')
    expect((screen.getByLabelText('密码') as HTMLInputElement).value).toBe('')
    expect((screen.getByRole('button', { name: /秒后可重试/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('blocks duplicate pending login submissions', async () => {
    let resolveLogin!: (value: Response) => void
    const calls = network((url) => url.endsWith('/auth/login') ? new Promise<Response>((resolve) => { resolveLogin = resolve }) : undefined)
    render(<App />)
    await screen.findByRole('heading', { name: '登录工作空间' })
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'review-admin' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: password } })
    const form = screen.getByRole('form', { name: '登录工作空间' })
    fireEvent.submit(form)
    fireEvent.submit(form)
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/auth/login'))).toHaveLength(1)
    await act(async () => resolveLogin(ok(session)))
    await screen.findByRole('heading', { name: '检测总览' })
  })

  it('switches string organization IDs and discards stale responses from the prior organization', async () => {
    let resolveAlpha!: (value: Response) => void
    const calls = network((url, options) => {
      if (!url.endsWith('/roles')) return undefined
      return new Headers(options.headers).get('X-Organization-ID') === session.organizations[0].id
        ? new Promise<Response>((resolve) => { resolveAlpha = resolve })
        : ok({ items: [{ name: 'beta-role', permissions: ['beta.read'] }], next_cursor: null })
    }, true)
    render(<App />)
    await screen.findByRole('heading', { name: '检测总览' })
    const user = userEvent.setup()
    await user.click(screen.getByRole('link', { name: '组织与角色' }))
    await waitFor(() => expect(resolveAlpha).toBeTypeOf('function'))
    await user.selectOptions(screen.getByLabelText('当前组织'), session.organizations[1].id)
    expect(await screen.findByText('beta-role')).toBeTruthy()
    await act(async () => resolveAlpha(ok({ items: [{ name: 'stale-alpha', permissions: [] }], next_cursor: null })))
    expect(screen.queryByText('stale-alpha')).toBeNull()
    const first = calls.mock.calls.find(([url, options]) => String(url).endsWith('/roles') && new Headers(options?.headers).get('X-Organization-ID') === session.organizations[0].id)!
    expect(first[1]?.signal?.aborted).toBe(true)
  })

  it('shows role permission denial without pretending there are no roles', async () => {
    network((url) => url.endsWith('/roles') ? fail('MI_PERMISSION_DENIED', 403) : undefined, true)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    expect((await screen.findByRole('alert')).textContent).toContain('没有执行此操作的权限')
    expect(screen.queryByText('服务端未返回角色定义。')).toBeNull()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('handles an empty organization list without fabricated records or role requests', async () => {
    const calls = network((url) => url.endsWith('/auth/me') ? ok({ ...session, organizations: [] }) : undefined)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    expect(await screen.findByText('当前账号没有可访问的组织，请联系管理员分配成员权限。')).toBeTruthy()
    expect(within(screen.getByLabelText('当前组织')).getAllByRole('option')).toHaveLength(1)
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/roles'))).toBe(false)
  })

  it('retains the previous role list with a stale warning when refresh fails', async () => {
    let roleRequests = 0
    network((url) => url.endsWith('/roles') && roleRequests++ > 0 ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined, true)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByText('viewer')
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新角色' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText('viewer')).toBeTruthy()
    expect(screen.getByText(/下方保留上次成功加载的目录/)).toBeTruthy()
  })

  it('returns to login on role session expiry without losing the route', async () => {
    network((url) => url.endsWith('/roles') ? fail('MI_SESSION_REQUIRED', 401) : undefined, true)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(window.location.hash).toBe('#/organizations')
    expect(screen.getByRole('status').textContent).toContain('会话已失效')
  })

  it('changes password using CSRF then requires reauthentication', async () => {
    const calls = network((url) => url.endsWith('/auth/change-password') ? ok({ ok: true }) : undefined, true)
    window.history.replaceState(null, '', '/#/account')
    render(<App />)
    await screen.findByLabelText('当前密码')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('当前密码'), password)
    await user.type(screen.getByLabelText('新密码'), 'new-synthetic-password')
    await user.type(screen.getByLabelText('确认密码'), 'new-synthetic-password')
    await user.click(screen.getByRole('button', { name: '修改密码并重新登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(screen.getByRole('status').textContent).toContain('所有会话已失效')
    const options = calls.mock.calls.find(([url]) => String(url).endsWith('/auth/change-password'))![1]!
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(session.csrf_token)
    expect(JSON.parse(options.body as string)).toEqual({ current_password: password, new_password: 'new-synthetic-password' })
  })

  it('shows a retryable startup failure instead of opening setup on an unavailable service', async () => {
    let count = 0
    network((url) => url.endsWith('/setup/status') && count++ === 0 ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    render(<App />)
    await screen.findByRole('heading', { name: '暂时无法打开工作空间' })
    expect(screen.queryByRole('form')).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: '重试连接' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
  })

  it('does not claim logout succeeded when the network fails', async () => {
    network((url) => url.endsWith('/auth/logout') ? Promise.reject(new Error('sensitive-url')) : undefined, true)
    render(<App />)
    await screen.findByRole('heading', { name: '检测总览' })
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    expect((await screen.findByRole('alert')).textContent).toContain('无法连接服务')
    expect(screen.queryByRole('heading', { name: '登录工作空间' })).toBeNull()
    expect(document.body.textContent).not.toContain('sensitive-url')
  })

  it('expires the in-memory session at the server-provided deadline', async () => {
    vi.useFakeTimers()
    network((url) => url.endsWith('/auth/me') ? ok({ ...session, expires_at: new Date(Date.now() + 1000).toISOString() }) : undefined)
    await act(async () => { render(<App />) })
    expect(screen.getByRole('heading', { name: '检测总览' })).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(1001) })
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(screen.getByRole('status').textContent).toContain('会话已过期')
    expect(document.title).toBe('登录 · Model Integrity Inspector')
  })

  it('supports keyboard-only login and skip navigation without corrupting the route', async () => {
    network()
    render(<App />)
    await screen.findByRole('heading', { name: '登录工作空间' })
    const user = userEvent.setup()
    await user.tab()
    expect(document.activeElement).toBe(screen.getByLabelText('用户名'))
    await user.keyboard('review-admin')
    await user.tab()
    expect(document.activeElement).toBe(screen.getByLabelText('密码'))
    await user.keyboard(password)
    await user.keyboard('{Enter}')
    await screen.findByRole('heading', { name: '检测总览' })
    screen.getByRole('link', { name: '跳转到主要内容' }).focus()
    await user.keyboard('{Enter}')
    expect(document.activeElement).toBe(screen.getByRole('main'))
    expect(screen.getByRole('heading', { name: '检测总览' })).toBeTruthy()
    expect(window.location.hash).not.toBe('#main-content')
  })

  it('focuses a failed login alert and associates field errors with their inputs', async () => {
    network((url) => url.endsWith('/auth/login') ? fail('MI_LOGIN_FAILED', 401) : undefined)
    render(<App />)
    await screen.findByRole('heading', { name: '登录工作空间' })
    fireEvent.submit(screen.getByRole('form', { name: '登录工作空间' }))
    expect(screen.getByLabelText('用户名').getAttribute('aria-describedby')).toBe('username-error')
    expect(screen.getByLabelText('密码').getAttribute('aria-describedby')).toBe('password-error')
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'review-admin' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: password } })
    fireEvent.submit(screen.getByRole('form', { name: '登录工作空间' }))
    expect(await screen.findByRole('alert')).toBe(document.activeElement)
  })

  it('returns to login on CSRF rejection without retrying the write', async () => {
    const calls = network((url) => url.endsWith('/auth/logout') ? fail('MI_CSRF_INVALID', 403) : undefined, true)
    render(<App />)
    await screen.findByRole('heading', { name: '检测总览' })
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(screen.getByRole('status').textContent).toContain('安全校验未通过')
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/auth/logout'))).toHaveLength(1)
  })

  it('keeps the authenticated account page on a wrong current password, clearing all password fields', async () => {
    network((url) => url.endsWith('/auth/change-password') ? fail('MI_LOGIN_FAILED', 401) : undefined, true)
    window.history.replaceState(null, '', '/#/account')
    render(<App />)
    await screen.findByLabelText('当前密码')
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'wrong-current-password' } })
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: password } })
    fireEvent.change(screen.getByLabelText('确认密码'), { target: { value: password } })
    fireEvent.submit(screen.getByRole('form', { name: '修改密码' }))
    expect((await screen.findByRole('alert')).textContent).toContain('用户名或密码不正确')
    expect(screen.queryByRole('heading', { name: '登录工作空间' })).toBeNull()
    for (const label of ['当前密码', '新密码', '确认密码']) expect((screen.getByLabelText(label) as HTMLInputElement).value).toBe('')
  })

  it('does not request roles for a disabled organization', async () => {
    const calls = network((url) => url.endsWith('/auth/me') ? ok({ ...session, organizations: [{ ...session.organizations[0], status: 'disabled' }] }) : undefined)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByText('请选择一个启用的组织以查看角色目录。')
    expect((screen.getByRole('option', { name: 'Alpha（已停用）' }) as HTMLOptionElement).disabled).toBe(true)
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/roles'))).toBe(false)
  })

  it('survives development StrictMode request cancellation without duplicate mutations', async () => {
    const calls = network(undefined, true)
    render(<StrictMode><App /></StrictMode>)
    await screen.findByRole('heading', { name: '检测总览' })
    expect(calls.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
  })

  it('gates temporary-password sessions before mounting any business navigation or requesting roles', async () => {
    const calls = network((url) => url.endsWith('/auth/me') ? ok({ ...session, user: { ...session.user, must_change_password: true } }) : undefined)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByLabelText('当前密码')
    expect(screen.getByText(/仅可修改密码或退出登录/)).toBeTruthy()
    expect(document.title).toBe('必须修改密码 · Model Integrity Inspector')
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.queryByLabelText('当前组织')).toBeNull()
    expect(screen.queryByText('Alpha')).toBeNull()
    expect(calls).toHaveBeenCalledTimes(2)
    await act(async () => { window.location.hash = '#/runs' })
    expect(screen.getByRole('form', { name: '修改密码' })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '检测任务' })).toBeNull()
    expect(document.title).toBe('必须修改密码 · Model Integrity Inspector')
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/roles'))).toBe(false)
  })

  it('honors mandatory-password flags returned by login, then clears the session after changing password', async () => {
    const calls = network((url) => {
      if (url.endsWith('/auth/login')) return ok({ ...session, user: { ...session.user, must_change_password: true } })
      if (url.endsWith('/auth/change-password')) return ok({ ok: true })
    })
    render(<App />)
    await screen.findByRole('heading', { name: '登录工作空间' })
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'review-admin' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: password } })
    fireEvent.submit(screen.getByRole('form', { name: '登录工作空间' }))
    await screen.findByLabelText('当前密码')
    expect(screen.queryByRole('navigation')).toBeNull()
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: password } })
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'new-synthetic-password' } })
    fireEvent.change(screen.getByLabelText('确认密码'), { target: { value: 'new-synthetic-password' } })
    fireEvent.submit(screen.getByRole('form', { name: '修改密码' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(screen.getByRole('status').textContent).toContain('所有会话已失效')
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/roles'))).toBe(false)
    expect((screen.getByLabelText('密码') as HTMLInputElement).value).toBe('')
  })

  it('permits logout from the forced-password page using the current CSRF token', async () => {
    const calls = network((url) => {
      if (url.endsWith('/auth/me')) return ok({ ...session, user: { ...session.user, must_change_password: true } })
      if (url.endsWith('/auth/logout')) return ok({ ok: true })
    })
    render(<App />)
    await screen.findByLabelText('当前密码')
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    const options = calls.mock.calls.find(([url]) => String(url).endsWith('/auth/logout'))![1]!
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(session.csrf_token)
  })

  it('unmounts the business view and recovers me on password-required 403 without replaying roles', async () => {
    let sessionRequests = 0
    let resolveRecovery!: (response: Response) => void
    const calls = network((url) => {
      if (url.endsWith('/auth/me')) return sessionRequests++ === 0 ? ok(session) : new Promise<Response>((resolve) => { resolveRecovery = resolve })
      if (url.endsWith('/roles')) return fail('MI_PASSWORD_CHANGE_REQUIRED', 403)
    })
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByText('正在重新读取会话…')
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.queryByLabelText('当前组织')).toBeNull()
    await act(async () => resolveRecovery(ok({ ...session, csrf_token: 'refreshed-csrf', user: { ...session.user, must_change_password: true } })))
    await screen.findByLabelText('当前密码')
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/roles'))).toHaveLength(1)
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/auth/me'))).toHaveLength(2)
  })

  it('keeps the gate closed when me refresh fails, then allows explicit session-only retry', async () => {
    let sessionRequests = 0
    const calls = network((url) => {
      if (url.endsWith('/auth/me')) {
        sessionRequests++
        if (sessionRequests === 1) return ok(session)
        if (sessionRequests === 2) return fail('MI_SERVICE_UNAVAILABLE', 503)
        return ok({ ...session, user: { ...session.user, must_change_password: true } })
      }
      if (url.endsWith('/roles')) return fail('MI_PASSWORD_CHANGE_REQUIRED', 403)
    })
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByRole('alert')
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.queryByRole('form')).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: '重新读取会话' }))
    await screen.findByRole('form', { name: '修改密码' })
    expect(sessionRequests).toBe(3)
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/roles'))).toHaveLength(1)
  })

  it('does not reopen business UI on inconsistent password-required and me flag responses', async () => {
    const calls = network((url) => url.endsWith('/roles') ? fail('MI_PASSWORD_CHANGE_REQUIRED', 403) : undefined, true)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    expect((await screen.findByRole('alert')).textContent).toContain('会话状态尚未同步')
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.queryByLabelText('当前组织')).toBeNull()
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/roles'))).toHaveLength(1)
  })

  it('does not automatically retry a denied authenticated write after recovering the session', async () => {
    let sessionRequests = 0
    const calls = network((url) => {
      if (url.endsWith('/auth/me')) return ok(sessionRequests++ === 0 ? session : { ...session, user: { ...session.user, must_change_password: true } })
      if (url.endsWith('/auth/logout')) return fail('MI_PASSWORD_CHANGE_REQUIRED', 403)
    })
    render(<App />)
    await screen.findByRole('heading', { name: '检测总览' })
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('form', { name: '修改密码' })
    expect(calls.mock.calls.filter(([url]) => String(url).endsWith('/auth/logout'))).toHaveLength(1)
    expect(sessionRequests).toBe(2)
  })

  it('resets the document title after logging out from an organization route', async () => {
    network((url) => url.endsWith('/auth/logout') ? ok({ ok: true }) : undefined, true)
    window.history.replaceState(null, '', '/#/organizations')
    render(<App />)
    await screen.findByRole('heading', { name: '组织与角色' })
    expect(document.title).toBe('组织与角色 · Model Integrity Inspector')
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(document.title).toBe('登录 · Model Integrity Inspector')
    expect(window.location.hash).toBe('#/organizations')
  })
})
