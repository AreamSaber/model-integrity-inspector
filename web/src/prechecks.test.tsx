import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import type { Session } from './api'
import { checkNames, precheck, prechecksApi, type Precheck } from './prechecks-api'
import type { Target } from './targets-api'

const org = '9007199254740995', secondOrg = '9007199254740997', targetID = '9007199254741001'
const precheckID = '9007199254741003', jobID = '9007199254741005', csrf = 'synthetic-precheck-csrf'
const target: Target = { id: targetID, name: 'Controlled target', provider_id: null, model_profile_id: null, endpoint: 'https://upstream.example/v1', protocol: 'openai_chat', model: 'fixture-model', environment: 'staging', channel_id: '', tags: [], options: { max_output_parameter: 'auto', tls_verify: true, timeout_seconds: 180, concurrency: 1, rpm: 60 }, status: 'active', version: 8, secret: { id: '9007199254741009', version: 2, mask: '********test' } }
const queued: Precheck = { id: precheckID, job_id: jobID, target_id: targetID, target_version: 8, version: 1, status: 'queued', request_count: 0, checks: [], error_code: '', max_output_parameter: '', created_at: '2026-09-07T00:00:00Z', started_at: null, checked_at: null }
const passed: Precheck = { ...queued, version: 4, status: 'passed', request_count: 2, checks: checkNames.map((name) => ({ name, status: 'passed' })), max_output_parameter: 'max_tokens', started_at: '2026-09-07T00:00:01Z', checked_at: '2026-09-07T00:00:02Z' }
const session: Session = { user: { id: '9007199254740993', username: 'admin', status: 'active', system_admin: true, must_change_password: false, display_name: '', version: 1 }, organizations: [{ id: org, name: 'Alpha', status: 'active' }, { id: secondOrg, name: 'Beta', status: 'active' }], csrf_token: csrf, expires_at: new Date(Date.now() + 3600_000).toISOString() }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'precheck-request' }, { status }) }
function fail(code: string, status = 409) { return Response.json({ error: { code, message: 'private-upstream-message-never-render' }, request_id: 'precheck-error' }, { status }) }
type Handler = (path: string, options: RequestInit, url: URL) => Response | Promise<Response> | undefined
function network(handler?: Handler) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), path = url.pathname
    const override = handler?.(path, options, url)
    if (override) return override
    if (path.endsWith('/setup/status')) return ok({ initialized: true })
    if (path.endsWith('/auth/me')) return ok(session)
    if (path.endsWith('/auth/logout')) return ok({ ok: true })
    if (path === '/api/v1/targets') return ok({ items: [target], next_cursor: null })
    if (path === `/api/v1/targets/${targetID}`) return ok(target)
    if (path.endsWith('/precheck')) return options.method === 'POST' ? ok(queued, 202) : ok(passed)
    if (path.endsWith(`/prechecks/${precheckID}`)) return ok(passed)
    throw new Error('Unexpected precheck test route')
  })
  vi.stubGlobal('fetch', calls)
  return calls
}
function renderTargets() { window.history.replaceState(null, '', '/#/targets'); return render(<App />) }
async function openPanel() {
  await screen.findByText('Controlled target')
  await userEvent.setup().click(screen.getByRole('button', { name: '预检 Controlled target' }))
  await screen.findByRole('heading', { name: '目标预检：Controlled target' })
}
async function submit() {
  fireEvent.click(screen.getByRole('checkbox', { name: /我确认向此目标/ }))
  await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '确认目标预检' })) })
}
function posts(calls: ReturnType<typeof network>) { return calls.mock.calls.filter(([, options]) => options?.method === 'POST') }
function polls(calls: ReturnType<typeof network>) { return calls.mock.calls.filter(([url]) => String(url).includes('/prechecks/')) }

describe('explicit bounded target precheck workflow', () => {
  it('does not precheck on list/open and requires explicit acknowledgement of cost before posting', async () => {
    const calls = network(); renderTargets(); await openPanel()
    expect(posts(calls)).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/precheck'))).toBe(false)
    fireEvent.submit(screen.getByRole('form', { name: '确认目标预检' }))
    await screen.findByText('请先确认预检会向该目标发起请求，且可能产生上游费用。')
    expect(posts(calls)).toHaveLength(0)
    expect((screen.getByRole('button', { name: '发起检测（尚未接入）' }) as HTMLButtonElement).disabled).toBe(true)
  })
  it('posts the fresh target version with CSRF/org/fixed idempotency key and tracks its precise precheck ID', async () => {
    const calls = network((path) => path === `/api/v1/targets/${targetID}` ? ok({ ...target, version: 10 }) : undefined)
    // Override the synthetic enqueue/poll versions to match the fresh GET.
    const original = globalThis.fetch
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(async (input, options) => {
      const response = await original(input, options)
      if (String(input).includes('/precheck')) {
        const json = await response.json(); json.data.target_version = 10
        return Response.json(json, { status: response.status })
      }
      return response
    }))
    renderTargets(); await openPanel(); await submit()
    await screen.findByRole('heading', { name: '本次提交的预检：通过' })
    const post = posts(calls)[0]
    expect(JSON.parse(post[1]!.body as string)).toEqual({ version: 10 })
    const headers = new Headers(post[1]!.headers)
    expect(headers.get('X-Organization-ID')).toBe(org); expect(headers.get('X-CSRF-Token')).toBe(csrf)
    expect(headers.get('Idempotency-Key')).toMatch(/^mii-[a-f0-9-]{36}$/)
    expect(String(polls(calls)[0][0])).toBe(`/api/v1/targets/${targetID}/prechecks/${precheckID}`)
    expect(calls.mock.calls.filter(([url, options]) => String(url).endsWith('/precheck') && options?.method === 'GET')).toHaveLength(0)
    expect(screen.getByText('预检能力检查通过，不是模型真实性或完整性结论。')).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '本次提交的预检：通过' }))
  })
  it('never automatically replays an uncertain POST; explicit retry retains the exact same key and body', async () => {
    let attempt = 0
    const calls = network((path, options) => path.endsWith('/precheck') && options.method === 'POST' && ++attempt === 1 ? Promise.reject(new TypeError('synthetic lost response')) : undefined)
    renderTargets(); await openPanel(); await submit()
    await screen.findByRole('button', { name: '使用同一请求标识重试确认' })
    expect(posts(calls)).toHaveLength(1)
    expect((screen.getByRole('button', { name: '查看最近一次预检（只读）' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.submit(screen.getByRole('form', { name: '确认目标预检' }))
    await screen.findByRole('heading', { name: '本次提交的预检：通过' })
    const writes = posts(calls)
    expect(writes).toHaveLength(2)
    expect(writes[0][1]?.body).toBe(writes[1][1]?.body)
    expect(new Headers(writes[0][1]?.headers).get('Idempotency-Key')).toBe(new Headers(writes[1][1]?.headers).get('Idempotency-Key'))
    expect(document.body.textContent).not.toContain('synthetic lost response')
  })
  it('prevents duplicate submissions while the request is pending and aborts when leaving the panel', async () => {
    let resolve: ((response: Response) => void) | undefined
    const calls = network((path, options) => path.endsWith('/precheck') && options.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderTargets(); await openPanel(); await submit()
    fireEvent.submit(screen.getByRole('form', { name: '确认目标预检' }))
    expect(posts(calls)).toHaveLength(1)
    await userEvent.setup().click(screen.getByRole('button', { name: '返回目标列表' }))
    expect(posts(calls)[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(ok(queued, 202)) })
    expect(screen.queryByRole('heading', { name: /本次提交的预检/ })).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织检测目标' }))
  })
  it('polls only the pinned ID, stops at terminal status, and displays fixed safe failure classifications', async () => {
    let reads = 0
    const calls = network((path) => path.includes('/prechecks/') ? ok(++reads === 1 ? { ...queued, status: 'running', version: 2, request_count: 1 } : { ...queued, status: 'failed', version: 3, request_count: 1, error_code: 'MI_AUTH_FAILED', checks: [{ name: 'authentication', status: 'failed', error_code: 'MI_AUTH_FAILED' }] }) : undefined)
    renderTargets(); await openPanel(); vi.useFakeTimers(); await submit()
    expect(polls(calls)).toHaveLength(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(screen.getByRole('heading', { name: '本次提交的预检：失败' })).toBeTruthy()
    expect(screen.getAllByText('上游认证失败，请检查凭证。').length).toBeGreaterThan(0)
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(polls(calls)).toHaveLength(2); expect(posts(calls)).toHaveLength(1)
  })
  it('stops polling on read failures and resumes only manually against the same ID', async () => {
    let reads = 0
    const calls = network((path) => path.includes('/prechecks/') && ++reads === 1 ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    renderTargets(); await openPanel(); vi.useFakeTimers(); await submit()
    expect(screen.getByText('服务暂不可用，请稍后重试。')).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(polls(calls)).toHaveLength(1)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '重新读取此预检' })) })
    expect(screen.getByRole('heading', { name: '本次提交的预检：通过' })).toBeTruthy()
    expect(posts(calls)).toHaveLength(1)
    expect(new Set(polls(calls).map(([url]) => String(url))).size).toBe(1)
  })
  it('pins job ID and target snapshot, rejecting a different logical job returned under the same precheck URL', async () => {
    const calls = network((path) => path.includes('/prechecks/') ? ok({ ...passed, job_id: '9007199254741011' }) : undefined)
    renderTargets(); await openPanel(); await submit()
    await screen.findByText('服务响应格式异常，请联系管理员。')
    expect(screen.queryByRole('heading', { name: '本次提交的预检：通过' })).toBeNull()
    expect(polls(calls)).toHaveLength(1)
  })
  it('rejects a regressing record version instead of rolling progress backwards', async () => {
    let reads = 0
    network((path) => path.includes('/prechecks/') ? ok(++reads === 1 ? { ...queued, status: 'running', version: 3 } : { ...queued, version: 2 }) : undefined)
    renderTargets(); await openPanel(); vi.useFakeTimers(); await submit()
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(screen.getByRole('heading', { name: '本次提交的预检：执行中' })).toBeTruthy()
    expect(screen.getByText('服务响应格式异常，请联系管理员。')).toBeTruthy()
  })
  it('cancels polling on organization change and ignores an old in-flight response', async () => {
    let resolve: ((response: Response) => void) | undefined
    const calls = network((path) => path.includes('/prechecks/') ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderTargets(); await openPanel(); await submit()
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), secondOrg)
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(ok(passed)) })
    expect(screen.queryByRole('heading', { name: /本次提交的预检/ })).toBeNull()
  })
  it('cancels polling when the session expires', async () => {
    vi.useFakeTimers()
    const calls = network((path) => path.includes('/prechecks/') ? new Promise<Response>(() => {}) : path.endsWith('/auth/me') ? ok({ ...session, expires_at: new Date(Date.now() + 60000).toISOString() }) : undefined)
    await act(async () => { renderTargets() })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '预检 Controlled target' })) })
    await submit()
    await act(async () => { await vi.advanceTimersByTimeAsync(60001) })
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
  })
  it('cancels polling on logout without trying to cancel or recreate the backend job', async () => {
    const calls = network((path) => path.includes('/prechecks/') ? new Promise<Response>(() => {}) : undefined)
    renderTargets(); await openPanel(); await submit()
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
    expect(posts(calls).map(([url]) => String(url))).toEqual([`/api/v1/targets/${targetID}/precheck`, '/api/v1/auth/logout'])
  })
  it('enters the forced password-change gate on polling authorization changes without replaying the precheck', async () => {
    let me = 0
    const calls = network((path) => path.includes('/prechecks/') ? fail('MI_PASSWORD_CHANGE_REQUIRED', 403) : path.endsWith('/auth/me') ? ok(++me === 1 ? session : { ...session, user: { ...session.user, must_change_password: true } }) : undefined)
    renderTargets(); await openPanel(); await submit()
    await screen.findByRole('heading', { name: '修改密码' })
    expect(screen.queryByLabelText('当前组织')).toBeNull()
    expect(posts(calls)).toHaveLength(1)
  })
  it('reads the latest record only after explicit choice, labels it separately and never POSTs', async () => {
    const calls = network((path, options) => path.endsWith('/precheck') && options.method === 'GET' ? ok({ ...passed, target_version: 7 }) : undefined)
    renderTargets(); await openPanel()
    await userEvent.setup().click(screen.getByRole('button', { name: '查看最近一次预检（只读）' }))
    await screen.findByRole('heading', { name: '最近记录（非本次提交）：通过' })
    expect(screen.getByText('此记录对应不同目标版本，不能作为本页配置的预检结果；请重新读取目标。')).toBeTruthy()
    expect(posts(calls)).toHaveLength(0)
    expect(polls(calls)).toHaveLength(0)
  })
  it('shows a truthful empty latest result without interpreting 404 as a successful precheck', async () => {
    const calls = network((path, options) => path.endsWith('/precheck') && options.method === 'GET' ? fail('MI_NOT_FOUND', 404) : undefined)
    renderTargets(); await openPanel(); await userEvent.setup().click(screen.getByRole('button', { name: '查看最近一次预检（只读）' }))
    await screen.findByText('未找到该目标可读取的预检记录；本次查看不会发起上游请求。')
    expect(posts(calls)).toHaveLength(0)
  })
  it('keeps definitive version conflicts manual and never leaks server messages', async () => {
    const calls = network((path, options) => path.endsWith('/precheck') && options.method === 'POST' ? fail('MI_VERSION_CONFLICT') : undefined)
    renderTargets(); await openPanel(); await submit()
    await screen.findByRole('button', { name: '重新读取目标版本' })
    expect(posts(calls)).toHaveLength(1)
    expect(document.body.textContent).not.toContain('private-upstream-message-never-render')
    expect(screen.queryByRole('button', { name: '使用同一请求标识重试确认' })).toBeNull()
  })
  it('does not dispatch without secure request-key generation or falsely report an uncertain queued task', async () => {
    const calls = network()
    vi.spyOn(crypto, 'randomUUID').mockImplementation(() => { throw new Error('no secure randomness') })
    renderTargets(); await openPanel(); await submit()
    await screen.findByText('操作失败，请稍后重试。')
    expect(posts(calls)).toHaveLength(0)
    expect(screen.queryByRole('button', { name: '使用同一请求标识重试确认' })).toBeNull()
  })
  it('pauses after the bounded polling budget without declaring failure or issuing a second POST', async () => {
    const calls = network((path) => path.includes('/prechecks/') ? ok(queued) : undefined)
    renderTargets(); await openPanel(); vi.useFakeTimers(); await submit()
    await act(async () => { await vi.advanceTimersByTimeAsync(900000) })
    expect(polls(calls)).toHaveLength(300)
    expect(screen.getByText('已达到本页自动读取次数上限，暂停读取；这不表示后台失败。')).toBeTruthy()
    expect(posts(calls)).toHaveLength(1)
  })
})

describe('closed precheck DTO contract', () => {
  it('accepts real queued/passed DTOs but rejects false success, non-string IDs, excessive budget and secret/raw fields', () => {
    expect(precheck(queued)).toBe(true); expect(precheck(passed)).toBe(true)
    for (const patch of [{ id: Number(precheckID) }, { target_version: '8' }, { status: ['passed'] }, { request_count: 4 }, { request_count: -1 }, { checks: [] }, { checks: [...passed.checks, passed.checks[0]] }, { max_output_parameter: '' }, { max_output_parameter: ['max_tokens'] }, { checked_at: null }, { headers: { Authorization: 'secret' } }, { error_code: 'private-upstream-error' }]) expect(precheck({ ...passed, ...patch })).toBe(false)
    expect(precheck({ ...queued, checks: [{ name: 'raw-upstream-body', status: 'passed' }] })).toBe(false)
    expect(precheck({ ...queued, status: 'failed', error_code: 'MI_UNCERTAIN_ATTEMPT' })).toBe(true)
  })
  it('rejects responses for another target/precheck and refuses invalid request identities before fetching', async () => {
    const calls = network((path) => path.includes('/prechecks/') ? ok({ ...passed, id: '9007199254741011' }) : path.endsWith('/precheck') ? ok({ ...queued, target_id: '9007199254741011' }) : undefined)
    await expect(prechecksApi.enqueue(org, csrf, targetID, 8, 'test-key')).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    await expect(prechecksApi.get(org, targetID, precheckID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(() => prechecksApi.enqueue(org, csrf, targetID, 0, 'test-key')).toThrow('MI_INVALID_REQUEST')
    expect(() => prechecksApi.get(org, targetID, '../other')).toThrow('MI_INVALID_REQUEST')
    expect(calls).toHaveBeenCalledTimes(2)
  })
})

describe('server target filtering', () => {
  it('sends all filter fields to the real API and binds the same filters to page navigation', async () => {
    const calls = network((path, _, url) => path === '/api/v1/targets' ? ok({ items: [target], next_cursor: url.searchParams.has('cursor') ? null : 'signed-target-cursor' }) : undefined)
    renderTargets(); await screen.findByText('Controlled target')
    fireEvent.change(screen.getByLabelText('搜索名称、模型或渠道'), { target: { value: 'model_% &' } })
    fireEvent.change(screen.getByLabelText('精确模型名称'), { target: { value: 'exact-model' } })
    fireEvent.change(screen.getByLabelText('精确环境'), { target: { value: 'staging' } })
    await userEvent.setup().selectOptions(screen.getByLabelText('目标状态'), 'active')
    fireEvent.submit(screen.getByRole('form', { name: '筛选目标' }))
    await waitFor(() => expect(calls.mock.calls.some(([url]) => String(url).includes('q=model_%25+%26'))).toBe(true))
    await waitFor(() => expect((screen.getByRole('button', { name: '下一页' }) as HTMLButtonElement).disabled).toBe(false))
    await userEvent.setup().click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByText('第 2 页')
    const url = new URL(String(calls.mock.calls.at(-1)![0]), 'http://localhost')
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: '25', cursor: 'signed-target-cursor', q: 'model_% &', model: 'exact-model', environment: 'staging', status: 'active' })
    expect(screen.getByText('Controlled target')).toBeTruthy() // Deliberately not filtered client-side.
    await userEvent.setup().click(screen.getByRole('button', { name: '清空筛选' }))
    await screen.findByText('第 1 页')
    expect((screen.getByLabelText('精确模型名称') as HTMLInputElement).value).toBe('')
    await waitFor(() => expect(String(calls.mock.calls.at(-1)![0])).toBe('/api/v1/targets?limit=25'))
  })
})
