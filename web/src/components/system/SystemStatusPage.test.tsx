import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { SystemStatusPage } from './SystemStatusPage'
import { fail, ok, org, otherOrg, otherUser, systemFixture, unavailableJobs, userID } from './test-fixtures'

function props() { return { organizationID: org, userID, csrfToken: 'unused-read-only', systemAdmin: true, onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() } }
function network(data = systemFixture()) { const calls = vi.fn<typeof fetch>(async () => ok(data)); vi.stubGlobal('fetch', calls); return calls }
const table = () => screen.findByRole('table', { name: '系统状态的观测来源与局限' })
const refreshButton = () => screen.getByRole('button', { name: '手动刷新系统状态' })
async function refresh() { await act(async () => { fireEvent.click(refreshButton()) }) }

describe('real scoped system status page', () => {
  it('shows partial observations and startup-only limits, never fabricates aggregate health or actions', async () => {
    const calls = network(); render(<SystemStatusPage {...props()} />); const grid = await table()
    expect(within(grid).getAllByRole('row')).toHaveLength(13)
    expect(screen.getByText('已观测项未返回错误；不可观测项仍未知。')).toBeTruthy()
    expect(within(grid).getAllByText('仅启动时校验')).toHaveLength(2)
    expect(within(grid).getAllByText('不可观测')).toHaveLength(5)
    expect(screen.getByText(/未重新探测当前密钥文件/)).toBeTruthy()
    expect(screen.getByText(/未探测当前容量、可写性/)).toBeTruthy()
    expect(screen.getByText(/设置为 0 不代表正文已经停止留存/)).toBeTruthy()
    expect(screen.getByText(/当前写入策略固定 30 天/)).toBeTruthy()
    expect(screen.getByText('本次验证尾部事件数：2')).toBeTruthy()
    expect(screen.getByText(/仅校验当前组织审计头和末尾最多 2 个事件/)).toBeTruthy()
    expect(screen.getByText(/不是 Run 数、调用成功率或独立样本数/)).toBeTruthy()
    expect(screen.getByText(/当前组织：9007199254740995/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: '系统运行状态' })).toBe(document.activeElement)
    expect(screen.getAllByRole('button')).toHaveLength(1); expect(calls).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: /备份|恢复|清理|设置/ })).toBeNull()
  })
  it('shows worker error as degraded and server-only as not applicable, not fake remote failure', async () => {
    const data = systemFixture(); data.observed_state = 'degraded'; Object.assign(data.local_worker, { state: 'error', reason: 'local_runner_not_ready' })
    const calls = network(data); render(<SystemStatusPage {...props()} />); await table()
    expect(screen.getByText('已观测项中存在异常；不可观测项仍未知。')).toBeTruthy()
    expect(screen.getByText(/可能尚未启动或已经停止/)).toBeTruthy()
    const server = systemFixture(); server.process_role = 'server'; Object.assign(server.local_worker, { state: 'not_applicable', reason: 'server_role_has_no_local_worker' })
    calls.mockImplementation(async () => ok(server)); await refresh(); const grid = await table()
    expect(within(grid).getByText('不适用')).toBeTruthy(); expect(screen.queryByText('已观测项中存在异常；不可观测项仍未知。')).toBeNull()
    expect(screen.getByText(/不能据此判断 PostgreSQL Worker 全部正常或离线/)).toBeTruthy()
  })
  it('shows unavailable counts as unknown and a true empty queue as zero with no success-rate inference', async () => {
    const data = systemFixture(); unavailableJobs(data)
    Object.assign(data.organization_audit, { state: 'unavailable', source: 'not_observed', checked_at: null, reason: 'audit_signer_unavailable', verified_tail_events: null, last_event_at: null })
    const calls = network(data); render(<SystemStatusPage {...props()} />); await table()
    const jobs = screen.getByRole('region', { name: '当前组织活动 Job（不是 Run 或样本）' })
    expect(within(jobs).getAllByText('未知 / 无观测')).toHaveLength(5); expect(within(jobs).queryByText('0')).toBeNull()
    expect(screen.getByText('本次验证尾部事件数：未知 / 无观测')).toBeTruthy()
    const empty = systemFixture(); Object.assign(empty.organization_jobs, { total_active_jobs: 0, pending_ready: 0, pending_delayed: 0, running_leased: 0, running_expired: 0 })
    calls.mockImplementation(async () => ok(empty)); await refresh(); await table()
    expect(within(screen.getByRole('region', { name: '当前组织活动 Job（不是 Run 或样本）' })).getAllByText('0')).toHaveLength(5)
    expect(screen.getByText(/不能将空队列解释为系统无故障/)).toBeTruthy()
  })
  it('only performs another read after explicit keyboard refresh and restores accessible focus', async () => {
    const calls = network(); render(<SystemStatusPage {...props()} />); await table()
    refreshButton().focus(); await userEvent.setup().keyboard('{Enter}'); await table()
    expect(calls).toHaveBeenCalledTimes(2); expect(screen.getByRole('heading', { name: '系统运行状态' })).toBe(document.activeElement)
    expect(calls.mock.calls.every(([path, options]) => path === '/api/v1/system/health' && options?.method === 'GET' && options.body === undefined)).toBe(true)
  })
  it.each([['MI_PERMISSION_DENIED', 403], ['MI_SYSTEM_STATUS_BUSY', 429], ['MI_SYSTEM_STATUS_TIMEOUT', 503], ['MI_SERVICE_UNAVAILABLE', 503], ['MI_SETUP_REQUIRED', 409]])('clears prior state on %s and never shows upstream text or retries', async (code, status) => {
    const calls = network(); render(<SystemStatusPage {...props()} />); await table()
    calls.mockImplementation(async () => fail(code, status)); await refresh(); await screen.findByRole('alert')
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('已观测项未返回错误；不可观测项仍未知。')).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_SYSTEM_STATUS_ERROR'); expect(calls).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('alert')).toBe(document.activeElement)
  })
  it('clears old data on network failure and allows one manual recovery', async () => {
    const calls = network(); render(<SystemStatusPage {...props()} />); await table()
    calls.mockRejectedValue(new Error('PRIVATE_SYSTEM_STATUS_ERROR')); await refresh(); await screen.findByRole('alert')
    expect(screen.queryByRole('table')).toBeNull(); expect(document.body.textContent).not.toContain('PRIVATE_SYSTEM_STATUS_ERROR')
    calls.mockImplementation(async () => ok(systemFixture())); await refresh(); await table()
    expect(screen.queryByRole('alert')).toBeNull(); expect(calls).toHaveBeenCalledTimes(3)
  })
  it.each(['MI_SESSION_REQUIRED', 'MI_PASSWORD_CHANGE_REQUIRED'])('clears state and invokes the existing session lifecycle for %s', async (code) => {
    const context = props(), calls = network(); render(<SystemStatusPage {...context} />); await table()
    calls.mockImplementation(async () => fail(code, code === 'MI_SESSION_REQUIRED' ? 401 : 403)); await refresh()
    await waitFor(() => expect(code === 'MI_SESSION_REQUIRED' ? context.onSignedOut : context.onPasswordRequired).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('table')).toBeNull(); expect(calls).toHaveBeenCalledTimes(2)
  })
  it.each([401, 403])('invalidates session for malformed %i even without a trustworthy body', async (status) => {
    const context = props(), calls = network(); render(<SystemStatusPage {...context} />); await table()
    calls.mockImplementation(async () => new Response('PRIVATE_SYSTEM_STATUS_ERROR', { status })); await refresh()
    await waitFor(() => expect(context.onSignedOut).toHaveBeenCalledTimes(1)); expect(screen.queryByRole('table')).toBeNull()
  })
  it('a false navigation systemAdmin hint cannot pre-authorize or suppress the real server decision', async () => {
    const calls = network(); render(<SystemStatusPage {...props()} systemAdmin={false} />); await table(); expect(calls).toHaveBeenCalledTimes(1)
    calls.mockImplementation(async () => fail('MI_PERMISSION_DENIED')); await refresh(); await screen.findByRole('alert')
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText(/权限不足或已撤销，已清空状态数据/)).toBeTruthy()
  })
  it.each(['organization', 'user'])('aborts on %s scope switch and ignores a late response', async (scope) => {
    let resolveOld: (response: Response) => void = () => {}
    const calls = vi.fn<typeof fetch>(() => new Promise((resolve) => { resolveOld = resolve })); vi.stubGlobal('fetch', calls)
    const context = props(), rendered = render(<SystemStatusPage {...context} />)
    await waitFor(() => expect(calls).toHaveBeenCalledTimes(1)); const oldSignal = calls.mock.calls[0][1]?.signal
    const next = scope === 'organization' ? { ...context, organizationID: otherOrg } : { ...context, userID: otherUser }
    calls.mockImplementation(async () => ok(systemFixture(next.organizationID, next.userID)))
    rendered.rerender(<SystemStatusPage {...next} />); await table(); expect(oldSignal?.aborted).toBe(true)
    await act(async () => { resolveOld(ok(systemFixture())) })
    expect(screen.getByText(`当前组织：${next.organizationID} · 当前用户：${next.userID}`)).toBeTruthy()
    expect(calls).toHaveBeenCalledTimes(2)
  })
  it('clears displayed organization immediately while the new scope remains pending', async () => {
    const calls = network(), context = props(), rendered = render(<SystemStatusPage {...context} />); await table()
    calls.mockImplementation(() => new Promise(() => {})); rendered.rerender(<SystemStatusPage {...context} organizationID={otherOrg} />)
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('正在验证权限并读取系统状态…')).toBeTruthy()
    expect(screen.queryByText(/当前组织：9007199254740995/)).toBeNull(); rendered.unmount()
    expect(calls.mock.calls[1][1]?.signal?.aborted).toBe(true)
  })
  it('aborts on unmount without firing session callbacks from a late denial', async () => {
    let finish: (response: Response) => void = () => {}
    const calls = vi.fn<typeof fetch>(() => new Promise((resolve) => { finish = resolve })); vi.stubGlobal('fetch', calls)
    const context = props(), rendered = render(<SystemStatusPage {...context} />); await waitFor(() => expect(calls).toHaveBeenCalledTimes(1)); rendered.unmount()
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { finish(fail('MI_SESSION_REQUIRED', 401)) })
    expect(context.onSignedOut).not.toHaveBeenCalled(); expect(context.onPasswordRequired).not.toHaveBeenCalled()
  })
  it('clears previous data before refresh settles and rejects a success body with mismatched identity or unsafe fields', async () => {
    const calls = network(); render(<SystemStatusPage {...props()} />); await table()
    let finish: (response: Response) => void = () => {}
    calls.mockImplementation(() => new Promise((resolve) => { finish = resolve })); await refresh()
    expect(screen.queryByRole('table')).toBeNull(); expect((refreshButton() as HTMLButtonElement).disabled).toBe(true)
    const data = systemFixture(otherOrg); Object.assign(data, { endpoint: 'PRIVATE_SYSTEM_STATUS_ERROR' })
    await act(async () => { finish(ok(data)) }); await screen.findByRole('alert')
    expect(screen.queryByRole('table')).toBeNull(); expect(document.body.textContent).not.toContain('PRIVATE_SYSTEM_STATUS_ERROR')
    expect(calls).toHaveBeenCalledTimes(2)
  })
})
