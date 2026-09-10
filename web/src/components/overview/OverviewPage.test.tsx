import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { OverviewPage } from './OverviewPage'
import { fail, ok, org, otherOrg, overview, userID } from './test-fixtures'
import type { Overview } from '../../overview-api'
import { SessionLayout } from '../SessionLayout'

const props = { organizationID: org, userID, csrfToken: 'unused', onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
function network(value = overview(), override?: (url: string, options: RequestInit) => Response | Promise<Response> | undefined) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = String(input), changed = override?.(url, options); if (changed) return changed
    return ok(url.includes('/auth/permissions') ? { organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: ['run.read', 'target.read'] } : value)
  }); vi.stubGlobal('fetch', calls); return calls
}
const table = () => screen.findByRole('table', { name: '按当地日历日统计（今日未完成）' })
async function refresh() { await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新组织总览' })) }) }
describe('real organization overview UI', () => {
  it('shows counts, nullable estimate and risk denominators without fabricated success rates', async () => {
    const calls = network(); render(<OverviewPage {...props} />); await table()
    expect(screen.getByText('已知部分小计：$1.234567 USD')).toBeTruthy(); expect(screen.getByText('完整窗口估算：未知 / 无观测')).toBeTruthy()
    expect(screen.getByText('费用已知 1 个 Run · 未知 2 个 Run')).toBeTruthy(); expect(screen.getByText('可估 1 · 不可估 1')).toBeTruthy()
    expect(screen.getByText('中等风险信号：1 / 1（100.0%）')).toBeTruthy(); expect(screen.getByText('2026-09-07（未完成日）')).toBeTruthy()
    expect(screen.getByText(/不是历史列表当前页/)).toBeTruthy(); expect(screen.getByText(/重试不增加任务数或独立样本/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: '组织检测统计' })).toBe(document.activeElement)
    expect(calls).toHaveBeenCalledTimes(2); expect(calls.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
    expect(screen.queryByRole('button', { name: /发起|生成报告|导出/ })).toBeNull()
  })
  it('uses true empty-state null costs, not default zeros after failure', async () => {
    network(overview(7, org, false)); render(<OverviewPage {...props} />); await table()
    expect(screen.getByText(/本窗口没有任务/)).toBeTruthy(); expect(screen.getByText('已知部分小计：未知 / 无观测')).toBeTruthy()
    expect(screen.queryByText(/\$0\.000000/)).toBeNull(); expect(screen.getByText(/尚无已发布修订 1/)).toBeTruthy()
  })
  it('renders integer USD micros without losing a least-significant unit at JS max', async () => {
    const data = overview(); data.costs.known_subtotal_micros = Number.MAX_SAFE_INTEGER
    network(data); render(<OverviewPage {...props} />); await table(); expect(screen.getByText('已知部分小计：$9007199254.740991 USD')).toBeTruthy()
  })
  it('switches windows explicitly, aborts old data and performs one new read', async () => {
    const calls = network(overview(), (url) => url.endsWith('/overview?days=30') ? ok(overview(30)) : undefined)
    render(<OverviewPage {...props} />); await table()
    const old = calls.mock.calls[1][1]?.signal
    await act(async () => { fireEvent.change(screen.getByLabelText('日历日窗口'), { target: { value: '30' } }) }); const grid = await table()
    expect(old?.aborted).toBe(true); expect(within(grid).getAllByRole('row')).toHaveLength(31); expect(calls).toHaveBeenCalledTimes(4)
    expect(String(calls.mock.calls[3][0])).toBe('/api/v1/overview?days=30')
  })
  it('refreshes with keyboard, restores focus and clears old statistics on permission revocation', async () => {
    const calls = network(); render(<OverviewPage {...props} />); await table()
    calls.mockImplementation(async () => ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }))
    screen.getByRole('button', { name: '刷新组织总览' }).focus(); await userEvent.setup().keyboard('{Enter}')
    await screen.findByRole('alert'); expect(screen.getByText(/权限不足或已撤销，已清空总览数据/)).toBeTruthy()
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/本窗口没有任务/)).toBeNull(); expect(screen.queryByText(/快照 2026/)).toBeNull()
    expect(calls).toHaveBeenCalledTimes(3); expect(screen.getByRole('alert')).toBe(document.activeElement)
  })
  it.each(['MI_OVERVIEW_BUSY', 'MI_OVERVIEW_LIMIT', 'MI_OVERVIEW_TIMEOUT', 'MI_OVERVIEW_TIMEZONE_INVALID', 'MI_ANALYSIS_RESULT_INVALID'])('fails closed on %s without automatic retry or upstream text', async (code) => {
    const calls = network(); render(<OverviewPage {...props} />); await table()
    calls.mockImplementation(async (input) => String(input).includes('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ['run.read', 'target.read'] }) : fail(code, code === 'MI_OVERVIEW_BUSY' ? 429 : 503))
    await refresh(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/本窗口没有任务/)).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_OVERVIEW_ERROR'); expect(calls).toHaveBeenCalledTimes(4)
  })
  it('cancels on scope change and ignores late responses from the previous organization', async () => {
    let resolveOld!: (value: Response) => void
    const calls = network(overview(), (url, options) => url.includes('/overview?') && new Headers(options.headers).get('X-Organization-ID') === org ? new Promise<Response>((resolve) => { resolveOld = resolve }) : url.includes('/overview?') ? ok(overview(7, otherOrg, false)) : undefined)
    const view = render(<OverviewPage {...props} />); await waitFor(() => expect(calls).toHaveBeenCalledTimes(2))
    const old = calls.mock.calls[1][1]?.signal; view.rerender(<OverviewPage {...props} organizationID={otherOrg} />); await table()
    expect(old?.aborted).toBe(true); expect(screen.getByText(/本窗口没有任务/)).toBeTruthy()
    await act(async () => { resolveOld(ok(overview())) }); expect(screen.queryByText('已知部分小计：$1.234567 USD')).toBeNull()
    const current = calls.mock.calls[3][1]?.signal; view.unmount(); expect(current?.aborted).toBe(true)
  })
  it.each([['MI_SESSION_REQUIRED', 401], ['MI_PASSWORD_CHANGE_REQUIRED', 403]] as const)('propagates %s without keeping statistics', async (code, status) => {
    const signedOut = vi.fn<(notice: string) => void>(), passwordRequired = vi.fn<() => void>(); network(overview(), () => fail(code, status))
    render(<OverviewPage {...props} onSignedOut={signedOut} onPasswordRequired={passwordRequired} />)
    await waitFor(() => expect(code === 'MI_SESSION_REQUIRED' ? signedOut : passwordRequired).toHaveBeenCalledTimes(1)); expect(screen.queryByRole('table')).toBeNull()
  })
  it('rejects invalid response metadata rather than exposing a half view', async () => {
    const data: Overview = overview(); data.runs.total++
    network(data); render(<OverviewPage {...props} />); expect((await screen.findByRole('alert')).textContent).toContain('统计分母不一致'); expect(screen.queryByRole('table')).toBeNull()
  })
  it('mounts the real overview route, and an unselected organization has no network', async () => {
    const calls = network(); const session = { user: { id: userID, username: 'Overview reader', status: 'active' as const, must_change_password: false }, organizations: [{ id: org, name: 'Overview org', status: 'active' as const, timezone: 'UTC' }], csrf_token: 'unused', expires_at: '2026-09-08T00:00:00Z' }
    render(<SessionLayout session={session} onSignedOut={props.onSignedOut} onPasswordRequired={props.onPasswordRequired} />); await table()
    expect(document.title).toBe('检测总览 · Model Integrity Inspector'); expect(screen.queryByText(/聚合统计尚未接入/)).toBeNull()
    await act(async () => { fireEvent.change(screen.getByLabelText('当前组织'), { target: { value: '' } }) })
    expect(screen.getByText('请选择一个启用的组织以读取检测总览。')).toBeTruthy(); expect(screen.queryByRole('table')).toBeNull(); expect(calls).toHaveBeenCalledTimes(2)
  })
})
