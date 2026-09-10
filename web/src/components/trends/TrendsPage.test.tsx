import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { TrendsPage } from './TrendsPage'
import { SessionLayout } from '../SessionLayout'
import { emptyAttempts, fail, ok, org, otherOrg, otherTargetID, page, runID, targetID, userID } from './test-fixtures'
import { history } from '../results/test-fixtures'

const props = { organizationID: org, userID, csrfToken: 'unused', onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
function network(value = page(), override?: (url: string, options: RequestInit) => Response | Promise<Response> | undefined) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = String(input), changed = override?.(url, options)
    if (changed) return changed
    return ok(url.includes('/auth/permissions') ? { organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: ['run.read'] } : value)
  }); vi.stubGlobal('fetch', calls); return calls
}
const table = () => screen.findByRole('table', { name: '当前页按创建时间倒序的逐 Run 趋势（不跨页汇总）' })
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
async function submit(name: string) { await act(async () => { fireEvent.submit(screen.getByRole('form', { name })) }) }
describe('real current-page target trends', () => {
  it('has an empty no-network target picker and rejects invalid IDs before routing', async () => {
    const calls = network(); render(<TrendsPage {...props} />)
    expect(calls).not.toHaveBeenCalled(); await submit('选择趋势目标')
    expect(screen.getByRole('alert').textContent).toContain('目标 ID 必须')
    fireEvent.change(screen.getByLabelText('目标 ID'), { target: { value: targetID } }); await submit('选择趋势目标')
    expect(window.location.hash).toBe(`#/trends/${targetID}`); expect(calls).not.toHaveBeenCalled()
  })
  it('renders real state denominators, retry and observed latency without whole-target totals', async () => {
    const calls = network(); render(<TrendsPage {...props} targetID={targetID} />); await table()
    expect(screen.getByText('60.00 %')).toBeTruthy(); expect(screen.getByText('成功 6 / 派发 10')).toBeTruthy()
    expect(screen.getByText('成功 6 · 失败 2')).toBeTruthy(); expect(screen.getByText('未知 1 · 在途 1')).toBeTruthy()
    expect(screen.getByText('逻辑样本 8 · 重试 2')).toBeTruthy(); expect(screen.getByText('均值 210.14 ms')).toBeTruthy()
    expect(screen.getByText('延迟有效 n = 7')).toBeTruthy(); expect(screen.getByText('尚无已发布分析（不是 0 分）')).toBeTruthy()
    expect(screen.getByText(/不是全目标或全组织汇总/)).toBeTruthy(); expect(screen.getByText(/重试是同一逻辑样本的再次派发/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: '单目标调用与风险趋势' })).toBe(document.activeElement)
    expect(calls).toHaveBeenCalledTimes(2); expect(calls.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
    expect(screen.queryByRole('button', { name: /检测|导出|生成报告/ })).toBeNull()
  })
  it('does not manufacture zero success, latency or risk from absent observations', async () => {
    const data = page()
    data.items[0].attempts = emptyAttempts(); Object.assign(data.items[0].run, { request_count: 0, completed_samples: 0, valid_sample_count: 0, status: 'QUEUED' })
    network(data); render(<TrendsPage {...props} targetID={targetID} />); const grid = await table()
    expect(within(grid).getByText('未测')).toBeTruthy(); expect(within(grid).getByText('均值 未测')).toBeTruthy(); expect(within(grid).queryByText('0.00 %')).toBeNull()
    expect(within(grid).getByText('延迟有效 n = 0')).toBeTruthy(); expect(within(grid).getByText('尚无已发布分析（不是 0 分）')).toBeTruthy()
  })
  it('shows nullable published risk and frozen version limitations, not current target labels', async () => {
    const data = page(2)
    data.items[0].run.result = { ...history().result!, overall_risk: null, completeness: 'insufficient', confidence: 20, evidence_grade: 'D', risk_level: 'insufficient' }
    data.items[1].run.versions = { ...data.items[1].run.versions, scoring: 'development.2' }
    data.items[1].run.current_target_name = 'CURRENT_TARGET_CANARY'
    network(data); render(<TrendsPage {...props} targetID={targetID} />); await table()
    expect(screen.getByText('风险 未测 · 置信指数 20 / 100')).toBeTruthy(); expect(screen.getByText(/本页冻结版本不同/)).toBeTruthy()
    expect(screen.queryByText('CURRENT_TARGET_CANARY')).toBeNull(); expect(screen.getByRole('link', { name: '修订 1 · 证据不足' }).getAttribute('href')).toBe(`#/results/${runID}/1`)
  })
  it('paginates only on user action, retains opaque cursors, and resets with exact UTC filters', async () => {
    const first = page(25); first.next_cursor = 'signed_next.opaque'
    const calls = network(first, (url) => url.includes('/runs/trends?') && url.includes('cursor=') ? ok(page(1, 25)) : undefined)
    render(<TrendsPage {...props} targetID={targetID} />); await table(); expect(calls).toHaveBeenCalledTimes(2)
    await click('下一页'); await waitFor(() => expect(screen.getByText('第 2 页 · 仅本页 1 条')).toBeTruthy())
    expect(calls).toHaveBeenCalledTimes(4); expect(String(calls.mock.calls[3][0])).toContain('cursor=signed_next.opaque')
    fireEvent.change(screen.getByLabelText('检测包'), { target: { value: 'quick' } })
    fireEvent.change(screen.getByLabelText('任务状态'), { target: { value: 'RUNNING' } })
    fireEvent.change(screen.getByLabelText('创建时间起（UTC，精确到秒）'), { target: { value: '2026-09-07T06:00:01' } })
    fireEvent.change(screen.getByLabelText('创建时间止（UTC，精确到秒）'), { target: { value: '2026-09-07T07:00:00' } })
    await submit('筛选目标趋势'); await table()
    expect(screen.queryByRole('alert')?.textContent).toBeUndefined()
    expect(screen.getByText('第 1 页 · 仅本页 25 条')).toBeTruthy(); const url = new URL(String(calls.mock.calls[5][0]), 'https://mii.test')
    expect(url.searchParams.get('cursor')).toBeNull(); expect(url.searchParams.get('package')).toBe('quick'); expect(url.searchParams.get('status')).toBe('RUNNING')
    expect(url.searchParams.get('date_from')).toBe('2026-09-07T06:00:01Z'); expect(url.searchParams.get('date_to')).toBe('2026-09-07T07:00:00Z')
  })
  it('rejects backwards UTC ranges without starting a request', async () => {
    const calls = network(); render(<TrendsPage {...props} targetID={targetID} />); await table()
    fireEvent.change(screen.getByLabelText('创建时间起（UTC，精确到秒）'), { target: { value: '2026-09-08T00:00:00' } })
    fireEvent.change(screen.getByLabelText('创建时间止（UTC，精确到秒）'), { target: { value: '2026-09-07T00:00:00' } })
    await submit('筛选目标趋势'); expect(screen.getByRole('alert').textContent).toContain('筛选无效'); expect(calls).toHaveBeenCalledTimes(2)
  })
  it('clears previously displayed data and paging metadata after a denied refresh without automatically retrying', async () => {
    const first = page(25); first.next_cursor = 'opaque.next'
    const calls = network(first); render(<TrendsPage {...props} targetID={targetID} />); await table()
    calls.mockImplementation(async () => ok({ organization_id: org, user_id: userID, permissions: [] }))
    await click('刷新当前页'); await screen.findByText(/读取权限不足或已撤销/)
    expect(screen.queryByRole('table')).toBeNull(); expect((screen.getByRole('button', { name: '下一页' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText('第 1 页 · 仅本页 — 条')).toBeTruthy(); expect(calls).toHaveBeenCalledTimes(3)
    expect(screen.queryByText(/没有可读取的 Run/)).toBeNull()
  })
  it.each(['repeated-page', 'cursor-loop'])('rejects %s and never displays an old or half page', async (mode) => {
    const first = page(25); first.next_cursor = 'cursor1'
    const second = page(25, mode === 'repeated-page' ? 0 : 25); second.next_cursor = mode === 'cursor-loop' ? 'cursor1' : null
    const calls = network(first, (url) => url.includes('/runs/trends?') && url.includes('cursor=') ? ok(second) : undefined)
    render(<TrendsPage {...props} targetID={targetID} />); await table(); await click('下一页')
    await screen.findByText(/趋势响应的目标、统计分母、顺序或游标不一致/)
    expect(screen.queryByRole('table')).toBeNull(); expect(calls).toHaveBeenCalledTimes(4)
  })
  it('aborts an old organization read and ignores its late response', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network(page(), (url, options) => url.includes('/runs/trends?') && new Headers(options.headers).get('X-Organization-ID') === org ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    const view = render(<TrendsPage {...props} targetID={targetID} />); await waitFor(() => expect(release).toBeTypeOf('function'))
    view.rerender(<TrendsPage {...props} organizationID={otherOrg} targetID={targetID} />); await table()
    expect(calls.mock.calls[1][1]?.signal?.aborted).toBe(true)
    const stale = page(); stale.items[0].run.id = '19'
    await act(async () => { release!(ok(stale)) }); expect(screen.queryByRole('link', { name: 'Run 19' })).toBeNull()
    view.unmount(); expect(calls.mock.calls[3][1]?.signal?.aborted).toBe(true)
  })
  it('clears data for target and user switches and reports session loss without exposing diagnostics', async () => {
    const calls = network(); const view = render(<TrendsPage {...props} targetID={targetID} />); await table()
    calls.mockImplementation(async () => fail('MI_SESSION_REQUIRED', 401))
    view.rerender(<TrendsPage {...props} userID="29" targetID={otherTargetID} />)
    await waitFor(() => expect(props.onSignedOut).toHaveBeenCalled())
    expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('SECRET_BODY_CANARY')).toBeNull(); expect(calls).toHaveBeenCalledTimes(3)
  })
  it('routes only canonical target IDs and applies navigation title and keyboard focus', async () => {
    window.history.replaceState(null, '', '/#/trends/01'); const calls = network()
    const session = { user: { id: userID, username: 'reader', status: 'active' as const, must_change_password: false }, organizations: [{ id: org, name: 'Alpha', status: 'active' as const }], csrf_token: 'test', expires_at: '2099-01-01T00:00:00Z' }
    render(<SessionLayout session={session} onSignedOut={props.onSignedOut} onPasswordRequired={props.onPasswordRequired} />)
    expect(screen.getByText('未找到对应页面')).toBeTruthy(); expect(calls).not.toHaveBeenCalled()
    await act(async () => { window.location.hash = `#/trends/${targetID}`; window.dispatchEvent(new HashChangeEvent('hashchange')) }); await table()
    expect(screen.getByRole('link', { name: '目标趋势' }).getAttribute('aria-current')).toBe('page')
    expect(document.title).toBe('单目标调用与风险趋势 · Model Integrity Inspector'); expect(calls).toHaveBeenCalledTimes(2)
  })
})
