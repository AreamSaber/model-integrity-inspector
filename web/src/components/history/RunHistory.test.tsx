import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { RunHistory } from './RunHistory'
import { fail, history, ok, org, otherOrg, runID, userID } from '../results/test-fixtures'
import { SessionLayout } from '../SessionLayout'

const context = { organizationID: org, userID, csrfToken: 'test-csrf', onSignedOut: vi.fn<(message: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
describe('real Run history page', () => {
  it('lists true server records with deleted-target fallback, unknown price and immutable result links', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [history()], next_cursor: null })); vi.stubGlobal('fetch', calls)
    render(<RunHistory {...context} />)
    expect(await screen.findByRole('link', { name: `Run ${runID}` })).toBeTruthy()
    expect(screen.getByRole('link', { name: '修订 1 · 需关注' }).getAttribute('href')).toBe(`#/results/${runID}/1`)
    expect(screen.getByText('价格未知，无法估算')).toBeTruthy()
    expect(screen.getByText(/已删除目标的任务仍保留目标 ID/)).toBeTruthy()
    expect(calls).toHaveBeenCalledTimes(1)
  })
  it('uses bounded server pagination and resets its cursor when filters change', async () => {
    const calls = vi.fn<typeof fetch>(async (input) => ok({ items: [history()], next_cursor: String(input).includes('cursor=') ? null : 'next-page' })); vi.stubGlobal('fetch', calls)
    render(<RunHistory {...context} />); await screen.findByRole('link', { name: `Run ${runID}` })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '下一页' })) })
    expect(screen.getByText('第 2 页')).toBeTruthy()
    expect(String(calls.mock.calls[1][0])).toContain('cursor=next-page')
    fireEvent.change(screen.getByLabelText('搜索目标或模型'), { target: { value: 'target' } })
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '筛选检测历史' })) })
    expect(screen.getByText('第 1 页')).toBeTruthy()
    expect(String(calls.mock.calls[2][0])).toContain('q=target'); expect(String(calls.mock.calls[2][0])).not.toContain('cursor=')
  })
  it('does not treat a denied refresh as an empty list and clears previously loaded records', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [history()], next_cursor: null })); vi.stubGlobal('fetch', calls)
    render(<RunHistory {...context} />); await screen.findByRole('link', { name: `Run ${runID}` })
    calls.mockImplementation(async () => fail('MI_PERMISSION_DENIED', 403))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新历史' })) })
    expect(screen.queryByRole('link', { name: `Run ${runID}` })).toBeNull()
    expect(screen.getByText(/已清除本页缓存/)).toBeTruthy()
    expect(screen.queryByText(/没有符合条件的检测任务/)).toBeNull()
  })
  it('aborts a prior organization read and ignores its late completion', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = vi.fn<typeof fetch>(async (_input, options = {}) => new Headers(options.headers).get('X-Organization-ID') === org ? new Promise<Response>((resolve) => { release = resolve }) : ok({ items: [], next_cursor: null })); vi.stubGlobal('fetch', calls)
    const view = render(<RunHistory {...context} />)
    await waitFor(() => expect(release).toBeTypeOf('function'))
    view.rerender(<RunHistory {...context} organizationID={otherOrg} />)
    await screen.findByText(/没有符合条件的检测任务/)
    await act(async () => { release!(ok({ items: [history()], next_cursor: null })) })
    expect(screen.queryByRole('link', { name: `Run ${runID}` })).toBeNull()
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
  })
  it('validates filter inputs before fetch and distinguishes report scope from report generation', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [], next_cursor: null })); vi.stubGlobal('fetch', calls)
    render(<RunHistory {...context} resultsOnly />); await screen.findByText(/没有符合条件的检测任务/)
    fireEvent.change(screen.getByLabelText('目标 ID'), { target: { value: 'bad/id' } })
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '筛选检测历史' })) })
    expect(screen.getByRole('alert').textContent).toContain('筛选字段格式无效')
    expect(calls).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/已支持显式生成和下载脱敏 S1 JSON\/HTML 报告/)).toBeTruthy()
  })
  it('selects only two explicit published IDs without scanning history or starting requests for comparison', async () => {
    const secondID = '9007199254741100'
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [history(), { ...history(), id: secondID }], next_cursor: null })); vi.stubGlobal('fetch', calls)
    render(<RunHistory {...context} />); await screen.findByRole('link', { name: `Run ${runID}` })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: `将 Run ${runID} 选为对比左侧` })); fireEvent.click(screen.getByRole('button', { name: `将 Run ${runID} 选为对比右侧` })) })
    expect(screen.queryByRole('link', { name: '读取所选两个固定修订 →' })).toBeNull()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: `将 Run ${secondID} 选为对比右侧` })) })
    expect(screen.getByRole('link', { name: '读取所选两个固定修订 →' }).getAttribute('href')).toBe(`#/compare/${runID}/1/${secondID}/1`)
    expect(calls).toHaveBeenCalledTimes(1)
    calls.mockImplementation(async () => fail('MI_PERMISSION_DENIED', 403))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新历史' })) })
    expect(screen.queryByRole('heading', { name: '两任务对比选择' })).toBeNull()
  })
  it('routes only supported fixed revisions and remounts when the organization changes', async () => {
    window.history.replaceState(null, '', `/#/results/${runID}/2`)
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [], next_cursor: null })); vi.stubGlobal('fetch', calls)
    const session = { user: { id: userID, username: 'reader', status: 'active' as const, must_change_password: false }, organizations: [{ id: org, name: 'Alpha', status: 'active' as const }, { id: otherOrg, name: 'Beta', status: 'active' as const }], csrf_token: 'test-csrf', expires_at: '2099-01-01T00:00:00Z' }
    render(<SessionLayout session={session} onSignedOut={context.onSignedOut} onPasswordRequired={context.onPasswordRequired} />)
    expect(screen.getByText('未找到对应页面')).toBeTruthy(); expect(calls).not.toHaveBeenCalled()
    await act(async () => { window.location.hash = '#/runs'; window.dispatchEvent(new HashChangeEvent('hashchange')) })
    await screen.findByText(/没有符合条件的检测任务/)
    await act(async () => { fireEvent.change(screen.getByLabelText('当前组织'), { target: { value: otherOrg } }) })
    expect(calls).toHaveBeenCalledTimes(2)
  })
})
