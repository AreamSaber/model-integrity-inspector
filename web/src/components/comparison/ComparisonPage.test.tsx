import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ComparisonPage } from './ComparisonPage'
import { ComparisonTables } from './ComparisonPage'
import { SessionLayout } from '../SessionLayout'
import { comparison, failure, ok, org, rightID, runID, userID } from './test-fixtures'
import type { Comparison } from '../../comparison-api'

const props = { organizationID: org, userID, csrfToken: 'unused', onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
const selection = { left: runID, right: rightID, revision: 1 as const }
function network(value = comparison(), override?: (url: string, options: RequestInit) => Response | Promise<Response> | undefined) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = String(input), replaced = override?.(url, options)
    if (replaced) return replaced
    if (url.includes('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: ['run.read'] })
    const side = url.includes(rightID) ? value.right : value.left
    return ok(url.includes('/result?') ? side.result : side.run)
  }); vi.stubGlobal('fetch', calls); return calls
}
const table = () => screen.findByRole('table', { name: '两个固定发布修订的描述性对比' })
async function submit() { await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '选择两个固定修订任务' })) }) }

describe('two-run descriptive comparison page', () => {
  it('does no network on the empty form and validates IDs before routing', async () => {
    const calls = network(); render(<ComparisonPage {...props} />)
    expect(calls).not.toHaveBeenCalled(); await submit(); expect(calls).not.toHaveBeenCalled()
    expect(screen.getByRole('alert').textContent).toContain('两个不同的 Run ID')
    fireEvent.change(screen.getByLabelText('左侧 Run ID'), { target: { value: runID } })
    fireEvent.change(screen.getByLabelText('右侧 Run ID'), { target: { value: rightID } })
    await submit(); expect(window.location.hash).toBe(`#/compare/${runID}/1/${rightID}/1`)
    expect(calls).not.toHaveBeenCalled()
  })
  it('renders fixed scope and actual metrics with missing values not zero, without extra history or evidence reads', async () => {
    const calls = network(); render(<ComparisonPage {...props} selection={selection} />); await table()
    expect(screen.getAllByText('未测 / 不可估')).toHaveLength(2)
    expect(screen.getByText('不可计算（至少一侧未测）')).toBeTruthy()
    expect(screen.getAllByText('16 / 18')).toHaveLength(2)
    expect(screen.getByText(/置信度指数（不是概率）/)).toBeTruthy()
    expect(screen.getByRole('link', { name: `Run ${runID} · 修订 1` }).getAttribute('href')).toBe(`#/results/${runID}/1`)
    expect(calls).toHaveBeenCalledTimes(5); expect(calls.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
    expect(screen.queryByRole('button', { name: /导出|生成报告/ })).toBeNull()
  })
  it('explains different frozen versions, targets and packages without calling the difference behavior worsening', () => {
    const value: Comparison = comparison()
    value.right.run.target_id = '29'; value.right.run.package = 'deep'; value.right.result.versions.scoring = 'development.2'
    value.right.result.token_risk = 35; value.right.result.valid_samples = 8
    render(<ComparisonTables value={value} />)
    expect(screen.getByText('+15.0')).toBeTruthy()
    expect(screen.getByText(/算法变化与行为变化无法据此拆分/)).toBeTruthy()
    expect(screen.getByText('不同目标')).toBeTruthy()
    expect(screen.getByText('覆盖范围可能不同')).toBeTruthy()
    expect(screen.queryByText('行为已恶化')).toBeNull()
  })
  it('clears both sides after denied refresh and does not keep a half-visible prior comparison', async () => {
    let denied = false
    network(comparison(), (url) => denied && url.includes(rightID) ? failure('MI_PERMISSION_DENIED', 403) : undefined)
    render(<ComparisonPage {...props} selection={selection} />); await table()
    denied = true; await submit()
    expect(screen.queryByRole('table', { name: '两个固定发布修订的描述性对比' })).toBeNull()
    expect(screen.getByText(/已清除两侧缓存/)).toBeTruthy()
    expect(document.body.textContent).not.toContain('COMPARISON_PRIVATE_CANARY')
  })
  it('refuses changed scores under the same published revision on refresh', async () => {
    let changed = false
    network(comparison(), (url) => changed && url.includes('/result?') ? ok({ ...comparison().left.result, run_id: url.includes(rightID) ? rightID : runID, token_risk: 40 }) : undefined)
    render(<ComparisonPage {...props} selection={selection} />); await table(); changed = true; await submit()
    expect(screen.queryByRole('table', { name: '两个固定发布修订的描述性对比' })).toBeNull()
    expect(screen.getByText(/或同一修订发生变化/)).toBeTruthy()
  })
  it('accepts semantically identical object key ordering when rereading a frozen revision', async () => {
    let reordered = false
    network(comparison(), (url) => {
      if (!reordered || !url.includes('/runs/')) return undefined
      const side = url.includes(rightID) ? comparison().right : comparison().left
      const value = url.includes('/result?') ? side.result : side.run
      return ok(Object.fromEntries(Object.entries(value).reverse()))
    })
    render(<ComparisonPage {...props} selection={selection} />); await table(); reordered = true; await submit()
    expect(await table()).toBeTruthy(); expect(screen.queryByRole('alert')).toBeNull()
  })
  it('rejects one missing result without rendering the other successfully read side', async () => {
    network(comparison(), (url) => url.includes(rightID) && url.includes('/result?') ? failure('MI_NOT_FOUND', 404) : undefined)
    render(<ComparisonPage {...props} selection={selection} />)
    await screen.findByText(/至少一侧在当前组织下不存在/)
    expect(screen.queryByRole('table')).toBeNull()
  })
  it('cancels all old user/org reads and does not display a late previous-scope response', async () => {
    const held: (AbortSignal | null | undefined)[] = []
    network(comparison(), (url, options) => {
      if (url.includes('/runs/') && new Headers(options.headers).get('X-Organization-ID') === org) { held.push(options.signal); return new Promise<Response>(() => {}) }
      if (url.includes('/runs/')) return failure('MI_NOT_FOUND', 404)
      return undefined
    })
    const view = render(<ComparisonPage {...props} selection={selection} />)
    await waitFor(() => expect(held).toHaveLength(4))
    view.rerender(<ComparisonPage {...props} organizationID="9007199254740999" selection={selection} />)
    await screen.findByText(/至少一侧在当前组织下不存在/)
    expect(held.every((signal) => signal?.aborted)).toBe(true)
    expect(screen.queryByRole('table')).toBeNull()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('propagates session expiration without showing server text', async () => {
    const signedOut = vi.fn<(notice: string) => void>()
    network(comparison(), () => failure('MI_SESSION_REQUIRED', 401))
    render(<ComparisonPage {...props} onSignedOut={signedOut} selection={selection} />)
    await waitFor(() => expect(signedOut).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('table')).toBeNull(); expect(document.body.textContent).not.toContain('COMPARISON_PRIVATE_CANARY')
  })
  it('routes only exact two-run revision 1 paths and loads the real page within the active organization', async () => {
    const session = { user: { id: userID, username: 'reader', status: 'active' as const, must_change_password: false }, organizations: [{ id: org, name: 'Organization', status: 'active' as const }], csrf_token: 'unused', expires_at: '2099-01-01T00:00:00Z' }
    window.history.replaceState(null, '', `/#/compare/${runID}/2/${rightID}/1`)
    const calls = network()
    render(<SessionLayout session={session} onSignedOut={props.onSignedOut} onPasswordRequired={props.onPasswordRequired} />)
    expect(screen.getByText('未找到对应页面')).toBeTruthy(); expect(calls).not.toHaveBeenCalled()
    await act(async () => { window.location.hash = `#/compare/${runID}/1/${rightID}/1`; window.dispatchEvent(new HashChangeEvent('hashchange')) })
    await table(); expect(calls).toHaveBeenCalledTimes(5)
    expect(screen.getByRole('link', { name: '任务对比' }).getAttribute('aria-current')).toBe('page')
    expect(document.title).toBe('两任务固定修订对比 · Model Integrity Inspector')
  })
})
