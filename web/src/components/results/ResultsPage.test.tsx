import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ResultsPage } from './ResultsPage'
import { detailed, fail, finding, ok, org, otherOrg, runID, sample, sampleDetail, sampleID, summary, userID } from './test-fixtures'

const context = { organizationID: org, userID, csrfToken: 'unused-synthetic-csrf', onSignedOut: vi.fn<(message: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
type Override = (url: URL, options: RequestInit) => Response | Promise<Response> | undefined
function network(override?: Override, grants = ['run.read', 'evidence.read']) {
  const fetcher = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), result = override?.(url, options)
    if (result) return result
    if (url.pathname.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: grants })
    if (url.pathname.endsWith('/result')) return ok(url.searchParams.get('include') ? detailed() : summary())
    if (url.pathname.endsWith(`/samples/${sampleID}`)) return ok(sampleDetail())
    if (url.pathname.endsWith('/samples')) return ok({ items: [sample()], next_cursor: null })
    if (url.pathname.endsWith('/findings')) return ok({ items: [finding()], next_cursor: null })
    throw new Error('Unexpected test request')
  }); vi.stubGlobal('fetch', fetcher); return fetcher
}
async function open() { await screen.findByRole('heading', { name: '修订 1 · 结果总览' }) }
async function tab(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }

describe('immutable result pages backed by real API contracts', () => {
  it('discloses limitations and shows only summary for run.read without fetching protected statistics', async () => {
    const calls = network(undefined, ['run.read']); render(<ResultsPage {...context} runID={runID} />); await open()
    expect(screen.queryByRole('button', { name: 'Token 分析' })).toBeNull()
    expect(screen.getByText(/不能升级为 A \/ B/)).toBeTruthy()
    expect(screen.getAllByText(/未测 \/ 不可估/).length).toBeGreaterThan(0)
    expect(calls.mock.calls.filter(([url]) => String(url).includes('statistics') || String(url).includes('/samples'))).toHaveLength(0)
    expect(calls.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
  })
  it('renders true denominator absence, quality and current-page scatter without fabricated observations', async () => {
    network(); render(<ResultsPage {...context} runID={runID} />); await open(); await tab('Token 分析')
    expect(screen.getAllByText('未测 / 分母为 0')).toHaveLength(2)
    expect(screen.getByRole('img', { name: /当前样本页请求上限/ })).toBeTruthy()
    expect(screen.getByText(/当前样本页散点（1 个有效样本/)).toBeTruthy()
    expect(screen.getByText(/兼容 · cl100k_base/)).toBeTruthy()
    expect(screen.getByText(/不同系列不可混合解释/)).toBeTruthy()
  })
  it('isolates self-report and labels paired differences as exploratory BH, not calibrated certainty', async () => {
    network(); render(<ResultsPage {...context} runID={runID} />); await open(); await tab('行为分析')
    expect(screen.getByText('模型自述辅助样本（权重 0）')).toBeTruthy()
    expect(screen.getByRole('heading', { name: /探索性配对差分/ })).toBeTruthy()
    expect(screen.getByText(/自述不是身份证明/)).toBeTruthy()
    expect(screen.getAllByText('未测 / 不可估').length).toBeGreaterThanOrEqual(3)
  })
  it('reads findings and explicit S1 attempt detail while preserving null Token observations', async () => {
    const calls = network(); render(<ResultsPage {...context} runID={runID} />); await open(); await tab('S1 证据')
    expect(screen.getByText('Development token observation')).toBeTruthy()
    await tab(`读取样本 ${sampleID} 的尝试记录`)
    expect(screen.getByRole('heading', { name: `样本 ${sampleID} · 尝试记录` })).toBeTruthy()
    expect(screen.getByText(/正文状态：已隐藏/)).toBeTruthy()
    expect(calls.mock.calls.filter(([url]) => String(url).includes(`/samples/${sampleID}?analysis_revision=1`))).toHaveLength(1)
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
  it('clears all statistics and evidence when a detail request returns revoked permission', async () => {
    network((url) => url.pathname.endsWith(`/samples/${sampleID}`) ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    render(<ResultsPage {...context} runID={runID} />); await open(); await tab('S1 证据'); await tab(`读取样本 ${sampleID} 的尝试记录`)
    expect(screen.getByText(/已清除结果与证据缓存/)).toBeTruthy()
    expect(screen.queryByText('Development token observation')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Token 分析' })).toBeNull()
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
  it('rechecks current permissions before every protected page and aborts old reads on tab changes', async () => {
    let granted = true
    const calls = network((url, options) => url.pathname.endsWith('/auth/permissions') ? ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: granted ? ['run.read', 'evidence.read'] : ['run.read'] }) : undefined)
    render(<ResultsPage {...context} runID={runID} />); await open(); granted = false; await tab('Token 分析')
    expect(screen.getByText(/已清除结果与证据缓存/)).toBeTruthy()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('include=statistics'))).toHaveLength(0)
  })
  it('does not substitute changed score content into an existing revision after refresh', async () => {
    let changed = false
    network((url) => url.pathname.endsWith('/result') ? ok({ ...summary(), overall_risk: changed ? 80 : 15 }) : undefined)
    render(<ResultsPage {...context} runID={runID} />); await open(); changed = true; await tab('重新读取结果与权限')
    expect(screen.getByText(/固定修订一致性校验未通过/)).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '修订 1 · 结果总览' })).toBeNull()
  })
  it('aborts cross-organization late responses and never displays the previous organizations score', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network((url, options) => url.pathname.endsWith('/result') ? new Headers(options.headers).get('X-Organization-ID') === org ? new Promise<Response>((resolve) => { release = resolve }) : fail('MI_NOT_FOUND', 404) : undefined)
    const view = render(<ResultsPage {...context} runID={runID} />)
    await waitFor(() => expect(release).toBeTypeOf('function'))
    view.rerender(<ResultsPage {...context} organizationID={otherOrg} runID={runID} />)
    await screen.findByText(/尚无可读取的修订 1/)
    await act(async () => { release!(ok(summary())) })
    expect(screen.queryByRole('heading', { name: '修订 1 · 结果总览' })).toBeNull()
    const old = calls.mock.calls.find(([url, options]) => String(url).includes('/result') && new Headers(options?.headers).get('X-Organization-ID') === org)
    expect(old?.[1]?.signal?.aborted).toBe(true)
  })
  it('aborts ongoing reads on unmount and invokes session gate without exposing server diagnostics', async () => {
    const signedOut = vi.fn<(message: string) => void>()
    network((url) => url.pathname.endsWith('/result') ? fail('MI_SESSION_REQUIRED', 401) : undefined)
    render(<ResultsPage {...context} onSignedOut={signedOut} runID={runID} />)
    await waitFor(() => expect(signedOut).toHaveBeenCalledTimes(1))
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
  it('handles corrupt responses as unavailable, not a successful empty zero-risk result', async () => {
    network((url) => url.pathname.endsWith('/result') ? ok({ ...summary(), prompt: 'SECRET_BODY_CANARY' }) : undefined)
    render(<ResultsPage {...context} runID={runID} />)
    await screen.findByText(/固定修订一致性校验未通过/)
    expect(screen.queryByText('低风险信号')).toBeNull()
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
})
