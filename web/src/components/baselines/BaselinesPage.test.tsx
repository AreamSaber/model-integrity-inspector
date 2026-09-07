import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Baseline } from '../../baselines-api'
import { BaselinesPage } from './BaselinesPage'
import { SessionLayout } from '../SessionLayout'
import { approvedFixture, baselineFixture, baselineID, fail, grants, ok, org, runID, user } from './test-fixtures'

const context = { organizationID: org, userID: user, csrfToken: 'baseline-csrf', onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
const disabled = (name: string) => (screen.getByRole('button', { name }) as HTMLButtonElement).disabled
function mockServer(value = baselineFixture(), permissions = grants) {
  let current = value
  const fetcher = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = String(input), headers = new Headers(options.headers), method = options.method ?? 'GET'
    if (url.endsWith('/auth/permissions')) return ok({ organization_id: headers.get('X-Organization-ID'), user_id: user, permissions })
    if (url.startsWith('/api/v1/baselines?')) return ok({ items: [current], next_cursor: null })
    if (method === 'GET') return ok(current)
    const body = JSON.parse(options.body as string) as Record<string, unknown>
    if (method === 'PATCH') current = { ...current, version: current.version + 1, name: String(body.name), expires_at: String(body.expires_at) }
    else if (url.endsWith('/approve')) current = approvedFixture(current)
    else if (url.endsWith('/retire')) current = { ...current, version: current.version + 1, status: 'retired', retired_at: new Date().toISOString() }
    else current = { ...current, name: String(body.name), run_id: String(body.run_id), source: body.source as Baseline['source'], region: String(body.region), expires_at: String(body.expires_at) }
    return ok(current, url === '/api/v1/baselines' ? 201 : 200)
  })
  vi.stubGlobal('fetch', fetcher); return fetcher
}
async function details() { fireEvent.click(await screen.findByRole('button', { name: '查看基线 组织合成参考' })); await screen.findByRole('heading', { name: '参考详情：组织合成参考' }) }
async function openApprove() { await details(); fireEvent.click(screen.getByRole('button', { name: '审批此组织参考' })); await screen.findByRole('form', { name: '审批组织参考' }) }
function approveFields() { fireEvent.change(screen.getByLabelText('审批理由'), { target: { value: 'Organization decision' } }); fireEvent.change(screen.getByLabelText('业务复核说明（必填）'), { target: { value: 'Elevated-risk business explanation' } }); fireEvent.click(screen.getByRole('checkbox')) }
describe('real baseline management UI', () => {
  it('shows only actual server records, immutable metadata and unverified development restrictions', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await details()
    expect(screen.getByText('a'.repeat(64))).toBeTruthy(); expect(screen.getByText('b'.repeat(64))).toBeTruthy()
    expect(screen.getByRole('link', { name: `${runID} · 修订 1` }).getAttribute('href')).toBe(`#/results/${runID}/1`)
    expect(screen.getByText(/当前只管理组织审核参考/)).toBeTruthy(); expect(screen.getByText('尚不参与可信对照评分或证据等级提升')).toBeTruthy()
    expect(fetcher.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
  })
  it('requires explicit risk/development acknowledgement before approval and retains approval after retirement', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await openApprove()
    fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })); expect(screen.getByRole('alert').textContent).toContain('明确确认')
    fireEvent.click(screen.getByRole('checkbox')); fireEvent.change(screen.getByLabelText('审批理由'), { target: { value: 'review' } })
    fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })); expect(screen.getByRole('alert').textContent).toContain('业务复核说明')
    fireEvent.change(screen.getByLabelText('业务复核说明（必填）'), { target: { value: 'Explicit synthetic decision' } })
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })) })
    expect(disabled('编辑此草稿')).toBe(true)
    expect(disabled('审批此组织参考')).toBe(true)
    expect(screen.getByText(new RegExp(`已保存组织参考 ${baselineID}`))).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '退休此参考' })); fireEvent.change(screen.getByLabelText('退休理由'), { target: { value: 'withdraw' } }); fireEvent.click(screen.getByRole('checkbox'))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '退休组织参考' })) })
    expect(disabled('退休此参考')).toBe(true)
    expect(screen.getByText(/原审批信息保留/)).toBeTruthy()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2)
  })
  it('creates a draft from a string Run ID without sending eligibility or arbitrary scope', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await screen.findByRole('button', { name: '查看基线 组织合成参考' })
    fireEvent.click(screen.getByRole('button', { name: '创建基线草稿' })); fireEvent.change(screen.getByLabelText('参考名称'), { target: { value: 'New reference' } }); fireEvent.change(screen.getByLabelText('已发布 Run ID'), { target: { value: runID } })
    fireEvent.submit(screen.getByRole('form', { name: '从已发布 Run 创建草稿' })); expect(screen.getByRole('alert').textContent).toContain('明确确认')
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    fireEvent.click(screen.getByRole('checkbox'))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '从已发布 Run 创建草稿' })) })
    expect(await screen.findByRole('heading', { name: '参考详情：New reference' })).toBeTruthy()
    const [, options] = fetcher.mock.calls.find(([url, opts]) => url === '/api/v1/baselines' && opts?.method === 'POST')!
    expect(JSON.parse(options!.body as string)).toMatchObject({ run_id: runID, analysis_revision: 1, source: 'historical' }); expect(JSON.parse(options!.body as string)).not.toHaveProperty('eligible_for_scoring')
  })
  it('uses actual grants, not system-admin labels, and rechecks before sending a mutation', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await openApprove(); approveFields()
    fetcher.mockImplementation(async () => ok({ organization_id: org, user_id: user, permissions: ['baseline.read'] }))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })) })
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0)
    expect(screen.queryByRole('heading', { name: '参考详情：组织合成参考' })).toBeNull(); expect(screen.queryByLabelText('审批理由')).toBeNull()
    expect(screen.getByRole('alert').textContent).toContain('没有执行此操作的权限')
  })
  it('does not silently resubmit a conflict and requires a fresh read', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await openApprove(); approveFields()
    const prior = fetcher.getMockImplementation()!
    fetcher.mockImplementation((input, options) => options?.method === 'POST' ? Promise.resolve(fail('MI_CONFLICT', 409)) : prior(input, options))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })) })
    expect(screen.getByText(/版本或状态冲突/)).toBeTruthy(); expect(screen.queryByLabelText('审批理由')).toBeNull()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新基线与权限' })) })
    expect(await screen.findByRole('button', { name: '查看基线 组织合成参考' })).toBeTruthy()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })
  it('locks uncertain writes until the reader explicitly reconciles, without automatic retry', async () => {
    const fetcher = mockServer(); render(<BaselinesPage {...context} />); await openApprove(); approveFields()
    const prior = fetcher.getMockImplementation()!
    fetcher.mockImplementation((input, options) => options?.method === 'POST' ? Promise.reject(new Error('PRIVATE_SERVER_BODY')) : prior(input, options))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '审批组织参考' })) })
    expect(screen.getByText(/提交结果未确认/)).toBeTruthy(); expect(disabled('创建基线草稿')).toBe(true)
    expect(disabled('已核对最新记录，允许新的手动操作')).toBe(true)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新基线与权限' })) })
    fireEvent.click(screen.getByRole('button', { name: '已核对最新记录，允许新的手动操作' }))
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1); expect(document.body.textContent).not.toContain('PRIVATE_SERVER_BODY')
  })
  it('binds pagination to searches and does not perform client-only status filtering', async () => {
    const fetcher = mockServer(), prior = fetcher.getMockImplementation()!
    fetcher.mockImplementation((input, options) => String(input).includes('/baselines?') ? Promise.resolve(ok({ items: [baselineFixture()], next_cursor: String(input).includes('cursor=') ? null : 'opaque-next' })) : prior(input, options))
    render(<BaselinesPage {...context} />); await screen.findByRole('button', { name: '查看基线 组织合成参考' })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '基线下一页' })) })
    expect(screen.getByText('基线第 2 页')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('服务端搜索基线名称'), { target: { value: 'target' } })
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '搜索参考基线' })) })
    const last = fetcher.mock.calls.filter(([url]) => String(url).includes('/baselines?')).at(-1)!
    expect(String(last[0])).toContain('q=target'); expect(String(last[0])).not.toContain('cursor='); expect(screen.getByText('基线第 1 页')).toBeTruthy()
  })
  it('clears user/org-scoped form state and aborts a prior read, ignoring a late completion', async () => {
    const fetcher = mockServer(), prior = fetcher.getMockImplementation()!
    let release: ((value: Response) => void) | undefined
    fetcher.mockImplementation((input, options) => String(input).endsWith(`/baselines/${baselineID}`) ? new Promise((resolve) => { release = resolve }) : prior(input, options))
    const view = render(<BaselinesPage {...context} />)
    fireEvent.click(await screen.findByRole('button', { name: '查看基线 组织合成参考' })); await waitFor(() => expect(release).toBeTypeOf('function'))
    const detailCall = fetcher.mock.calls.find(([url]) => String(url).endsWith(`/baselines/${baselineID}`))!
    view.rerender(<BaselinesPage {...context} organizationID="12" />)
    await act(async () => { release!(ok(baselineFixture({ name: 'STALE_PRIVATE_NAME' }))) })
    expect(detailCall[1]?.signal?.aborted).toBe(true); expect(document.body.textContent).not.toContain('STALE_PRIVATE_NAME')
  })
  it('removes protected state and invokes the password/session gates on denied reads', async () => {
    const password = vi.fn<() => void>(), logout = vi.fn<(notice: string) => void>(), fetcher = mockServer()
    render(<BaselinesPage {...context} onPasswordRequired={password} onSignedOut={logout} />); await details()
    fetcher.mockResolvedValue(fail('MI_PASSWORD_CHANGE_REQUIRED', 403))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新基线与权限' })) })
    expect(password).toHaveBeenCalledTimes(1); expect(screen.queryByRole('heading', { name: '参考详情：组织合成参考' })).toBeNull()
    fetcher.mockResolvedValue(fail('MI_SESSION_REQUIRED', 401))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '刷新基线与权限' })) })
    expect(logout).toHaveBeenCalledTimes(1)
  })
  it('replaces the real session-layout placeholder and prevents approved/expired/retired editing', async () => {
    const approved = approvedFixture(baselineFixture()); mockServer({ ...approved, status: 'expired', limitations: [...approved.limitations, 'MI_BASELINE_EXPIRED_RESAMPLE'] })
    window.history.replaceState(null, '', '/#/baselines')
    render(<SessionLayout session={{ user: { id: user, username: 'reader', status: 'active', must_change_password: false }, csrf_token: 'csrf', expires_at: '2099-01-01T00:00:00Z', organizations: [{ id: org, name: 'Org', status: 'active' }] }} onSignedOut={context.onSignedOut} onPasswordRequired={context.onPasswordRequired} />)
    await details(); expect(screen.queryByText('可信基线正在开发中')).toBeNull()
    expect(disabled('编辑此草稿')).toBe(true); expect(disabled('审批此组织参考')).toBe(true)
  })
  it('clears unsaved reviewer text on user changes and renders names as text, never HTML', async () => {
    const fetcher = mockServer(), view = render(<BaselinesPage {...context} />); await openApprove()
    fireEvent.change(screen.getByLabelText('审批理由'), { target: { value: 'PRIVATE_UNSAVED_REASON' } })
    fetcher.mockImplementation(async (input, options) => String(input).endsWith('/auth/permissions') ? ok({ organization_id: new Headers(options?.headers).get('X-Organization-ID'), user_id: '13', permissions: ['baseline.read'] }) : ok({ items: [baselineFixture({ name: '<img src=x onerror=alert(1)>' })], next_cursor: null }))
    view.rerender(<BaselinesPage {...context} userID="13" />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeTruthy()
    expect(screen.queryByLabelText('审批理由')).toBeNull(); expect(document.body.innerHTML).not.toContain('PRIVATE_UNSAVED_REASON'); expect(document.querySelector('img')).toBeNull()
    expect(disabled('创建基线草稿')).toBe(true)
  })
  it('allows baseline-only readers to inspect references without suggesting inaccessible Run views', async () => {
    const fetcher = mockServer(baselineFixture(), ['baseline.read']); render(<BaselinesPage {...context} />); await details()
    expect(screen.queryByRole('link', { name: `${runID} · 修订 1` })).toBeNull()
    expect(screen.getByText(/没有来源结果读取权限/)).toBeTruthy()
    expect(disabled('创建基线草稿')).toBe(true); expect(disabled('编辑此草稿')).toBe(true); expect(disabled('审批此组织参考')).toBe(true); expect(disabled('退休此参考')).toBe(true)
    expect(fetcher.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
  })
  it('distinguishes invalid source admission from a version conflict and permits explicit correction', async () => {
    const fetcher = mockServer(), prior = fetcher.getMockImplementation()!
    fetcher.mockImplementation((input, options) => input === '/api/v1/baselines' && options?.method === 'POST' ? Promise.resolve(fail('MI_BASELINE_SOURCE_INVALID', 409)) : prior(input, options))
    render(<BaselinesPage {...context} />); await screen.findByRole('button', { name: '查看基线 组织合成参考' })
    fireEvent.click(screen.getByRole('button', { name: '创建基线草稿' })); fireEvent.change(screen.getByLabelText('参考名称'), { target: { value: 'invalid source' } }); fireEvent.change(screen.getByLabelText('已发布 Run ID'), { target: { value: '1' } }); fireEvent.click(screen.getByRole('checkbox'))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '从已发布 Run 创建草稿' })) })
    expect(screen.getByRole('alert').textContent).toContain('来源必须是当前组织已结束且已发布的有效修订')
    expect(screen.queryByText(/版本或状态冲突/)).toBeNull(); expect(screen.getByLabelText('已发布 Run ID')).toBeTruthy()
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })
})
