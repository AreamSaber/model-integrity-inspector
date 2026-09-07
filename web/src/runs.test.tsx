import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import type { Session } from './api'
import type { Target } from './targets-api'
import type { EstimateInput, Quote, Run } from './runs-api'

const org = '9007199254740995', otherOrg = '9007199254740997', userID = '9007199254740993', csrf = 'synthetic-csrf'
const target: Target = { id: '9007199254741005', version: 4, name: 'Run target', model: 'example-model', endpoint: 'https://upstream.example/v1', protocol: 'openai_chat', provider_id: null, model_profile_id: null, environment: 'test', channel_id: '', tags: [], status: 'active', options: { max_output_parameter: 'auto', tls_verify: true, timeout_seconds: 180, concurrency: 1, rpm: 60 }, secret: { id: '9007199254741007', version: 3, mask: '********test' } }
const session: Session = { user: { id: userID, username: 'admin', status: 'active', system_admin: true, must_change_password: false }, organizations: [{ id: org, name: 'Alpha', status: 'active' }, { id: otherOrg, name: 'Beta', status: 'active' }], csrf_token: csrf, expires_at: '2099-01-01T00:00:00Z' }
const grants = ['run.read', 'run.create', 'run.custom', 'run.high-cost', 'run.cancel-own']
function draft(): Quote { return { id: '9007199254741021', target_id: target.id, target_version: 4, package: 'quick', manifest_hash: 'a'.repeat(64), versions: { rule_bundle: '1.0.0-dev.1', template_bundle: '1.0.0-dev.1', scoring: '1.0.0-dev.1', tokenizer_bundle: '1.0.0' }, estimate: { requests: 18, input_tokens: 2000, max_output_tokens: 4000, cost_micros: null, duration_seconds: 900, usage_safety_factor: 1.25, warnings: ['MI_PROBE_DEVELOPMENT_UNCALIBRATED', 'MI_TEMPLATE_PUBLIC_DEVELOPMENT_POOL'], completeness: 'full' }, expires_at: new Date(Date.now() + 600000).toISOString(), budgets: { max_requests: 20, max_tokens: 15000, max_cost_micros: null, timeout_seconds: 900 } } }
function queued(quote = draft()): Run { return { id: '9007199254741023', target_id: quote.target_id, created_by: userID, package: quote.package, status: 'QUEUED', version: 1, versions: quote.versions, estimate: quote.estimate, manifest_hash: quote.manifest_hash, request_count: 0, token_count: 0, estimated_cost_micros: null, valid_sample_count: 0, planned_samples: quote.estimate.requests, completed_samples: 0, created_at: '2026-09-07T08:00:00Z', started_at: null, finished_at: null, execution_closed_at: null, error_summary: [] } }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'run-test-request' }, { status }) }
function fail(code: string, status = 409) { return Response.json({ error: { code, message: 'private-upstream-diagnostic' }, request_id: 'run-test-error' }, { status }) }
type Handler = (path: string, options: RequestInit) => Response | Promise<Response> | undefined
function network(handler?: Handler) {
  let quote = draft(), record = queued(quote)
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const path = new URL(String(input), 'http://localhost').pathname
    const override = handler?.(path, options); if (override) return override
    if (path.endsWith('/setup/status')) return ok({ initialized: true })
    if (path.endsWith('/auth/me')) return ok(session)
    if (path.endsWith('/auth/logout')) return ok({ ok: true })
    if (path.endsWith('/auth/permissions')) return ok({ organization_id: org, user_id: userID, permissions: grants })
    if (path === '/api/v1/targets') return ok({ items: [target], next_cursor: null })
    if (path === `/api/v1/targets/${target.id}`) return ok(target)
    if (path === '/api/v1/runs/estimate') {
      const body = JSON.parse(String(options.body)) as EstimateInput
      quote = { ...draft(), target_version: body.target_version, package: body.package, budgets: { max_requests: body.options.max_requests ?? 60, max_tokens: body.options.max_tokens ?? 50000, max_cost_micros: body.options.max_cost_micros ?? null, timeout_seconds: (body.options.max_minutes ?? 15) * 60 } }
      quote.estimate.duration_seconds = quote.budgets.timeout_seconds
      if (quote.budgets.max_cost_micros !== null) quote.estimate.cost_micros = Math.min(1000, quote.budgets.max_cost_micros)
      return ok(quote)
    }
    if (path === '/api/v1/runs' && options.method === 'POST') { record = queued(quote); return ok(record, 202) }
    if (path === `/api/v1/runs/${record.id}/cancel`) { record = { ...record, status: 'CANCELLING', version: record.version + 1 }; return ok(record) }
    if (path === `/api/v1/runs/${record.id}`) return ok(record)
    throw new Error('Unexpected controlled test route')
  })
  vi.stubGlobal('fetch', calls); return calls
}
function renderTargets() { window.history.replaceState(null, '', '/#/targets'); return render(<App />) }
async function openConfiguration() {
  await screen.findByRole('button', { name: '配置检测 Run target' })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: '配置检测 Run target' })) })
}
async function estimate() { await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '配置检测并预估' })) }) }
async function confirm() { await act(async () => { const checkbox = screen.queryByRole('checkbox', { name: /我确认开始向该目标/ }); if (checkbox) fireEvent.click(checkbox); fireEvent.submit(screen.getByRole('form', { name: '确认检测费用' })) }) }
function requests(calls: ReturnType<typeof network>, path: string, method = 'POST') { return calls.mock.calls.filter(([url, options]) => String(url) === path && options?.method === method) }
function polls(calls: ReturnType<typeof network>) { return requests(calls, `/api/v1/runs/${queued().id}`, 'GET') }

describe('real Run configuration and explicit confirmation', () => {
  it('loads permissions only when configuration is opened and sends exact quick defaults without upstream actions', async () => {
    const calls = network(); renderTargets()
    await screen.findByRole('button', { name: '配置检测 Run target' })
    expect(requests(calls, '/api/v1/auth/permissions', 'GET')).toHaveLength(0)
    await openConfiguration()
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '配置检测：Run target' }))
    expect((screen.getByLabelText('请求预算') as HTMLInputElement).value).toBe('20')
    expect((screen.getByLabelText('Token 总预算') as HTMLInputElement).value).toBe('15000')
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
    await estimate()
    expect(screen.getByRole('heading', { name: '确认预估：快速检测' })).toBeTruthy()
    const request = requests(calls, '/api/v1/runs/estimate')[0][1]!
    expect(JSON.parse(String(request.body))).toEqual({ target_id: target.id, target_version: 4, package: 'quick', options: { max_requests: 20, max_tokens: 15000, max_cost_micros: null, max_minutes: 15, concurrency: 1, max_retries: 2 } })
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe(csrf)
    expect(new Headers(request.headers).get('X-Organization-ID')).toBe(org)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => String(url).includes('/precheck'))).toBe(false)
    expect(screen.getByText('价格未知，无法估算')).toBeTruthy()
  })
  it('uses fresh target versions and validates exact currency conversion', async () => {
    const calls = network((path) => path === `/api/v1/targets/${target.id}` ? ok({ ...target, version: 5 }) : undefined)
    renderTargets(); await openConfiguration()
    fireEvent.change(screen.getByLabelText('金额预算（USD，可留空）'), { target: { value: '1.234567' } })
    await estimate()
    const body = JSON.parse(String(requests(calls, '/api/v1/runs/estimate')[0][1]?.body))
    expect(body.target_version).toBe(5)
    expect(body.options.max_cost_micros).toBe(1234567)
  })
  it('supports explicit custom families, language, repeated samples, tiers and only-stream without silent changes', async () => {
    const calls = network(); renderTargets(); await openConfiguration()
    fireEvent.change(screen.getByLabelText('检测包'), { target: { value: 'custom' } })
    for (const name of ['精确格式契约', '中性任务行为', '成对差分', '风格观察']) fireEvent.click(screen.getByRole('checkbox', { name }))
    fireEvent.click(screen.getByRole('checkbox', { name: '简体中文' }))
    fireEvent.change(screen.getByLabelText('流式模式'), { target: { value: 'stream' } })
    fireEvent.change(screen.getByLabelText('输出上限档位（英文逗号分隔）'), { target: { value: '64,256,1024' } })
    fireEvent.change(screen.getByLabelText('每条件重复次数'), { target: { value: '5' } })
    await estimate()
    expect(JSON.parse(String(requests(calls, '/api/v1/runs/estimate')[0][1]?.body))).toMatchObject({ package: 'custom', options: { probe_types: ['sequence', 'jsonl'], languages: ['en-US'], repetitions: 5, stream_modes: [true], max_output_levels: [64, 256, 1024] } })
  })
  it('rejects invalid custom tiers and excessive precision locally instead of silently dropping input', async () => {
    const calls = network(); renderTargets(); await openConfiguration()
    fireEvent.change(screen.getByLabelText('金额预算（USD，可留空）'), { target: { value: '1.2345678' } }); await estimate()
    expect(screen.getByRole('alert').textContent).toContain('最多 6 位小数')
    fireEvent.change(screen.getByLabelText('检测包'), { target: { value: 'custom' } })
    fireEvent.change(screen.getByLabelText('输出上限档位（英文逗号分隔）'), { target: { value: '128,64' } }); await estimate()
    expect(screen.getByRole('alert').textContent).toContain('须严格递增')
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
  })
  it('enforces the actual service request, token, duration and monetary maxima before posting', async () => {
    const calls = network(); renderTargets(); await openConfiguration()
    for (const [label, invalid, restore] of [['请求预算', '1001', '20'], ['Token 总预算', '10000001', '15000'], ['最长执行时间（分钟）', '46', '15'], ['金额预算（USD，可留空）', '1000.000001', '']]) {
      fireEvent.change(screen.getByLabelText(label), { target: { value: invalid } }); await estimate()
      expect(screen.getByRole('alert')).toBeTruthy()
      expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
      fireEvent.change(screen.getByLabelText(label), { target: { value: restore } })
    }
  })
  it('does not infer organization grants from system_admin or role definitions', async () => {
    const calls = network((path) => path.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: [] }) : undefined)
    renderTargets(); await openConfiguration()
    expect((screen.getByRole('button', { name: '生成预估（不调用上游）' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('option', { name: '深度检测' }) as HTMLOptionElement).disabled).toBe(true)
    expect((screen.getByRole('option', { name: '自定义检测' }) as HTMLOptionElement).disabled).toBe(true)
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => String(url).includes('/roles'))).toBe(false)
  })
  it('keeps actions disabled when permission reads fail and does not create a fallback permission set', async () => {
    const calls = network((path) => path.endsWith('/auth/permissions') ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    renderTargets(); await openConfiguration()
    expect(screen.getByText(/无法确认当前有效权限/)).toBeTruthy()
    expect(screen.queryByRole('form', { name: '配置检测并预估' })).toBeNull()
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
  })
  it('requires high-cost permission for budget escalation and rereads authorization before estimate', async () => {
    let reads = 0
    const calls = network((path) => path.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ++reads === 1 ? ['run.create'] : [] }) : undefined)
    renderTargets(); await openConfiguration()
    fireEvent.change(screen.getByLabelText('请求预算'), { target: { value: '61' } }); await estimate()
    expect(screen.getByRole('alert').textContent).toContain('run.high-cost')
    fireEvent.change(screen.getByLabelText('请求预算'), { target: { value: '20' } }); await estimate()
    expect(screen.getByText('当前账号没有 run.create 权限，不能生成预估或创建检测。')).toBeTruthy()
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(0)
  })
  it('shows missing precheck, draft limits and unready backend errors without paid-call fallbacks', async () => {
    let code = 'MI_PRECHECK_REQUIRED'
    const calls = network((path) => path.endsWith('/runs/estimate') ? fail(code, code === 'MI_RUN_ESTIMATE_LIMIT' ? 429 : 409) : undefined)
    renderTargets(); await openConfiguration(); await estimate()
    expect(screen.getByText(/需要先完成该目标版本的预检/)).toBeTruthy()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/precheck'))).toBe(false)
    code = 'MI_RUN_ESTIMATE_LIMIT'; await estimate()
    expect(screen.getByText(/已达到活跃预估草稿限制/)).toBeTruthy()
    expect(document.body.textContent).not.toContain('private-upstream-diagnostic')
    expect(requests(calls, '/api/v1/runs')).toHaveLength(0)
  })
  it('requires explicit cost acknowledgement, creates one Run and does not present ANALYZING as completion', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok({ ...queued(), status: 'ANALYZING', version: 2, completed_samples: 18, valid_sample_count: 16, execution_closed_at: '2026-09-07T08:01:00Z' }) : undefined)
    renderTargets(); await openConfiguration(); await estimate()
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '确认检测费用' })) })
    expect(screen.getByRole('alert').textContent).toContain('勾选费用确认')
    expect(requests(calls, '/api/v1/runs')).toHaveLength(0)
    await confirm()
    expect(screen.getByRole('heading', { name: '本次检测：分析中' })).toBeTruthy()
    expect(screen.getByText(/分析尚未完成/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '分析结果（尚未接入）' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: '检测报告（尚未接入）' }) as HTMLButtonElement).disabled).toBe(true)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
    expect(polls(calls)).toHaveLength(1)
  })
  it('does not auto-rebuild or auto-resend an uncertain create and manually recovers the same body', async () => {
    let submits = 0
    const calls = network((path, options) => path === '/api/v1/runs' && options.method === 'POST' && ++submits === 1 ? Promise.reject(new Error('private transport details')) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByText(/创建结果不确定/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: '返回修改配置' })).toBeNull()
    expect((screen.getByRole('button', { name: '返回目标列表' }) as HTMLButtonElement).disabled).toBe(true)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
    await confirm()
    expect(screen.getByRole('heading', { name: '本次检测：已排队' })).toBeTruthy()
    const writes = requests(calls, '/api/v1/runs')
    expect(writes).toHaveLength(2); expect(writes[0][1]?.body).toBe(writes[1][1]?.body)
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(1)
    expect(document.body.textContent).not.toContain('private transport details')
  })
  it('blocks expired unused quotes and requires explicit re-estimate', async () => {
    const calls = network((path) => path.endsWith('/runs/estimate') ? ok({ ...draft(), expires_at: new Date(Date.now() - 1).toISOString() }) : undefined)
    renderTargets(); await openConfiguration(); await estimate()
    expect(screen.getByText(/此预估已到期/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '确认费用并创建检测' }) as HTMLButtonElement).disabled).toBe(true)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: '重新配置并预估' }))
    expect(screen.getByRole('form', { name: '配置检测并预估' })).toBeTruthy()
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(1)
  })
  it('allows same-draft uncertain recovery after expiration but never creates another draft automatically', async () => {
    let submits = 0
    const calls = network((path, options) => path === '/api/v1/runs' && options.method === 'POST' && ++submits === 1 ? Promise.reject(new Error('lost response')) : undefined)
    renderTargets(); await openConfiguration(); vi.useFakeTimers(); await estimate(); await confirm()
    await act(async () => { await vi.advanceTimersByTimeAsync(600001) })
    expect((screen.getByRole('button', { name: '恢复同一预估的提交结果' }) as HTMLButtonElement).disabled).toBe(false)
    await confirm()
    expect(screen.getByRole('heading', { name: '本次检测：已排队' })).toBeTruthy()
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(1)
    expect(requests(calls, '/api/v1/runs')[0][1]?.body).toBe(requests(calls, '/api/v1/runs')[1][1]?.body)
  })
  it('presents real execution-not-ready errors without inventing a completed Run', async () => {
    const calls = network((path, options) => path === '/api/v1/runs' && options.method === 'POST' ? fail('MI_EXECUTION_NOT_READY', 503) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByText(/检测执行或分析服务尚未就绪/)).toBeTruthy()
    expect(screen.queryByRole('heading', { name: /本次检测/ })).toBeNull()
    expect(screen.queryByRole('button', { name: '恢复同一预估的提交结果' })).toBeNull()
    expect((screen.getByRole('button', { name: '返回目标列表' }) as HTMLButtonElement).disabled).toBe(false)
    expect(polls(calls)).toHaveLength(0)
  })
  it('rereads permissions before confirmation and refuses revoked creation authority without a POST', async () => {
    let reads = 0
    const calls = network((path) => path.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ++reads < 3 ? grants : ['run.read'] }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByText(/当前有效权限不足/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '确认费用并创建检测' }) as HTMLButtonElement).disabled).toBe(true)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(0)
  })
  it('allows only one pending create and ignores its late response after leaving the organization', async () => {
    let resolve: ((value: Response) => void) | undefined
    const calls = network((path, options) => path === '/api/v1/runs' && options.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '确认检测费用' })) })
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), otherOrg)
    expect(requests(calls, '/api/v1/runs')[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(ok(queued(), 202)) })
    expect(screen.queryByRole('heading', { name: /本次检测/ })).toBeNull()
    expect(polls(calls)).toHaveLength(0)
  })
  it('signs out on a failed CSRF check without retrying a possibly submitted creation', async () => {
    const calls = network((path, options) => path === '/api/v1/runs' && options.method === 'POST' ? fail('MI_CSRF_INVALID', 403) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
    expect(polls(calls)).toHaveLength(0)
    expect(document.title).toBe('登录 · Model Integrity Inspector')
  })
  it('restores keyboard focus to the target heading when returning from configuration', async () => {
    network(); renderTargets(); await openConfiguration()
    const back = screen.getByRole('button', { name: '返回目标列表' }); back.focus()
    await userEvent.setup().keyboard('{Enter}')
    expect(screen.queryByRole('form', { name: '配置检测并预估' })).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织检测目标' }))
    expect(document.title).toBe('目标与模型档案 · Model Integrity Inspector')
  })
  it('renders conservative limits and omitted stream warnings without claiming supplier declarations', async () => {
    network((path) => path.endsWith('/runs/estimate') ? ok({ ...draft(), estimate: { ...draft().estimate, completeness: 'partial', warnings: ['MI_MODEL_LIMITS_CONSERVATIVE_ASSUMPTION', 'MI_STREAM_COMPARISON_DISABLED', 'MI_PRIVATE_WARNING_MARKER'] } }) : undefined)
    renderTargets(); await openConfiguration(); await estimate()
    expect(screen.getByText(/4096/).textContent).toContain('1024')
    expect(screen.getByText(/4096/).textContent).toContain('不是供应商')
    expect(screen.getByText(/探针覆盖不完整/)).toBeTruthy()
    expect(document.body.textContent).not.toContain('MI_PRIVATE_WARNING_MARKER')
  })
})

describe('fixed Run progress and cancellation', () => {
  it('polls one ID, stops on terminal status and renders safe error summaries only', async () => {
    let reads = 0
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok(++reads === 1 ? { ...queued(), status: 'RUNNING', version: 2, request_count: 1 } : { ...queued(), status: 'FAILED', version: 3, completed_samples: 18, finished_at: '2026-09-07T08:02:00Z', error_summary: [{ code: 'MI_AUTH_FAILED', count: 1 }, { code: 'MI_UNRECOGNIZED_PRIVATE_MARKER', count: 1 }] }) : undefined)
    renderTargets(); await openConfiguration(); vi.useFakeTimers(); await estimate(); await confirm()
    expect(polls(calls)).toHaveLength(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(screen.getByRole('heading', { name: '本次检测：失败' })).toBeTruthy()
    expect(document.body.textContent).not.toContain('MI_UNRECOGNIZED_PRIVATE_MARKER')
    await act(async () => { await vi.advanceTimersByTimeAsync(60000) })
    expect(polls(calls)).toHaveLength(2)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
  })
  it('rejects regressing versions without moving the tracked Run', async () => {
    let reads = 0
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok(++reads === 1 ? { ...queued(), status: 'RUNNING', version: 3 } : { ...queued(), status: 'RUNNING', version: 2 }) : undefined)
    renderTargets(); await openConfiguration(); vi.useFakeTimers(); await estimate(); await confirm()
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(screen.getByText('服务响应格式异常，请联系管理员。')).toBeTruthy()
    expect(screen.getByRole('heading', { name: '本次检测：采样执行中' })).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(50000) })
    expect(polls(calls)).toHaveLength(2)
  })
  it('requires cancel acknowledgement and current permission, uses version, and preserves progress while cancelling', async () => {
    const calls = network(); renderTargets(); await openConfiguration(); await estimate(); await confirm()
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '取消检测' })) })
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(0)
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认停止后续采样/ }))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '取消检测' })) })
    expect(screen.getByRole('heading', { name: '本次检测：正在取消' })).toBeTruthy()
    expect(screen.getByText(/当前不是“已取消”状态/)).toBeTruthy()
    expect(JSON.parse(String(requests(calls, `/api/v1/runs/${queued().id}/cancel`)[0][1]?.body))).toEqual({ version: 1 })
    expect(screen.queryByRole('button', { name: '确认取消检测' })).toBeNull()
  })
  it('does not let cancel-own permission cancel somebody else’s Run', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok({ ...queued(), created_by: '9007199254740999' }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    // The changed creator is inconsistent with the pinned original and rejected.
    expect(screen.getByText('服务响应格式异常，请联系管理员。')).toBeTruthy()
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(0)
  })
  it('aborts a pending status read on organization switch and ignores a stale response', async () => {
    let resolve: ((value: Response) => void) | undefined
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), otherOrg)
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(ok({ ...queued(), status: 'COMPLETED', version: 2 })) })
    expect(screen.queryByRole('heading', { name: /本次检测/ })).toBeNull()
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
  })
  it('aborts polling on logout and does not cancel the backend Run implicitly', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? new Promise<Response>(() => {}) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    await userEvent.setup().click(screen.getByRole('button', { name: '退出登录' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(0)
  })
  it('enforces the temporary-password gate without retrying the rejected estimate', async () => {
    let recovery = false
    const calls = network((path) => {
      if (path.endsWith('/runs/estimate')) { recovery = true; return fail('MI_PASSWORD_CHANGE_REQUIRED', 403) }
      if (path.endsWith('/auth/me') && recovery) return ok({ ...session, user: { ...session.user, must_change_password: true } })
      return undefined
    })
    renderTargets(); await openConfiguration(); await estimate()
    expect(screen.getByRole('heading', { name: '修改密码' })).toBeTruthy()
    expect(screen.queryByRole('form', { name: '配置检测并预估' })).toBeNull()
    expect(requests(calls, '/api/v1/runs/estimate')).toHaveLength(1)
  })
  it('does not permit cancellation after the execution stage closes even if the status is still RUNNING', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok({ ...queued(), status: 'RUNNING', version: 2, execution_closed_at: '2026-09-07T08:02:00Z' }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByText(/执行阶段已经关闭/)).toBeTruthy()
    expect(screen.queryByRole('form', { name: '取消检测' })).toBeNull()
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(0)
  })
  it('recovers an unknown cancellation using only a fixed-ID read and cannot repeat the pending write', async () => {
    let reads = 0, resolve: ((value: Response) => void) | undefined
    const calls = network((path) => {
      if (path.endsWith('/cancel')) return Promise.reject(new Error('private cancellation transport'))
      if (path === `/api/v1/runs/${queued().id}` && ++reads > 1) return new Promise<Response>((done) => { resolve = done })
      return undefined
    })
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认停止后续采样/ }))
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '取消检测' })) })
    expect(screen.getByText(/取消请求结果不确定/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '确认取消检测' }) as HTMLButtonElement).disabled).toBe(true)
    await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '取消检测' })) })
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(1)
    expect(polls(calls)).toHaveLength(2)
    await act(async () => { resolve?.(ok({ ...queued(), status: 'CANCELLED', version: 2, finished_at: '2026-09-07T08:02:00Z' })) })
    expect(screen.getByRole('heading', { name: '本次检测：已取消' })).toBeTruthy()
    expect(document.body.textContent).not.toContain('private cancellation transport')
  })
  it('halts fixed-ID polling on session expiration without cancelling or recreating the Run', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? fail('MI_SESSION_REQUIRED', 401) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(polls(calls)).toHaveLength(1)
    expect(polls(calls)[0][1]?.signal?.aborted).toBe(true)
    expect(requests(calls, '/api/v1/runs')).toHaveLength(1)
    expect(requests(calls, `/api/v1/runs/${queued().id}/cancel`)).toHaveLength(0)
  })
  it('rejects a different manifest and retains the last accepted record', async () => {
    const calls = network((path) => path === `/api/v1/runs/${queued().id}` ? ok({ ...queued(), manifest_hash: 'b'.repeat(64), status: 'COMPLETED', version: 2 }) : undefined)
    renderTargets(); await openConfiguration(); await estimate(); await confirm()
    expect(screen.getByText('服务响应格式异常，请联系管理员。')).toBeTruthy()
    expect(screen.getByRole('heading', { name: '本次检测：已排队' })).toBeTruthy()
    expect(polls(calls)).toHaveLength(1)
  })
})
