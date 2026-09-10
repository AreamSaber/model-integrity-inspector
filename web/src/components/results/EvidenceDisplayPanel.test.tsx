import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EvidenceDisplayPanel } from './EvidenceDisplayPanel'
import { ResultsPage } from './ResultsPage'
import { evidenceDisplayStatuses, type EvidenceDisplay } from '../../evidence-display-api'
import { detailed, finding, org, runID, sample, sampleDetail, sampleID, summary, userID } from './test-fixtures'

const attemptID = '9007199254741041'
const props = { organizationID: org, userID, runID, sampleID, attemptID, analysisRevision: 1, isFinal: true, csrfToken: 'unused-synthetic-csrf', onDenied: vi.fn<(failure: unknown) => void>(), onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
const canary = '<img src="x" onerror="alert(1)"> **synthetic S2 body**', requestJSON = '{"messages":[{"role":"user","content":"[REDACTED]"}],"seed":9223372036854775807}'
function value(): EvidenceDisplay {
  return { version: 'mii.evidence-display-output.v1', run_id: runID, sample_id: sampleID, attempt_id: attemptID, analysis_revision: 1, is_final: true, status: 'available', payload_hash: 'a'.repeat(64), content: {
    version: 1, policy: 'display-redaction-v1', source_hash: 'b'.repeat(64), request_hash: 'c'.repeat(64), template_hash: 'd'.repeat(64), request_json: requestJSON, request_changed: true, metadata_omitted: true,
    response: { content: canary, model_reported: 'synthetic-model', http_status: 200, finish_reason: 'stop', parse_status: 'valid', prompt_tokens: null, completion_tokens: 10, total_tokens: null, reasoning_tokens: null, duration_ms: 100, first_token_ms: null, stream_terminated: false, events: null, event_summary_partial: true },
  } }
}
const ok = (data: unknown) => Response.json({ data, request_id: 'evidence-panel-test' })
const fail = (status: number) => Response.json({ error: { code: status === 401 ? 'MI_SESSION_REQUIRED' : 'MI_PERMISSION_DENIED', message: 'PRIVATE_ERROR_CANARY' }, request_id: 'evidence-panel-error' }, { status })
type Handler = (url: URL, options: RequestInit) => Response | Promise<Response> | undefined
function network(handler?: Handler, permissions = ['run.read', 'evidence.read', 'evidence.body']) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), result = handler?.(url, options)
    if (result) return result
    if (url.pathname.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions })
    if (url.pathname.endsWith('/evidence')) return ok(value())
    if (url.pathname.endsWith('/result')) return ok(url.searchParams.has('include') ? detailed() : summary())
    if (url.pathname.endsWith(`/samples/${sampleID}`)) return ok(sampleDetail())
    if (url.pathname.endsWith('/samples')) return ok({ items: [sample()], next_cursor: null })
    if (url.pathname.endsWith('/findings')) return ok({ items: [finding()], next_cursor: null })
    throw new Error('Unexpected request PRIVATE_ERROR_CANARY')
  })
  vi.stubGlobal('fetch', calls); return calls
}
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
const read = () => click(`查看 Attempt ${attemptID} 的脱敏正文`)
const reread = () => click(`重新核验并读取 Attempt ${attemptID} 正文`)
async function available() { await screen.findByText(canary, { selector: 'pre' }) }
beforeEach(() => { props.onDenied.mockClear(); props.onSignedOut.mockClear(); props.onPasswordRequired.mockClear() })

describe('explicit isolated S2 response display panel', () => {
  it('labels server-verified deletion without inventing a body or treating an unproven 503 as deleted', async () => {
    let deleted = true
    network((url) => url.pathname.endsWith('/evidence') ? deleted ? ok({ ...value(), status: 'unavailable_deleted', content: null }) : Response.json({ error: { code: 'MI_EVIDENCE_UNAVAILABLE' }, request_id: 'unproven-missing' }, { status: 503 }) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read()
    expect(await screen.findByText(/服务器已核验删除凭证/)).toBeTruthy()
    expect(document.querySelector('pre')).toBeNull()
    deleted = false; await reread()
    expect(screen.queryByText(/服务器已核验删除凭证/)).toBeNull()
    expect(screen.getByRole('alert')).toBeTruthy(); expect(document.querySelector('pre')).toBeNull()
  })
  it('does not fetch even permissions on mount; only an explicit click reads current permissions then S2', async () => {
    const calls = network(); render(<EvidenceDisplayPanel {...props} />)
    expect(calls).not.toHaveBeenCalled(); expect(screen.queryByText(canary)).toBeNull()
    await read(); await available()
    expect(calls.mock.calls.map(([url]) => String(url))).toEqual(['/api/v1/auth/permissions', `/api/v1/runs/${runID}/samples/${sampleID}/attempts/${attemptID}/evidence?analysis_revision=1`])
    expect(calls.mock.calls.every(([, options]) => options?.method === 'GET' && options.cache === 'no-store')).toBe(true)
    expect(localStorage.length + sessionStorage.length).toBe(0)
    expect(document.querySelector('a[download],iframe')).toBeNull()
  })
  it('renders body and original request string as escaped text, preserving large seed and null Usage', async () => {
    network(); render(<EvidenceDisplayPanel {...props} />); await read(); await available()
    expect(document.querySelector('img,script,iframe,strong')).toBeNull()
    expect(screen.getByText(requestJSON, { selector: 'pre' }).textContent).toBe(requestJSON)
    expect(screen.getAllByText(/未测 \/ 不可估/).length).toBeGreaterThan(0)
    expect(screen.getByText(/请求已发生脱敏替换/)).toBeTruthy()
    expect(screen.getByText(`实际请求哈希：${'c'.repeat(64)}`)).toBeTruthy()
    expect(screen.getByText(`脱敏模板哈希：${'d'.repeat(64)}`)).toBeTruthy()
    expect(screen.getByText(/流式事件摘要不完整/)).toBeTruthy()
    for (const pre of document.querySelectorAll('pre')) { expect(pre.className).toContain('review-explanation'); expect(pre.style.maxWidth).toBe('100%'); expect(pre.style.overflowX).toBe('auto') }
    expect(document.activeElement?.textContent).toBe(`Attempt ${attemptID} · 授权正文`)
  })
  it.each([{ permissions: ['run.read', 'evidence.read'] }, { permissions: ['run.read', 'evidence.body'] }, { permissions: ['evidence.read', 'evidence.body'] }, { permissions: ['report.export'] }, { permissions: [] }])('requires all real body permissions, not evidence.read or export alone: $permissions', async ({ permissions }) => {
    const calls = network(undefined, permissions); render(<EvidenceDisplayPanel {...props} />); await read()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/attempts/'))).toBe(false)
    expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/已清除正文并停止读取/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` })).toBeNull()
  })
  it('clears existing S2 immediately before a manual re-read and refuses subsequently revoked permissions without another body fetch', async () => {
    let grants = true, release: ((response: Response) => void) | undefined
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') && !grants ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read(); await available(); grants = false; await reread()
    expect(screen.queryByText(canary)).toBeNull()
    await act(async () => release!(ok({ organization_id: org, user_id: userID, permissions: ['run.read', 'evidence.read'] })))
    expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/attempts/'))).toHaveLength(1)
  })
  it.each([401, 403])('clears S2 and aborts on a late HTTP %s denial without displaying server messages', async (status) => {
    let denied = false, signal: AbortSignal | null | undefined
    network((url, options) => { if (url.pathname.endsWith('/evidence') && denied) { signal = options.signal; return fail(status) }; return undefined })
    render(<EvidenceDisplayPanel {...props} />); await read(); await available(); denied = true; await reread()
    expect(screen.queryByText(canary)).toBeNull(); expect(signal?.aborted).toBe(true)
    expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(props.onSignedOut).toHaveBeenCalledTimes(status === 401 ? 1 : 0)
    expect(document.body.textContent).not.toContain('PRIVATE_ERROR_CANARY')
  })
  it('treats malformed 403 as a session downgrade and clears everything', async () => {
    network((url) => url.pathname.endsWith('/evidence') ? new Response('<html>PRIVATE_ERROR_CANARY', { status: 403 }) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read()
    expect(props.onSignedOut).toHaveBeenCalledTimes(1); expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(document.querySelector('pre')).toBeNull(); expect(document.body.textContent).not.toContain('PRIVATE_ERROR_CANARY')
  })
  it.each([
    { organizationID: '9007199254740996' }, { userID: '9007199254740994' }, { runID: '9007199254741024' }, { sampleID: '9007199254741032' }, { attemptID: '9007199254741042' }, { analysisRevision: 2 }, { isFinal: false },
  ])('clears visible S2 and does not auto-fetch on scope change %j', async (changed) => {
    const calls = network(), view = render(<EvidenceDisplayPanel {...props} />); await read(); await available()
    view.rerender(<EvidenceDisplayPanel {...props} {...changed} />)
    expect(screen.queryByText(canary)).toBeNull(); expect(calls).toHaveBeenCalledTimes(2)
    expect(screen.queryByText(requestJSON)).toBeNull()
  })
  it.each(['close', 'unmount', 'scope'])('aborts pending uncooperative S2 and rejects late replies after %s', async (action) => {
    let release: ((response: Response) => void) | undefined, signal: AbortSignal | null | undefined
    network((url, options) => url.pathname.endsWith('/evidence') ? new Promise<Response>((resolve) => { release = resolve; signal = options.signal }) : undefined)
    const view = render(<EvidenceDisplayPanel {...props} />); await read(); await waitFor(() => expect(release).toBeTypeOf('function'))
    if (action === 'close') await click(`关闭并清除 Attempt ${attemptID} 正文`)
    else if (action === 'unmount') view.unmount()
    else view.rerender(<EvidenceDisplayPanel {...props} userID="9007199254740994" />)
    expect(signal?.aborted).toBe(true)
    await act(async () => release!(ok(value())))
    expect(screen.queryByText(canary)).toBeNull(); expect(screen.queryByText(requestJSON)).toBeNull()
    expect(props.onDenied).not.toHaveBeenCalled()
  })
  it('cancels pending permission checks when closed, prevents double clicks and requires a fresh action to reopen', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    render(<EvidenceDisplayPanel {...props} />)
    const button = screen.getByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` })
    await act(async () => { fireEvent.click(button); fireEvent.click(button) }); expect(calls).toHaveBeenCalledTimes(1)
    await click(`关闭并清除 Attempt ${attemptID} 正文`)
    await act(async () => release!(ok({ organization_id: org, user_id: userID, permissions: ['run.read', 'evidence.read', 'evidence.body'] })))
    expect(calls).toHaveBeenCalledTimes(1); expect(screen.queryByText(canary)).toBeNull()
    expect(screen.getByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` })).toBeTruthy()
  })
  it.each(evidenceDisplayStatuses.filter((status) => status !== 'available'))('shows %s as unavailable, never an invented empty body', async (status) => {
    network((url) => url.pathname.endsWith('/evidence') ? ok({ ...value(), status, content: null }) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read()
    await screen.findByText(/分析修订 1 ·/)
    expect(document.querySelector('pre')).toBeNull()
    expect(screen.queryByText(/响应正文为空字符串/)).toBeNull()
    expect(document.querySelector('.notice.warning')).toBeTruthy()
  })
  it('distinguishes authenticated empty content and unchanged request from missing evidence', async () => {
    const data = value(); data.content!.response.content = ''; data.content!.template_hash = data.content!.request_hash; data.content!.request_changed = false
    network((url) => url.pathname.endsWith('/evidence') ? ok(data) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read()
    expect(await screen.findByText(/已认证展示副本中的响应正文为空字符串/)).toBeTruthy()
    expect(screen.getByText(/响应内容仍可能已脱敏/)).toBeTruthy()
  })
  it('does not retain previous plaintext after a corrupt refresh or invent body download controls', async () => {
    let corrupt = false
    network((url) => url.pathname.endsWith('/evidence') && corrupt ? ok({ ...value(), attempt_id: '2' }) : undefined)
    render(<EvidenceDisplayPanel {...props} />); await read(); await available(); corrupt = true; await reread()
    expect(screen.queryByText(canary)).toBeNull(); expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /下载|重放/ })).toBeNull()
  })
})

describe('response display wired into actual results sample inspection', () => {
  it('selects exactly one Attempt and cancels its in-flight body when switching to another retry', async () => {
    const otherAttempt = '9007199254741042', detail = sampleDetail()
    detail.attempts.push({ ...detail.attempts[0], id: otherAttempt, attempt_no: 2 })
    let release: ((response: Response) => void) | undefined, signal: AbortSignal | null | undefined
    const calls = network((url, options) => {
      if (url.pathname.endsWith(`/samples/${sampleID}`)) return ok(detail)
      if (url.pathname.endsWith(`/attempts/${otherAttempt}/evidence`)) return new Promise<Response>((resolve) => { release = resolve; signal = options.signal })
      return undefined
    })
    render(<ResultsPage {...props} />)
    await screen.findByRole('heading', { name: '修订 1 · 结果总览' }); await click('S1 证据'); await click(`读取样本 ${sampleID} 的尝试记录`)
    await screen.findByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` }); await read(); await available()
    fireEvent.change(screen.getByLabelText('选择要查看正文的 Attempt'), { target: { value: otherAttempt } })
    expect(screen.queryByText(canary)).toBeNull()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/attempts/'))).toHaveLength(1)
    await click(`查看 Attempt ${otherAttempt} 的脱敏正文`); await waitFor(() => expect(release).toBeTypeOf('function'))
    fireEvent.change(screen.getByLabelText('选择要查看正文的 Attempt'), { target: { value: attemptID } })
    expect(signal?.aborted).toBe(true)
    await act(async () => release!(ok({ ...value(), attempt_id: otherAttempt, is_final: false })))
    expect(screen.queryByText(canary)).toBeNull()
    expect(screen.queryByRole('heading', { name: `Attempt ${otherAttempt} · 授权正文` })).toBeNull()
    expect(screen.getByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` })).toBeTruthy()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/attempts/'))).toHaveLength(2)
  })
  it('keeps initial result, S1 tab and sample inspection body-free until the explicit authorized attempt button', async () => {
    const calls = network(); render(<ResultsPage {...props} />)
    await screen.findByRole('heading', { name: '修订 1 · 结果总览' }); await click('S1 证据'); await click(`读取样本 ${sampleID} 的尝试记录`)
    await screen.findByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` })
    expect(calls.mock.calls.some(([url]) => String(url).includes('/attempts/'))).toBe(false)
    await read(); await available()
    await click('关闭样本详情')
    expect(screen.queryByText(canary)).toBeNull(); expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('does not expose a body button for evidence.read alone', async () => {
    const calls = network(undefined, ['run.read', 'evidence.read']); render(<ResultsPage {...props} />)
    await screen.findByRole('heading', { name: '修订 1 · 结果总览' }); await click('S1 证据'); await click(`读取样本 ${sampleID} 的尝试记录`)
    await screen.findByText(/查看脱敏正文还需要 evidence.body 权限/)
    expect(screen.queryByRole('button', { name: /的脱敏正文/ })).toBeNull()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/attempts/'))).toBe(false)
  })
  it('clears the entire parent S1/evidence view when body authorization is revoked', async () => {
    network((url) => url.pathname.endsWith('/evidence') ? fail(403) : undefined)
    render(<ResultsPage {...props} />)
    await screen.findByRole('heading', { name: '修订 1 · 结果总览' }); await click('S1 证据'); await click(`读取样本 ${sampleID} 的尝试记录`)
    await screen.findByRole('button', { name: `查看 Attempt ${attemptID} 的脱敏正文` }); await read()
    expect(screen.getByText(/已清除结果与证据缓存/)).toBeTruthy()
    expect(screen.queryByText('Development token observation')).toBeNull()
    expect(screen.queryByText(canary)).toBeNull()
  })
})
