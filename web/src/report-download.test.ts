// @ts-expect-error -- Test-only Node built-in is present in the pinned runner; the browser project deliberately has no Node ambient type dependency.
import { createHash, webcrypto } from 'node:crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { downloadReport } from './report-download'
import type { Report } from './reports-api'

const org = '9007199254740993'
const bytes = (value: string) => new TextEncoder().encode(value)
const checksum = (value: Uint8Array) => `sha256:${createHash('sha256').update(value).digest('hex')}`
const mimeTypes = { json: 'application/json', html: 'text/html', csv: 'text/csv' } as const
const csvBytes = bytes('csv_schema,path,value_type,json_value\r\nmii.report.csv.v1,,object,{}\r\n')
function record(body = bytes('{"safe":"S1"}')): Report { return { id: '9007199254740997', run_id: '9007199254740995', analysis_revision: 1, revision: 2, format: 'json', schema_version: 'mii.report.v1', status: 'ready', created_at: '2026-09-07T10:00:00Z', review_state: 'not_included', content_hash: `sha256:${'a'.repeat(64)}`, file_hash: checksum(body), file_size: body.length } }
function response(value: Report, body: BodyInit = bytes('{"safe":"S1"}'), change: Record<string, string> = {}) {
  return new Response(body, { headers: { 'Content-Type': `${mimeTypes[value.format]}; charset=utf-8`, 'Content-Disposition': `attachment; filename="report-${value.id}-r${value.revision}.${value.format}"`, 'Content-Length': String(value.file_size), 'X-Report-Content-Hash': value.content_hash!, 'X-Report-File-Hash': value.file_hash!, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'", ...change } })
}
function fetchResponse(value: Response) { const fetcher = vi.fn<typeof fetch>().mockResolvedValue(value); vi.stubGlobal('fetch', fetcher); return fetcher }
beforeEach(() => { vi.stubGlobal('crypto', webcrypto) })

describe('bounded verified report downloads', () => {
  it.each(['json', 'html', 'csv'] as const)('verifies actual SHA-256 bytes and returns a non-executed %s Blob', async (format) => {
    const data = format === 'csv' ? csvBytes : bytes(format === 'html' ? '<!doctype html><html><body>S1 中文</body></html>' : '{"safe":"S1 中文"}')
    const value = { ...record(data), format }, fetcher = fetchResponse(response(value, data))
    const file = await downloadReport(org, value)
    expect(file.blob.size).toBe(data.length); expect(file.blob.type).toBe(`${mimeTypes[format]}; charset=utf-8`)
    expect(file.filename).toBe(`report-${value.id}-r2.${format}`)
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/reports/${value.id}/download`)
    const options = fetcher.mock.calls[0][1]!
    expect(options.redirect).toBe('error'); expect(options.credentials).toBe('same-origin'); expect(options.cache).toBe('no-store')
    expect(new Headers(options.headers).get('X-Organization-ID')).toBe(org)
    expect(new Headers(options.headers).get('Accept')).toBe(mimeTypes[format])
    expect(document.querySelector('iframe')).toBeNull(); expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each(['application/json; charset=utf-8', 'text/html; charset=utf-8', 'text/csv', 'text/csv; charset=iso-8859-1', 'application/octet-stream'])('rejects CSV with an incorrect MIME or missing UTF-8 charset: %s', async (contentType) => {
    const value: Report = { ...record(csvBytes), format: 'csv' }
    fetchResponse(response(value, csvBytes, { 'Content-Type': contentType }))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects CSV attachment substitution, exact-length tampering and a wrong file hash independently of content hash', async () => {
    const value: Report = { ...record(csvBytes), format: 'csv' }
    fetchResponse(response(value, csvBytes, { 'Content-Disposition': `attachment; filename="report-${value.id}-r2.json"` }))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    const changed = csvBytes.slice(); changed[0] = 'x'.charCodeAt(0)
    fetchResponse(response(value, changed))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    fetchResponse(response(value, csvBytes, { 'X-Report-File-Hash': value.content_hash! }))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('never falls back to JSON for an unknown format or accepts CSV profile as the document schema', async () => {
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    for (const invalid of [{ ...record(), format: 'pdf' }, { ...record(), format: 'csv', schema_version: 'mii.report.csv.v1' }]) {
      await expect(downloadReport(org, invalid as Report)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    }
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('cancels a stalled CSV body on scope withdrawal without returning a Blob', async () => {
    const value: Report = { ...record(csvBytes), format: 'csv' }, controller = new AbortController(), cancel = vi.fn<() => void>()
    fetchResponse(response(value, new ReadableStream<Uint8Array>({ cancel })))
    const pending = downloadReport(org, value, controller.signal).catch((failure: unknown) => failure)
    await Promise.resolve(); controller.abort()
    expect(await pending).toMatchObject({ name: 'AbortError' }); expect(cancel).toHaveBeenCalled()
  })
  it.each([401, 403])('withdraws CSV authority on HTTP %s even with malformed denial bytes', async (status) => {
    const value: Report = { ...record(csvBytes), format: 'csv' }, cancel = vi.fn<() => void>()
    fetchResponse(new Response(new ReadableStream<Uint8Array>({ cancel }), { status, headers: { 'Content-Type': 'text/csv' } }))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
    expect(cancel).toHaveBeenCalled()
  })
  it.each<Record<string, string>>([
    { 'Content-Type': 'text/plain' }, { 'Content-Disposition': 'inline' }, { 'Content-Disposition': 'attachment; filename="../secret.html"' },
    { 'Content-Security-Policy': 'sandbox allow-scripts' }, { 'X-Content-Type-Options': 'sniff' }, { 'X-Report-Content-Hash': `sha256:${'c'.repeat(64)}` },
    { 'X-Report-File-Hash': `sha256:${'c'.repeat(64)}` }, { 'Content-Length': '1' }, { 'Content-Length': '16777217' }, { 'Content-Encoding': 'gzip' },
  ])('fails closed for unsafe or inconsistent response headers %#', async (headers) => {
    fetchResponse(response(record(), undefined, headers))
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects same-length byte tampering even if every response header matches', async () => {
    fetchResponse(response(record(), bytes('x'.repeat(record().file_size!))))
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects malformed UTF-8 even if attacker-provided metadata hashes match the invalid bytes', async () => {
    const invalid = new Uint8Array([0x61, 0xc3, 0x28]), value = record(invalid)
    fetchResponse(response(value, invalid))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects truncated or absent success bodies before creating a Blob', async () => {
    fetchResponse(response(record(), bytes('a')))
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    const value = response(record()); Object.defineProperty(value, 'body', { value: null }); fetchResponse(value)
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([401, 403])('invalidates session immediately for HTTP %s, including infinite denial bodies', async (status) => {
    const cancel = vi.fn<() => void>(), body = new ReadableStream<Uint8Array>({ cancel })
    fetchResponse(new Response(body, { status, headers: { 'Content-Type': 'text/html', 'Content-Length': '999999999' } }))
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
    expect(cancel).toHaveBeenCalled()
  })
  it('bounds other error bodies to 64KiB and never includes server messages', async () => {
    fetchResponse(Response.json({ error: { code: 'MI_REPORT_FILE_UNAVAILABLE', message: 'SECRET_CANARY' } }, { status: 503 }))
    const error = await downloadReport(org, record()).catch((failure: unknown) => failure)
    expect(error).toMatchObject({ code: 'MI_REPORT_FILE_UNAVAILABLE', status: 503 }); expect(String(error)).not.toContain('SECRET_CANARY')
    fetchResponse(new Response(' '.repeat(65537), { status: 503, headers: { 'Content-Type': 'application/json' } }))
    await expect(downloadReport(org, record())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects an oversized stream without trusting the declared length and cancels the reader', async () => {
    const cancel = vi.fn<() => void>(), value = { ...record(), file_size: 16777216 }
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array(16777217)) }, cancel }, { highWaterMark: 0 })
    fetchResponse(response(value, stream))
    await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(cancel).toHaveBeenCalled()
  })
  it('bounds pathological empty and tiny-chunk streams without starving cancellation timers', async () => {
    for (const tiny of [false, true]) {
      let reads = 0
      const cancel = vi.fn<() => void>(), value = { ...record(), file_size: 16777216 }
      const stream = new ReadableStream<Uint8Array>({ pull(controller) { reads++; controller.enqueue(tiny ? bytes(' ') : new Uint8Array()) }, cancel }, { highWaterMark: 0 })
      fetchResponse(response(value, stream))
      await expect(downloadReport(org, value)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
      expect(reads).toBeLessThanOrEqual(tiny ? 131073 : 1026); expect(cancel).toHaveBeenCalled()
    }
  })
  it('aborts an uncooperative stalled body on scope change and cancels the reader', async () => {
    const controller = new AbortController(), cancel = vi.fn<() => void>()
    fetchResponse(response(record(), new ReadableStream<Uint8Array>({ cancel })))
    const pending = downloadReport(org, record(), controller.signal).catch((failure: unknown) => failure)
    await Promise.resolve(); controller.abort()
    expect(await pending).toMatchObject({ name: 'AbortError' })
    expect(cancel).toHaveBeenCalled()
  })
  it('has a 60-second total deadline even if fetch never settles', async () => {
    vi.useFakeTimers(); vi.stubGlobal('fetch', vi.fn<typeof fetch>(() => new Promise(() => {})))
    const pending = downloadReport(org, record()).catch((failure: unknown) => failure)
    await vi.advanceTimersByTimeAsync(60000)
    expect(await pending).toMatchObject({ code: 'MI_NETWORK_ERROR' })
  })
  it('rejects local malformed metadata before fetch and discards unsafe transport error details', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new Error('SECRET_CANARY https://private/path')); vi.stubGlobal('fetch', fetcher)
    await expect(downloadReport(org, { ...record(), status: 'queued' })).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    expect(fetcher).not.toHaveBeenCalled()
    const error = await downloadReport(org, record()).catch((failure: unknown) => failure)
    expect(error).toMatchObject({ code: 'MI_NETWORK_ERROR' }); expect(String(error)).not.toContain('SECRET_CANARY')
  })
})
