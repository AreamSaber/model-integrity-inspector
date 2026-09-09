import { ApiError, object } from './api'
import { report, reportMaximumBytes, type Report, type ReportFormat } from './reports-api'
import { readScope } from './runs-history-api'

export interface ReportFile { blob: Blob; filename: string }
const maximumErrorBytes = 64 * 1024, maximumReadOperations = 131072, timeoutMS = 60000
const downloadCSP = "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'"
function cancelled() { return new DOMException('Download cancelled', 'AbortError') }
function check(signal: AbortSignal) { if (signal.aborted) throw cancelled() }
function cancelBody(body: ReadableStream<Uint8Array> | null) { try { void body?.cancel().catch(() => {}) } catch { /* best effort */ } }
function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const stop = () => { signal.removeEventListener('abort', stop); reject(cancelled()) }
    signal.addEventListener('abort', stop, { once: true })
    promise.then((value) => { signal.removeEventListener('abort', stop); resolve(value) }, () => { signal.removeEventListener('abort', stop); reject(new ApiError('MI_NETWORK_ERROR')) })
    if (signal.aborted) stop()
  })
}
async function readBytes(response: Response, signal: AbortSignal, maximum: number, expected?: number) {
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined, complete = false
  let received = 0, operations = 0, emptyReads = 0
  const chunks: Uint8Array<ArrayBuffer>[] = []
  try {
    check(signal)
    if (!response.body) throw new ApiError('MI_INVALID_RESPONSE')
    reader = response.body.getReader()
    const decoder = new TextDecoder('utf-8', { fatal: true })
    for (;;) {
      check(signal)
      if (++operations > maximumReadOperations) throw new ApiError('MI_INVALID_RESPONSE')
      const part = await abortable(reader.read(), signal)
      check(signal)
      if (part.done) { complete = true; break }
      if (!ArrayBuffer.isView(part.value) || Object.prototype.toString.call(part.value) !== '[object Uint8Array]') throw new ApiError('MI_INVALID_RESPONSE')
      received += part.value.byteLength
      if (received > maximum || (expected !== undefined && received > expected)) throw new ApiError('MI_INVALID_RESPONSE')
      if (part.value.byteLength === 0) { if (++emptyReads > 1024) throw new ApiError('MI_INVALID_RESPONSE'); continue }
      emptyReads = 0
      try { decoder.decode(part.value, { stream: true }) } catch { throw new ApiError('MI_INVALID_RESPONSE') }
      chunks.push(new Uint8Array(part.value))
    }
    try { decoder.decode() } catch { throw new ApiError('MI_INVALID_RESPONSE') }
    if (received === 0 || (expected !== undefined && received !== expected)) throw new ApiError('MI_INVALID_RESPONSE')
    const bytes = new Uint8Array(received)
    let offset = 0
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
    return bytes
  } finally {
    chunks.length = 0
    if (reader) {
      if (!complete) { try { void reader.cancel().catch(() => {}) } catch { /* best effort */ } }
      try { reader.releaseLock() } catch { /* pending read may still settle */ }
    } else cancelBody(response.body)
  }
}
function lengthHeader(response: Response, maximum: number, required: boolean) {
  const header = response.headers.get('Content-Length')
  if (header === null && !required) return undefined
  if (header === null || !/^[0-9]{1,16}$/.test(header) || !Number.isSafeInteger(Number(header)) || Number(header) < 1 || Number(header) > maximum) throw new ApiError('MI_INVALID_RESPONSE')
  return Number(header)
}
function jsonType(value: string) { return /^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(value) }
function reportMIME(format: ReportFormat): string {
  switch (format) {
    case 'json': return 'application/json'
    case 'html': return 'text/html'
    case 'csv': return 'text/csv'
    default: throw new ApiError('MI_INVALID_REQUEST')
  }
}

// Returns a verified file, never a URL to navigate/iframe and never parsed HTML.
// Caller must refresh current permissions before calling and discard this Blob
// after the explicit save action. No local/session storage or filesystem write.
export async function downloadReport(orgID: string, value: Report, userSignal?: AbortSignal): Promise<ReportFile> {
  const headers = readScope(orgID)
  if (!report(value) || value.status !== 'ready') throw new ApiError('MI_INVALID_REQUEST')
  const expected = Object.freeze({ ...value })
  const mime = reportMIME(expected.format)
  const timeout = new AbortController(), timer = setTimeout(() => timeout.abort(), timeoutMS)
  const signal = userSignal ? AbortSignal.any([userSignal, timeout.signal]) : timeout.signal
  let response: Response | undefined
  try {
    check(signal)
    response = await abortable<Response>(fetch(`/api/v1/reports/${expected.id}/download`, { method: 'GET', credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: { ...headers, Accept: mime }, signal }).then((result) => { response = result; if (signal.aborted) { cancelBody(result.body); throw cancelled() }; return result }), signal)
    // Status alone is sufficient to withdraw UI authority. A malformed, huge,
    // wrong-type or stalled denial body cannot preserve an authenticated view.
    if (response.status === 401 || response.status === 403) throw new ApiError('MI_SESSION_REQUIRED', response.status)
    check(signal)
    const encoding = response.headers.get('Content-Encoding')?.trim().toLowerCase()
    if (encoding && encoding !== 'identity') throw new ApiError('MI_INVALID_RESPONSE')
    if (!response.ok) {
      if (!jsonType(response.headers.get('Content-Type') ?? '')) throw new ApiError('MI_INVALID_RESPONSE')
      const bytes = await readBytes(response, signal, maximumErrorBytes, lengthHeader(response, maximumErrorBytes, false))
      let body: unknown
      try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown } catch { throw new ApiError('MI_INVALID_RESPONSE') }
      const codes = ['MI_REPORT_NOT_READY', 'MI_REPORT_INVALID', 'MI_REPORT_LIMIT', 'MI_REPORT_FILE_UNAVAILABLE', 'MI_NOT_FOUND', 'MI_SERVICE_UNAVAILABLE']
      const code = object(body) && object(body.error) && typeof body.error.code === 'string' && codes.includes(body.error.code) ? body.error.code : 'MI_SERVICE_UNAVAILABLE'
      throw new ApiError(code, response.status)
    }
    const filename = `report-${expected.id}-r${expected.revision}.${expected.format}`
    if (response.status !== 200 || response.redirected || response.headers.get('Content-Type')?.toLowerCase() !== `${mime}; charset=utf-8` || response.headers.get('Content-Disposition') !== `attachment; filename="${filename}"` || response.headers.get('X-Content-Type-Options') !== 'nosniff' || response.headers.get('Content-Security-Policy') !== downloadCSP || response.headers.get('X-Report-Content-Hash') !== expected.content_hash || response.headers.get('X-Report-File-Hash') !== expected.file_hash || lengthHeader(response, reportMaximumBytes, true) !== expected.file_size) throw new ApiError('MI_INVALID_RESPONSE')
    const bytes = await readBytes(response, signal, reportMaximumBytes, expected.file_size)
    const digest = await abortable(crypto.subtle.digest('SHA-256', bytes), signal)
    check(signal)
    const hash = `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')}`
    if (hash !== expected.file_hash) throw new ApiError('MI_INVALID_RESPONSE')
    return { blob: new Blob([bytes], { type: `${mime}; charset=utf-8` }), filename }
  } catch (failure) {
    if (userSignal?.aborted) throw cancelled()
    if (response?.status === 401 || response?.status === 403) throw new ApiError('MI_SESSION_REQUIRED', response.status)
    if (timeout.signal.aborted) throw new ApiError('MI_NETWORK_ERROR')
    if (failure instanceof ApiError) throw failure
    throw new ApiError('MI_NETWORK_ERROR')
  } finally { clearTimeout(timer); if (response?.body && !response.body.locked) cancelBody(response.body) }
}
