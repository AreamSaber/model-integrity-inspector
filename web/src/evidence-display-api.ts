import { ApiError, object, request } from './api'
import { closed, decimalID, integer, readScope } from './runs-history-api'

// S2 lives only in this explicit endpoint DTO, never an S1 result/report DTO.
export const evidenceDisplayStatuses = ['available', 'unavailable_policy_zero', 'unavailable_not_retained', 'unavailable_not_captured', 'unavailable_uncertain', 'unavailable_expired', 'unavailable_deleted', 'unavailable_legacy_unverified', 'unavailable_redaction_policy', 'unavailable_safety_limit', 'unavailable_source_invalid', 'unavailable_cancelled', 'unavailable_capture', 'unavailable_seal'] as const
export type EvidenceDisplayStatus = typeof evidenceDisplayStatuses[number]
export interface DisplayEvent { sequence: number; type: string; bytes: number; arrival_ms: number; interval_ms: number }
export interface DisplayResponse {
  content: string; model_reported: string; http_status: number; finish_reason: string; parse_status: string
  prompt_tokens: number | null; completion_tokens: number | null; total_tokens: number | null; reasoning_tokens: number | null
  duration_ms: number; first_token_ms: number | null; stream_terminated: boolean; events: DisplayEvent[] | null; event_summary_partial: boolean
}
export interface DisplayContent {
  version: 1; policy: 'display-redaction-v1'; source_hash: string; request_hash: string; template_hash: string
  request_json: string; request_changed: boolean; response: DisplayResponse; metadata_omitted: true
}
export interface EvidenceDisplay {
  version: 'mii.evidence-display-output.v1'; run_id: string; sample_id: string; attempt_id: string; analysis_revision: 1
  is_final: boolean; status: EvidenceDisplayStatus; payload_hash?: string; content: DisplayContent | null
}
export interface EvidenceSelection { runID: string; sampleID: string; attemptID: string; analysisRevision: number; isFinal: boolean }
const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v)
const boundedText = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && new TextEncoder().encode(v).length <= max
const count = (v: unknown): v is number | null => v === null || integer(v)
function response(v: unknown): v is DisplayResponse {
  if (!closed(v, ['content', 'model_reported', 'http_status', 'finish_reason', 'parse_status', 'prompt_tokens', 'completion_tokens', 'total_tokens', 'reasoning_tokens', 'duration_ms', 'first_token_ms', 'stream_terminated', 'events', 'event_summary_partial']) ||
    !boundedText(v.content, 1 << 20) || !boundedText(v.model_reported, 2048) || !(v.http_status === 0 || integer(v.http_status, 100, 599)) ||
    typeof v.finish_reason !== 'string' || !['', 'stop', 'length', 'content_filter', 'tool_calls', 'function_call', 'unknown'].includes(v.finish_reason) || typeof v.parse_status !== 'string' || !['valid', 'invalid', 'partial', 'unobserved'].includes(v.parse_status) ||
    ![v.prompt_tokens, v.completion_tokens, v.total_tokens, v.reasoning_tokens].every(count) || !integer(v.duration_ms, 0, 86400000) || !(v.first_token_ms === null || integer(v.first_token_ms, 0, v.duration_ms)) || typeof v.stream_terminated !== 'boolean' || typeof v.event_summary_partial !== 'boolean') return false
  if (v.events === null) return true
  if (!Array.isArray(v.events) || v.events.length > 256) return false
  let sequence = 0, arrival = 0
  for (const event of v.events) {
    if (!closed(event, ['sequence', 'type', 'bytes', 'arrival_ms', 'interval_ms']) || !integer(event.sequence, sequence + 1) || typeof event.type !== 'string' || !['done', 'error', 'malformed', 'usage', 'empty_delta', 'role', 'content_delta', 'finish'].includes(event.type) || !integer(event.bytes, 0, 1 << 20) || !integer(event.arrival_ms, arrival, v.duration_ms) || !integer(event.interval_ms, 0, v.duration_ms)) return false
    sequence = event.sequence; arrival = event.arrival_ms
  }
  return true
}
function content(v: unknown): v is DisplayContent {
  if (!closed(v, ['version', 'policy', 'source_hash', 'request_hash', 'template_hash', 'request_json', 'request_changed', 'response', 'metadata_omitted']) || v.version !== 1 || v.policy !== 'display-redaction-v1' || !hash(v.source_hash) || !hash(v.request_hash) || !hash(v.template_hash) || !boundedText(v.request_json, 1 << 20) || typeof v.request_changed !== 'boolean' || v.request_changed !== (v.request_hash !== v.template_hash) || v.metadata_omitted !== true || !response(v.response)) return false
  // Syntax only. Never reserialize or display parsed request numbers: seed may
  // use the full int64 range. The exact original request_json string is kept.
  try { return object(JSON.parse(v.request_json) as unknown) } catch { return false }
}
export function evidenceDisplay(v: unknown, selection: EvidenceSelection): v is EvidenceDisplay {
  if (!closed(v, ['version', 'run_id', 'sample_id', 'attempt_id', 'analysis_revision', 'is_final', 'status', 'payload_hash', 'content']) || v.version !== 'mii.evidence-display-output.v1' || !decimalID(v.run_id) || !decimalID(v.sample_id) || !decimalID(v.attempt_id) || v.run_id !== selection.runID || v.sample_id !== selection.sampleID || v.attempt_id !== selection.attemptID || v.analysis_revision !== 1 || v.analysis_revision !== selection.analysisRevision || typeof v.is_final !== 'boolean' || v.is_final !== selection.isFinal || !evidenceDisplayStatuses.some((status) => status === v.status)) return false
  return v.status === 'available' ? hash(v.payload_hash) && content(v.content) : v.content === null && (v.payload_hash === undefined || hash(v.payload_hash))
}
export const evidenceDisplayApi = {
  get(org: string, selection: EvidenceSelection, signal?: AbortSignal) {
    const expected = { runID: selection.runID, sampleID: selection.sampleID, attemptID: selection.attemptID, analysisRevision: selection.analysisRevision, isFinal: selection.isFinal }
    if (![expected.runID, expected.sampleID, expected.attemptID].every(decimalID) || expected.analysisRevision !== 1 || typeof expected.isFinal !== 'boolean') throw new ApiError('MI_INVALID_REQUEST')
    const path = `/runs/${expected.runID}/samples/${expected.sampleID}/attempts/${expected.attemptID}/evidence?analysis_revision=1`
    // Fixed closed route, GET, no-store, ordinary 8 MiB/64 KiB transport caps.
    // No arbitrary URL, response-size override, raw fallback or browser cache.
    return request(path, (v): v is EvidenceDisplay => evidenceDisplay(v, expected), { headers: readScope(org), signal })
  },
}
