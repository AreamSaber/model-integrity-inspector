import { ApiError, request } from './api'
import { closed, decimalID, isoDate, readPage, readScope, safeText, type ReadPage } from './runs-history-api'

export const reviewConclusions = ['confirmed', 'false_positive', 'watch', 'not_applicable'] as const
export type ReviewConclusion = typeof reviewConclusions[number]
export const reviewLabels: Record<ReviewConclusion, string> = { confirmed: '确认', false_positive: '误报', watch: '待观察', not_applicable: '不适用' }
export interface Review { id: string; run_id: string; analysis_revision: number; conclusion: ReviewConclusion; explanation: string; created_by: string; created_at: string }
export interface ReviewInput { analysis_revision: number; conclusion: ReviewConclusion; explanation: string; previous_review_id?: string }

// Match the server's byte limit and closed control-character policy. Human notes
// are text, not HTML, and are never copied into error messages or diagnostics.
export function reviewExplanation(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0 && new TextEncoder().encode(value).length <= 4096 && !/[\p{Cf}\p{Cs}]/u.test(value) && !/\p{Cc}/u.test(value.replace(/[\n\t]/g, ''))
}
const conclusion = (value: unknown): value is ReviewConclusion => reviewConclusions.some((item) => item === value)
export function review(value: unknown): value is Review {
  return closed(value, ['id', 'run_id', 'analysis_revision', 'conclusion', 'explanation', 'created_by', 'created_at']) && decimalID(value.id) && decimalID(value.run_id) && value.analysis_revision === 1 && conclusion(value.conclusion) && reviewExplanation(value.explanation) && decimalID(value.created_by) && isoDate(value.created_at)
}
function input(value: unknown): value is ReviewInput {
  return closed(value, ['analysis_revision', 'conclusion', 'explanation', 'previous_review_id']) && value.analysis_revision === 1 && conclusion(value.conclusion) && reviewExplanation(value.explanation) && (value.previous_review_id === undefined || decimalID(value.previous_review_id))
}
function path(runID: string, revision: number) {
  if (!decimalID(runID) || revision !== 1) throw new ApiError('MI_INVALID_REQUEST')
  return `/runs/${runID}/reviews`
}
export const reviewsApi = {
  list(orgID: string, runID: string, revision: number, cursor = '', signal?: AbortSignal) {
    const endpoint = path(runID, revision), query = new URLSearchParams({ analysis_revision: String(revision), limit: '25' })
    if (cursor) { if (!safeText(cursor, 1024)) throw new ApiError('MI_INVALID_REQUEST'); query.set('cursor', cursor) }
    const page = readPage((value): value is Review => review(value) && value.run_id === runID && value.analysis_revision === revision)
    return request(`${endpoint}?${query}`, (value): value is ReadPage<Review> => page(value) && value.items.length <= 25, { headers: readScope(orgID), signal })
  },
  append(orgID: string, runID: string, csrfToken: string, userID: string, value: ReviewInput, key: string, signal?: AbortSignal) {
    if (!input(value) || !decimalID(userID) || !/^[A-Za-z0-9._:-]{16,128}$/.test(key) || !/^[\x21-\x7e]{1,256}$/.test(csrfToken)) throw new ApiError('MI_INVALID_REQUEST')
    const endpoint = path(runID, value.analysis_revision)
    const body: ReviewInput = { analysis_revision: value.analysis_revision, conclusion: value.conclusion, explanation: value.explanation, ...(value.previous_review_id === undefined ? {} : { previous_review_id: value.previous_review_id }) }
    return request(endpoint, (data): data is Review => review(data) && data.run_id === runID && data.analysis_revision === body.analysis_revision && data.created_by === userID && data.conclusion === body.conclusion && data.explanation === body.explanation && data.id !== body.previous_review_id,
      { method: 'POST', body, headers: { ...readScope(orgID), 'X-CSRF-Token': csrfToken, 'Idempotency-Key': key }, signal })
  },
}
