// Synthetic contract fixtures. Product modules must not import this file.
import type { Comparison, ComparisonSide } from '../../comparison-api'
import type { Run } from '../../runs-api'
import { org, userID, runID, summary } from '../results/test-fixtures'

export { org, userID, runID }
export const rightID = '9007199254741024'
export function side(id = runID): ComparisonSide {
  const result = { ...summary(), run_id: id, versions: { ...summary().versions } }
  const run: Run = { id, target_id: '9007199254741005', created_by: userID, package: 'quick', status: 'COMPLETED', version: 3, versions: { ...result.versions }, manifest_hash: 'a'.repeat(64), estimate: { requests: 18, input_tokens: 100, max_output_tokens: 2304, cost_micros: null, duration_seconds: 900, usage_safety_factor: 1.25, warnings: [], completeness: 'full' }, request_count: 18, token_count: 2345, estimated_cost_micros: null, valid_sample_count: 17, planned_samples: 18, completed_samples: 18, created_at: '2026-09-07T07:00:00Z', started_at: '2026-09-07T07:00:01Z', execution_closed_at: '2026-09-07T07:59:00Z', finished_at: result.created_at, error_summary: [] }
  return { run, result }
}
export function comparison(): Comparison { return { left: side(), right: side(rightID) } }
export const ok = (data: unknown) => Response.json({ data, request_id: 'comparison-test' })
export const failure = (code: string, status: number) => Response.json({ error: { code, message: 'COMPARISON_PRIVATE_CANARY' }, request_id: 'comparison-error' }, { status })
