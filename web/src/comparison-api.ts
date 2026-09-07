import { ApiError } from './api'
import { resultsApi, type AnalysisResult } from './results-api'
import { runsApi, type Run, type Versions } from './runs-api'
import { decimalID } from './runs-history-api'

export interface ComparisonSelection { left: string; right: string; revision: 1 }
export interface ComparisonSide { run: Run; result: AnalysisResult }
export interface Comparison { left: ComparisonSide; right: ComparisonSide }
export type ComparisonRoute = { kind: 'form' } | { kind: 'pair'; selection: ComparisonSelection } | { kind: 'invalid' }
export function comparisonSelection(left: string, right: string, revision: number): ComparisonSelection {
  if (!decimalID(left) || !decimalID(right) || left === right || revision !== 1) throw new ApiError('MI_INVALID_REQUEST')
  return { left, right, revision: 1 }
}
export function comparisonHref(left: string, right: string) {
  const selected = comparisonSelection(left, right, 1)
  return `#/compare/${selected.left}/1/${selected.right}/1`
}
export function comparisonRoute(route: string): ComparisonRoute | null {
  if (route === 'compare') return { kind: 'form' }
  if (route !== 'compare' && !route.startsWith('compare/')) return null
  const parts = route.split('/')
  if (parts.length !== 5 || parts[2] !== '1' || parts[4] !== '1') return { kind: 'invalid' }
  try { return { kind: 'pair', selection: comparisonSelection(parts[1], parts[3], 1) } } catch { return { kind: 'invalid' } }
}
export function sameVersions(left: Versions, right: Versions) {
  return (['rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle'] as const).every((key) => left[key] === right[key])
}
function bind(run: Run, result: AnalysisResult, expected: string): ComparisonSide {
  const statuses = { full: 'COMPLETED', partial: 'PARTIAL', insufficient: 'REVIEW_REQUIRED' } as const
  if (run.id !== expected || result.run_id !== expected || !decimalID(run.target_id) || !decimalID(run.created_by) || result.analysis_revision !== 1 || !sameVersions(run.versions, result.versions) || run.status !== statuses[result.completeness] || !run.finished_at || !run.execution_closed_at || Date.parse(run.created_at) > Date.parse(run.execution_closed_at) || Date.parse(run.execution_closed_at) > Date.parse(run.finished_at) || Date.parse(run.finished_at) !== Date.parse(result.created_at) || result.expected_samples !== run.planned_samples || run.completed_samples !== run.planned_samples || result.valid_samples > run.valid_sample_count) throw new ApiError('MI_INVALID_RESPONSE')
  return { run, result }
}
// Exactly one permission GET and four object GETs per explicit read, never an
// unbounded history scan. Run metadata is the Run's own frozen target/package;
// current target/provider/model directories are not consulted. Cross-response
// consistency checks do not claim a database-wide atomic snapshot.
export const comparisonApi = {
  async read(orgID: string, userID: string, selected: ComparisonSelection, userSignal?: AbortSignal): Promise<Comparison> {
    const selection = comparisonSelection(selected.left, selected.right, selected.revision)
    if (!decimalID(orgID) || !decimalID(userID)) throw new ApiError('MI_INVALID_REQUEST')
    const controller = new AbortController(), signal = userSignal ? AbortSignal.any([userSignal, controller.signal]) : controller.signal
    try {
      const grants = await runsApi.permissions(orgID, userID, signal)
      if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
      if (!grants.permissions.includes('run.read')) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const [leftRun, leftResult, rightRun, rightResult] = await Promise.all([
        runsApi.get(orgID, selection.left, signal), resultsApi.get(orgID, selection.left, false, signal),
        runsApi.get(orgID, selection.right, signal), resultsApi.get(orgID, selection.right, false, signal),
      ])
      if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
      return { left: bind(leftRun, leftResult, selection.left), right: bind(rightRun, rightResult, selection.right) }
    } catch (failure) { controller.abort(); throw failure }
  },
}

// This is descriptive subtraction, not a new risk score, statistical test,
// treatment effect, probability, causal assertion or paired baseline analysis.
export function descriptiveDifference(left: number | null, right: number | null): number | null {
  if (left === null || right === null || !Number.isFinite(left) || !Number.isFinite(right)) return null
  const difference = right - left
  return Number.isFinite(difference) ? difference : null
}
export function comparisonLimitations(value: Comparison): string[] {
  const { left, right } = value
  const limits = ['仅为两个固定发布修订的描述性并列和右侧减左侧差值，不是时间趋势、显著性检验、成对实验或可信基线。', '均为未校准开发结果；同版本也不能证明样本、随机变量、参数、目标配置或上游行为等价。']
  if (!sameVersions(left.result.versions, right.result.versions)) limits.push('冻结规则、模板、评分或 Tokenizer 版本不同：算法变化与行为变化无法据此拆分，禁止直接归因行为恶化。')
  if (left.run.target_id !== right.run.target_id) limits.push('目标 ID 不同：仅为跨目标对照展示，不是同一目标的历史变化。')
  if (left.run.package !== right.run.package) limits.push('检测包不同：探针覆盖、预算及样本组成可能不同，分数差值不具备直接可比性。')
  if (left.run.manifest_hash !== right.run.manifest_hash) limits.push('Manifest 摘要不同：规划样本或随机变量并非同一份冻结清单，不构成成对基线。')
  if (left.result.expected_samples !== right.result.expected_samples || left.result.valid_samples !== right.result.valid_samples) limits.push('预期或纳入分析的有效样本数不同：分母与证据覆盖不同，不能把缺失视为无风险。')
  if (left.result.completeness !== 'full' || right.result.completeness !== 'full') limits.push('至少一侧证据不完整或不足，缺失指标保持未测，不补 0、不外推健康结论。')
  return limits
}
