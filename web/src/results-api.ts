import { ApiError, request } from './api'
import { closed, decimalID, identifier, integer, isoDate, nullableNumber, readPage, readScope, resultBadge, safeText, scalar, versions, type ResultBadge } from './runs-history-api'
import type { Versions } from './runs-api'

export interface TokenTier { series_id: string; family: string; language: string; requested_max_tokens: number; samples: number; median: number; mad: number; robust_cv: number }
export interface TokenPlateau { series_id: string; family: string; low_requested: number; high_requested: number; growth_ratio: number; strength: number; candidate: boolean; limited: boolean; lower: number | null; upper: number | null; paired: boolean; independent_groups: number; limitations: string[]; sample_refs: string[] }
export interface TokenAnalysis { tiers: TokenTier[]; plateaus: TokenPlateau[]; usage_samples: number; usage_median_relative_error: number; stream_pairs: number; stream_median_relative_difference: number; limitations: string[] }
export interface Pattern { kind: string; fingerprint: string; state: string; family_count: number; template_count: number; language_count: number; sample_refs: string[] }
export interface Difference { metric: string; state: string; pairs: number; effect_size: number | null; p_value: number | null; adjusted_p: number | null }
export interface BehaviorAnalysis { analyzed_samples: number; auxiliary_samples: number; patterns: Pattern[]; differences: Difference[]; limitations: string[] }
export interface AnalysisResult extends ResultBadge {
  expected_samples: number; valid_samples: number
  run_id: string; versions: Versions; prompt_risk: number | null; token_risk: number | null; response_risk: number | null; evidence_risk: number | null
  algorithm_risk_level: string; observation_mode: 'blackbox'; published: true; development: true; calibrated: false; created_at: string; limitations: string[]; recommendations: string[]
  token_analysis?: TokenAnalysis; behavior_analysis?: BehaviorAnalysis
}
export interface Statistic { name: string; actual: number | null; unit: string }
export interface Finding { id: string; run_id: string; analysis_revision: 1; category: string; rule_id: string; rule_version: string; title: string; summary: string; severity: string; risk_score: number; confidence: number; evidence_grade: 'C' | 'D'; statistics: Statistic[]; alternative_explanations: string[]; sample_refs: string[] }
export interface Sample {
  id: string; run_id: string; probe_instance_id: string; ordinal: number; family: string; language: string; validity: string; final_attempt_id: string | null; included: boolean; auxiliary_only: boolean
  requested_max_tokens: number; local_completion_tokens: number | null; reported_completion_tokens: number | null; tokenizer_id: string; tokenizer_quality: string; stream: boolean
  finish_reason: string | null; structure_complete: boolean | null; hard_truncation: boolean | null; contract: string | null; refusal_class: string | null; identity_class: string | null
  content_state: 'redacted'; response_hash: string | null; limitations: string[]
}
export interface Attempt { id: string; attempt_no: number; validity: string; error_code: string | null; http_status: number | null; prompt_tokens: number | null; completion_tokens: number | null; total_tokens: number | null; duration_ms: number | null; started_at: string | null; finished_at: string | null; content_state: 'redacted' }
export interface SampleDetail { sample: Sample; attempts: Attempt[] }

const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v)
const finite = (v: unknown): v is number => scalar(v, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)
const optional = <T,>(guard: (v: unknown) => v is T) => (v: unknown): v is T | null => v === null || guard(v)
const bool = (v: unknown): v is boolean => typeof v === 'boolean'
const array = <T,>(v: unknown, guard: (v: unknown) => v is T, max = 512): v is T[] => Array.isArray(v) && v.length <= max && v.every(guard)
const labels = (v: unknown): v is string[] => array(v, identifier, 128)
const refs = (v: unknown): v is string[] => array(v, decimalID) && new Set(v).size === v.length
const family = (v: unknown): v is string => ['sequence', 'jsonl', 'format', 'neutral', 'differential', 'style', 'self_report'].includes(String(v))
const language = (v: unknown): v is string => ['zh-CN', 'en-US'].includes(String(v))
const validity = (v: unknown): v is string => ['VALID', 'VALID_WITH_WARNING', 'INVALID_RETRYABLE', 'INVALID_PROTOCOL', 'INVALID_SAFETY_LIMIT', 'NOT_APPLICABLE', 'UNCERTAIN', 'PENDING'].includes(String(v))
const quality = (v: unknown): v is string => ['exact', 'compatible', 'heuristic', 'unavailable'].includes(String(v))
function tier(v: unknown): v is TokenTier { return closed(v, ['series_id', 'family', 'language', 'requested_max_tokens', 'samples', 'median', 'mad', 'robust_cv']) && hash(v.series_id) && family(v.family) && language(v.language) && integer(v.requested_max_tokens, 1) && integer(v.samples, 1, 512) && scalar(v.median, 0, Number.MAX_SAFE_INTEGER) && scalar(v.mad, 0, Number.MAX_SAFE_INTEGER) && scalar(v.robust_cv, 0, Number.MAX_SAFE_INTEGER) }
function plateau(v: unknown): v is TokenPlateau { return closed(v, ['series_id', 'family', 'low_requested', 'high_requested', 'growth_ratio', 'strength', 'candidate', 'limited', 'lower', 'upper', 'paired', 'independent_groups', 'limitations', 'sample_refs']) && hash(v.series_id) && family(v.family) && integer(v.low_requested, 1) && integer(v.high_requested, v.low_requested + 1) && finite(v.growth_ratio) && finite(v.strength) && bool(v.candidate) && bool(v.limited) && optional(finite)(v.lower) && optional(finite)(v.upper) && bool(v.paired) && integer(v.independent_groups, 0, 512) && labels(v.limitations) && refs(v.sample_refs) }
function tokenAnalysis(v: unknown): v is TokenAnalysis { return closed(v, ['tiers', 'plateaus', 'usage_samples', 'usage_median_relative_error', 'stream_pairs', 'stream_median_relative_difference', 'limitations']) && array(v.tiers, tier) && array(v.plateaus, plateau) && integer(v.usage_samples, 0, 512) && finite(v.usage_median_relative_error) && integer(v.stream_pairs, 0, 256) && finite(v.stream_median_relative_difference) && labels(v.limitations) }
function pattern(v: unknown): v is Pattern { return closed(v, ['kind', 'fingerprint', 'state', 'family_count', 'template_count', 'language_count', 'sample_refs']) && ['extra_prefix', 'extra_suffix', 'refusal_like', 'self_identity_like'].includes(String(v.kind)) && hash(v.fingerprint) && ['cross_family_repeat', 'insufficient_coverage'].includes(String(v.state)) && integer(v.family_count, 0, 7) && integer(v.template_count, 0, 512) && integer(v.language_count, 0, 2) && refs(v.sample_refs) }
function difference(v: unknown): v is Difference { return closed(v, ['metric', 'state', 'pairs', 'effect_size', 'p_value', 'adjusted_p']) && ['contract_deviation', 'extra_affix', 'neutral_refusal_like', 'unsolicited_identity_like'].includes(String(v.metric)) && ['descriptive_available', 'insufficient_pairs', 'no_discordant_pairs'].includes(String(v.state)) && integer(v.pairs, 0, 256) && optional((x): x is number => scalar(x, -1, 1))(v.effect_size) && optional((x): x is number => scalar(x, 0, 1))(v.p_value) && optional((x): x is number => scalar(x, 0, 1))(v.adjusted_p) }
function behaviorAnalysis(v: unknown): v is BehaviorAnalysis { return closed(v, ['analyzed_samples', 'auxiliary_samples', 'patterns', 'differences', 'limitations']) && integer(v.analyzed_samples, 0, 512) && integer(v.auxiliary_samples, 0, 512) && array(v.patterns, pattern, 2048) && array(v.differences, difference, 4) && labels(v.limitations) }
export function analysisResult(v: unknown, statistics = false): v is AnalysisResult {
  if (!closed(v, ['run_id', 'analysis_revision', 'expected_samples', 'valid_samples', 'overall_risk', 'confidence', 'evidence_grade', 'risk_level', 'completeness', 'versions', 'prompt_risk', 'token_risk', 'response_risk', 'evidence_risk', 'algorithm_risk_level', 'observation_mode', 'published', 'development', 'calibrated', 'created_at', 'limitations', 'recommendations', ...(statistics ? ['token_analysis', 'behavior_analysis'] : [])])) return false
  const badge = { analysis_revision: v.analysis_revision, overall_risk: v.overall_risk, confidence: v.confidence, evidence_grade: v.evidence_grade, risk_level: v.risk_level, completeness: v.completeness }
  return resultBadge(badge) && decimalID(v.run_id) && integer(v.expected_samples, 0, 512) && integer(v.valid_samples, 0, v.expected_samples) && versions(v.versions) && [v.prompt_risk, v.token_risk, v.response_risk, v.evidence_risk].every(optional(scalar)) &&
    ['low', 'attention', 'medium', 'high', 'severe_black_box_statistical_judgment', 'insufficient'].includes(String(v.algorithm_risk_level)) && v.observation_mode === 'blackbox' && v.published === true && v.development === true && v.calibrated === false && isoDate(v.created_at) && labels(v.limitations) && labels(v.recommendations) &&
    (!statistics || (tokenAnalysis(v.token_analysis) && behaviorAnalysis(v.behavior_analysis)))
}
export function finding(v: unknown): v is Finding { return closed(v, ['id', 'run_id', 'analysis_revision', 'category', 'rule_id', 'rule_version', 'title', 'summary', 'severity', 'risk_score', 'confidence', 'evidence_grade', 'statistics', 'alternative_explanations', 'sample_refs']) && decimalID(v.id) && decimalID(v.run_id) && v.analysis_revision === 1 && identifier(v.category) && identifier(v.rule_id) && identifier(v.rule_version) && safeText(v.title, 256) && safeText(v.summary, 2048) && identifier(v.severity) && scalar(v.risk_score) && integer(v.confidence, 0, 74) && ['C', 'D'].includes(String(v.evidence_grade)) && array(v.statistics, (x): x is Statistic => closed(x, ['name', 'actual', 'unit']) && identifier(x.name) && optional(finite)(x.actual) && identifier(x.unit), 64) && array(v.alternative_explanations, (x): x is string => safeText(x, 1024), 32) && refs(v.sample_refs) }
export function sample(v: unknown): v is Sample {
  return closed(v, ['id', 'run_id', 'probe_instance_id', 'ordinal', 'family', 'language', 'validity', 'final_attempt_id', 'included', 'auxiliary_only', 'requested_max_tokens', 'local_completion_tokens', 'reported_completion_tokens', 'tokenizer_id', 'tokenizer_quality', 'stream', 'finish_reason', 'structure_complete', 'hard_truncation', 'contract', 'refusal_class', 'identity_class', 'content_state', 'response_hash', 'limitations']) &&
    decimalID(v.id) && decimalID(v.run_id) && decimalID(v.probe_instance_id) && integer(v.ordinal, 0, 1000) && family(v.family) && language(v.language) && validity(v.validity) && optional(decimalID)(v.final_attempt_id) && bool(v.included) && bool(v.auxiliary_only) && integer(v.requested_max_tokens, 1) && nullableNumber(v.local_completion_tokens) && nullableNumber(v.reported_completion_tokens) && (v.tokenizer_id === '' || identifier(v.tokenizer_id)) && quality(v.tokenizer_quality) && bool(v.stream) && optional(identifier)(v.finish_reason) && optional(bool)(v.structure_complete) && optional(bool)(v.hard_truncation) && optional(identifier)(v.contract) && optional(identifier)(v.refusal_class) && optional(identifier)(v.identity_class) && v.content_state === 'redacted' && optional(hash)(v.response_hash) && labels(v.limitations) &&
    (!v.included || (v.final_attempt_id !== null && ['VALID', 'VALID_WITH_WARNING'].includes(String(v.validity)))) && (!v.auxiliary_only || v.family === 'self_report')
}
function attempt(v: unknown): v is Attempt { return closed(v, ['id', 'attempt_no', 'validity', 'error_code', 'http_status', 'prompt_tokens', 'completion_tokens', 'total_tokens', 'duration_ms', 'started_at', 'finished_at', 'content_state']) && decimalID(v.id) && integer(v.attempt_no, 1, 3) && validity(v.validity) && optional((x): x is string => typeof x === 'string' && /^MI_[A-Z0-9_]{1,80}$/.test(x))(v.error_code) && optional((x): x is number => integer(x, 100, 599))(v.http_status) && [v.prompt_tokens, v.completion_tokens, v.total_tokens, v.duration_ms].every(nullableNumber) && optional(isoDate)(v.started_at) && optional(isoDate)(v.finished_at) && v.content_state === 'redacted' }
export function sampleDetail(v: unknown): v is SampleDetail {
  if (!closed(v, ['sample', 'attempts']) || !sample(v.sample) || !array(v.attempts, attempt, 3)) return false
  const finalID = v.sample.final_attempt_id
  return new Set(v.attempts.map((a) => a.id)).size === v.attempts.length && new Set(v.attempts.map((a) => a.attempt_no)).size === v.attempts.length && (finalID === null || v.attempts.some((a) => a.id === finalID))
}
function path(runID: string) { if (!decimalID(runID)) throw new ApiError('MI_INVALID_REQUEST'); return `/runs/${runID}` }
function query(cursor: string) { const q = new URLSearchParams({ analysis_revision: '1', limit: '25' }); if (cursor) { if (!safeText(cursor, 1024)) throw new ApiError('MI_INVALID_REQUEST'); q.set('cursor', cursor) }; return q }
export const resultsApi = {
  get(org: string, runID: string, statistics = false, signal?: AbortSignal) { return request(`${path(runID)}/result?analysis_revision=1${statistics ? '&include=statistics' : ''}`, (v): v is AnalysisResult => analysisResult(v, statistics) && v.run_id === runID, { headers: readScope(org), signal }) },
  findings(org: string, runID: string, cursor = '', signal?: AbortSignal) { return request(`${path(runID)}/findings?${query(cursor)}`, readPage((v): v is Finding => finding(v) && v.run_id === runID), { headers: readScope(org), signal }) },
  samples(org: string, runID: string, cursor = '', signal?: AbortSignal) { return request(`${path(runID)}/samples?${query(cursor)}`, readPage((v): v is Sample => sample(v) && v.run_id === runID), { headers: readScope(org), signal }) },
  sample(org: string, runID: string, sampleID: string, signal?: AbortSignal) { if (!decimalID(sampleID)) throw new ApiError('MI_INVALID_REQUEST'); return request(`${path(runID)}/samples/${sampleID}?analysis_revision=1`, (v): v is SampleDetail => sampleDetail(v) && v.sample.run_id === runID && v.sample.id === sampleID, { headers: readScope(org), signal }) },
}
