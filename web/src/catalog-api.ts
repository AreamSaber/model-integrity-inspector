import { acknowledged, ApiError, id, object, page, request } from './api'
import { runsApi } from './runs-api'
import type { Page } from './targets-api'

export type CatalogStatus = 'active' | 'disabled'
export type TokenizerQuality = 'unavailable' | 'heuristic' | 'compatible' | 'exact'
export interface ProviderInput { name: string; description: string; contact: string; status: CatalogStatus }
export interface Provider extends ProviderInput { id: string; version: number; created_at: string; updated_at: string }
export interface ModelInput {
  provider_id: string; name: string; display_name: string; protocol: 'openai_chat'; status: CatalogStatus
  supports_stream: boolean; supports_seed: boolean; reasoning_model: boolean; tokenizer_id: string; tokenizer_quality: TokenizerQuality
  max_output_tokens: number | null; context_window: number | null; input_price_micros_per_million: number | null; output_price_micros_per_million: number | null
}
export interface ModelSummary { id: string; provider_id: string; name: string; display_name: string; protocol: 'openai_chat'; status: CatalogStatus; version: number; input_price_micros_per_million: number | null; output_price_micros_per_million: number | null; created_at: string; updated_at: string }
export interface ModelProfile extends ModelSummary { supports_stream: boolean; supports_seed: boolean; reasoning_model: boolean; tokenizer_id: string; tokenizer_quality: TokenizerQuality; max_output_tokens?: number; context_window?: number }
const providerFields = ['id', 'name', 'description', 'contact', 'status', 'version', 'created_at', 'updated_at']
const summaryFields = ['id', 'provider_id', 'name', 'display_name', 'protocol', 'status', 'version', 'input_price_micros_per_million', 'output_price_micros_per_million', 'created_at', 'updated_at']
const modelFields = [...summaryFields, 'supports_stream', 'supports_seed', 'reasoning_model', 'tokenizer_id', 'tokenizer_quality', 'max_output_tokens', 'context_window']
function closed(value: unknown, fields: string[]): value is Record<string, unknown> { return object(value) && Object.keys(value).every((key) => fields.includes(key)) }
export function catalogText(value: unknown, limit: number, required = false): value is string { return typeof value === 'string' && [...value].length <= limit && !/[\p{Cc}\p{Cs}]/u.test(value) && (!required || Boolean(value.trim())) }
function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max }
function version(value: unknown) { return integer(value, 1, 2147483647) }
function status(value: unknown) { return value === 'active' || value === 'disabled' }
function date(value: unknown) { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value) && value.length <= 64 && Number.isFinite(Date.parse(value)) }
function price(value: unknown) { return value === null || integer(value) }
export function provider(value: unknown): value is Provider { return closed(value, providerFields) && id(value.id) && catalogText(value.name, 128, true) && catalogText(value.description, 2048) && catalogText(value.contact, 256) && status(value.status) && version(value.version) && date(value.created_at) && date(value.updated_at) }
function modelBase(value: Record<string, unknown>) { return id(value.id) && id(value.provider_id) && catalogText(value.name, 128, true) && catalogText(value.display_name, 128) && value.protocol === 'openai_chat' && status(value.status) && version(value.version) && price(value.input_price_micros_per_million) && price(value.output_price_micros_per_million) && date(value.created_at) && date(value.updated_at) }
export function modelSummary(value: unknown): value is ModelSummary { return closed(value, summaryFields) && modelBase(value) }
export function modelProfile(value: unknown): value is ModelProfile {
  return closed(value, modelFields) && modelBase(value) && ['supports_stream', 'supports_seed', 'reasoning_model'].every((key) => typeof value[key] === 'boolean') &&
    catalogText(value.tokenizer_id, 128) && typeof value.tokenizer_quality === 'string' && (value.tokenizer_quality === 'unavailable' ? value.tokenizer_id === '' : ['heuristic', 'compatible', 'exact'].includes(value.tokenizer_quality) && value.tokenizer_id !== '') &&
    (value.max_output_tokens === undefined || integer(value.max_output_tokens, 1, 1048576)) && (value.context_window === undefined || integer(value.context_window, 1, 4194304)) &&
    (value.max_output_tokens === undefined || value.context_window === undefined || value.max_output_tokens <= value.context_window)
}
export function priceInput(raw: string): number | null {
  if (!raw.trim()) return null
  if (!/^\d+(?:\.\d{1,6})?$/.test(raw.trim()) || raw.length > 32) throw '价格须为非负 USD 数值，最多 6 位小数；留空表示未知，不是免费。'
  const [whole, fraction = ''] = raw.trim().split('.')
  const micros = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0'))
  if (micros > BigInt(Number.MAX_SAFE_INTEGER)) throw '价格超过可精确保存的整数微单位上限。'
  return Number(micros)
}
export function priceDecimal(value: number | null): string {
  if (value === null) return ''
  if (!integer(value)) throw new ApiError('MI_INVALID_RESPONSE')
  const micros = BigInt(value)
  return `${micros / 1000000n}.${String(micros % 1000000n).padStart(6, '0')}`
}
export function priceLabel(value: number | null) { return value === null ? '价格未知' : `${priceDecimal(value)} USD / 百万 Token` }
function scope(org: string, csrf?: string): Record<string, string> { if (!id(org)) throw new ApiError('MI_INVALID_REQUEST'); return { 'X-Organization-ID': org, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } }
function path(kind: 'providers' | 'model-profiles', recordID: string) { if (!id(recordID)) throw new ApiError('MI_INVALID_REQUEST'); return `/${kind}/${recordID}` }
function cas(value: number) { if (!integer(value, 1, 2147483646)) throw new ApiError('MI_INVALID_REQUEST'); return value }
function query(cursor: string, q: string) { if (new TextEncoder().encode(q).length > 128 || /[\p{Cc}\p{Cs}]/u.test(q)) throw new ApiError('MI_INVALID_REQUEST'); const params = new URLSearchParams({ limit: '25' }); if (cursor) params.set('cursor', cursor); if (q) params.set('q', q); return `?${params}` }
function providerInput(value: ProviderInput): ProviderInput { return { name: value.name, description: value.description, contact: value.contact, status: value.status } }
function modelInput(value: ModelInput): ModelInput { return { provider_id: value.provider_id, name: value.name, display_name: value.display_name, protocol: value.protocol, status: value.status, supports_stream: value.supports_stream, supports_seed: value.supports_seed, reasoning_model: value.reasoning_model, tokenizer_id: value.tokenizer_id, tokenizer_quality: value.tokenizer_quality, max_output_tokens: value.max_output_tokens, context_window: value.context_window, input_price_micros_per_million: value.input_price_micros_per_million, output_price_micros_per_million: value.output_price_micros_per_million } }
export const catalogApi = {
  permissions: runsApi.permissions,
  providers: (org: string, cursor = '', q = '', signal?: AbortSignal): Promise<Page<Provider>> => request(`/providers${query(cursor, q)}`, page(provider), { headers: scope(org), signal }),
  models: (org: string, cursor = '', q = '', signal?: AbortSignal): Promise<Page<ModelSummary>> => request(`/model-profiles${query(cursor, q)}`, page(modelSummary), { headers: scope(org), signal }),
  provider: (org: string, recordID: string, signal?: AbortSignal) => request(path('providers', recordID), (value): value is Provider => provider(value) && value.id === recordID, { headers: scope(org), signal }),
  model: (org: string, recordID: string, signal?: AbortSignal) => request(path('model-profiles', recordID), (value): value is ModelProfile => modelProfile(value) && value.id === recordID, { headers: scope(org), signal }),
  createProvider: (org: string, csrf: string, input: ProviderInput, signal?: AbortSignal) => request('/providers', provider, { body: providerInput(input), headers: scope(org, csrf), signal }),
  updateProvider: (org: string, csrf: string, record: Provider, input: ProviderInput, signal?: AbortSignal) => request(path('providers', record.id), (value): value is Provider => provider(value) && value.id === record.id && value.version === record.version + 1, { method: 'PATCH', body: { ...providerInput(input), version: cas(record.version) }, headers: scope(org, csrf), signal }),
  createModel: (org: string, csrf: string, input: ModelInput, signal?: AbortSignal) => request('/model-profiles', (value): value is ModelProfile => modelProfile(value) && value.provider_id === input.provider_id, { body: modelInput(input), headers: scope(org, csrf), signal }),
  updateModel: (org: string, csrf: string, record: ModelProfile, input: ModelInput, signal?: AbortSignal) => request(path('model-profiles', record.id), (value): value is ModelProfile => modelProfile(value) && value.id === record.id && value.provider_id === input.provider_id && value.version === record.version + 1, { method: 'PATCH', body: { ...modelInput(input), version: cas(record.version) }, headers: scope(org, csrf), signal }),
  remove: (kind: 'providers' | 'model-profiles', org: string, csrf: string, record: { id: string; version: number }, signal?: AbortSignal) => request(path(kind, record.id), acknowledged, { method: 'DELETE', body: { version: cas(record.version) }, headers: scope(org, csrf), signal }),
}
