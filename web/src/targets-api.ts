import { acknowledged, ApiError, id, object, page, request, text } from './api'

export interface Provider { id: string; name: string; status: 'active' | 'disabled'; version: number }
export interface ModelProfile { id: string; provider_id: string; name: string; display_name?: string; protocol: 'openai_chat'; version: number }
export interface TargetOptions {
  max_output_parameter: 'auto' | 'max_tokens' | 'max_completion_tokens'
  tls_verify: true
  timeout_seconds: number
  concurrency: number
  rpm: number
}
export interface TargetInput {
  name: string; provider_id: string | null; model_profile_id: string | null
  endpoint: string; protocol: 'openai_chat'; model: string; environment: string; channel_id: string
  tags: string[]; options: TargetOptions
}
export interface Target extends TargetInput {
  id: string; version: number; status: 'active' | 'disabled' | 'deleted'
  secret: { id: string; version: number; mask: string; rotated_at?: string | null }
  created_at?: string; updated_at?: string
}
// Write-only. Never merge this object into a Target or persist it in a store.
export interface Credentials { type: 'bearer' | 'custom_header'; api_key: string; header_name?: string; headers?: Record<string, string> }
export interface Page<T> { items: T[]; next_cursor: string | null }

function integer(value: unknown, max = 2147483647): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= max
}
function optionalString(value: unknown, max: number): value is string | undefined {
  return value === undefined || (typeof value === 'string' && [...value].length <= max && !/\p{Cc}/u.test(value))
}
function optionalDate(value: unknown) {
  return value === undefined || value === null || (typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)))
}
function provider(value: unknown): value is Provider {
  return object(value) && id(value.id) && text(value.name, 128) && (value.status === 'active' || value.status === 'disabled') && integer(value.version)
}
function profile(value: unknown): value is ModelProfile {
  return object(value) && id(value.id) && id(value.provider_id) && text(value.name, 128) && optionalString(value.display_name, 128) && value.protocol === 'openai_chat' && integer(value.version)
}
const readFields = new Set(['id', 'name', 'provider_id', 'model_profile_id', 'endpoint', 'protocol', 'model', 'environment', 'channel_id', 'tags', 'options', 'secret', 'status', 'version', 'created_at', 'updated_at'])
export function target(value: unknown): value is Target {
  if (!object(value) || !Object.keys(value).every((key) => readFields.has(key)) || !object(value.secret) || !object(value.options)) return false
  const secret = value.secret
  const options = value.options
  return id(value.id) && text(value.name, 128) && (value.provider_id === null || id(value.provider_id)) &&
    (value.model_profile_id === null || id(value.model_profile_id)) && text(value.endpoint, 1024) && value.protocol === 'openai_chat' &&
    text(value.model, 128) && typeof value.environment === 'string' && optionalString(value.environment, 64) &&
    typeof value.channel_id === 'string' && optionalString(value.channel_id, 128) && Array.isArray(value.tags) && value.tags.length <= 20 &&
    value.tags.every((tag) => text(tag, 64)) && new Set(value.tags).size === value.tags.length &&
    ['auto', 'max_tokens', 'max_completion_tokens'].includes(String(options.max_output_parameter)) && options.tls_verify === true &&
    integer(options.timeout_seconds, 180) && integer(options.concurrency, 100) && integer(options.rpm, 10000) &&
    Object.keys(options).every((key) => ['max_output_parameter', 'tls_verify', 'timeout_seconds', 'concurrency', 'rpm'].includes(key)) &&
    id(secret.id) && integer(secret.version) && typeof secret.mask === 'string' && /^\*{8}[^\p{Cc}]{0,4}$/u.test(secret.mask) &&
    optionalDate(secret.rotated_at) && optionalDate(value.created_at) && optionalDate(value.updated_at) &&
    Object.keys(secret).every((key) => ['id', 'version', 'mask', 'rotated_at'].includes(key)) &&
    ['active', 'disabled', 'deleted'].includes(String(value.status)) && integer(value.version)
}
function scope(organizationID: string, csrfToken?: string) {
  if (!id(organizationID)) throw new ApiError('MI_INVALID_REQUEST')
  return { 'X-Organization-ID': organizationID, ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) }
}
function targetPath(targetID: string) {
  if (!id(targetID)) throw new ApiError('MI_INVALID_REQUEST')
  return `/targets/${targetID}`
}
function listQuery(cursor = '') {
  const parameters = new URLSearchParams({ limit: '25' })
  if (cursor) parameters.set('cursor', cursor)
  return `?${parameters}`
}
function configuration(input: TargetInput): TargetInput {
  // Project, do not spread a read DTO (which also carries secret metadata).
  return { name: input.name, provider_id: input.provider_id, model_profile_id: input.model_profile_id,
    endpoint: input.endpoint, protocol: input.protocol, model: input.model, environment: input.environment,
    channel_id: input.channel_id, tags: [...input.tags], options: { max_output_parameter: input.options.max_output_parameter,
      tls_verify: true, timeout_seconds: input.options.timeout_seconds, concurrency: input.options.concurrency, rpm: input.options.rpm } }
}
export const targetsApi = {
  list: (org: string, cursor = '', signal?: AbortSignal): Promise<Page<Target>> => request(`/targets${listQuery(cursor)}`, page(target), { headers: scope(org), signal }),
  get: (org: string, targetID: string, signal?: AbortSignal) => request(targetPath(targetID), target, { headers: scope(org), signal }),
  create: (org: string, csrf: string, input: TargetInput, auth: Credentials, signal?: AbortSignal) => request('/targets', target, { body: { ...configuration(input), auth }, headers: scope(org, csrf), signal }),
  update: (org: string, csrf: string, targetID: string, input: TargetInput, status: 'active' | 'disabled', version: number, signal?: AbortSignal) => request(targetPath(targetID), target, { method: 'PATCH', body: { ...configuration(input), status, version }, headers: scope(org, csrf), signal }),
  rotate: (org: string, csrf: string, targetID: string, version: number, secretVersion: number, auth: Credentials, signal?: AbortSignal) => request(`${targetPath(targetID)}/rotate-secret`, target, { body: { version, secret_version: secretVersion, auth }, headers: scope(org, csrf), signal }),
  delete: (org: string, csrf: string, targetID: string, version: number, signal?: AbortSignal) => request(targetPath(targetID), acknowledged, { method: 'DELETE', body: { version }, headers: scope(org, csrf), signal }),
  providers: (org: string, cursor = '', signal?: AbortSignal): Promise<Page<Provider>> => request(`/providers${listQuery(cursor)}`, page(provider), { headers: scope(org), signal }),
  profiles: (org: string, cursor = '', signal?: AbortSignal): Promise<Page<ModelProfile>> => request(`/model-profiles${listQuery(cursor)}`, page(profile), { headers: scope(org), signal }),
}
