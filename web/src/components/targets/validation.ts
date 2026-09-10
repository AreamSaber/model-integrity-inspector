import type { Credentials, TargetInput } from '../../targets-api'

export type FieldErrors = Record<string, string>
export function safeText(value: string, limit: number, required = false) {
  return [...value].length <= limit && !/\p{Cc}/u.test(value) && (!required || value.trim().length > 0)
}
export function validEndpoint(value: string) {
  if (!safeText(value, 1024, true) || /[\\%#?\s]/u.test(value) || !value.startsWith('https://')) return false
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && !!url.hostname && !url.username && !url.password && !url.search && !url.hash
  } catch { return false }
}
const forbiddenHeaders = new Set(['authorization', 'content-type', 'accept', 'user-agent', 'idempotency-key', 'host', 'connection', 'keep-alive', 'transfer-encoding', 'content-length', 'trailer', 'te', 'upgrade', 'cookie', 'set-cookie', 'forwarded', 'forwarded-for', 'via', 'x-host', 'x-original-host', 'x-http-method-override', 'x-original-url', 'x-rewrite-url', 'expect', 'accept-encoding', 'content-encoding'])
function validHeaderName(value: string) {
  const lower = value.toLowerCase()
  return /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(value) && !forbiddenHeaders.has(lower) && !lower.startsWith('proxy-') && !lower.startsWith('x-forwarded')
}
export function readCredentials(form: HTMLFormElement): { auth?: Credentials; errors: FieldErrors } {
  const data = new FormData(form)
  const type = data.get('auth_type') === 'custom_header' ? 'custom_header' : 'bearer'
  const apiKey = String(data.get('api_key') ?? '')
  const headerName = String(data.get('header_name') ?? '').trim()
  const errors: FieldErrors = {}
  if (!apiKey || new TextEncoder().encode(apiKey).length > 8192 || /\p{Cc}/u.test(apiKey)) errors.api_key = '请输入新 API Key（不超过 8192 字节，不含控制字符）。'
  if (type === 'custom_header' && !validHeaderName(headerName)) errors.header_name = '请输入允许的认证请求头名称；不得覆盖认证、传输或代理保留头。'
  const headers: Record<string, string> = Object.create(null) as Record<string, string>
  const seen = new Set<string>(type === 'custom_header' ? [headerName.toLowerCase()] : [])
  let total = 0
  for (const [field, raw] of data.entries()) {
    if (!field.startsWith('extra_name_')) continue
    const name = String(raw).trim()
    const value = String(data.get(field.replace('extra_name_', 'extra_value_')) ?? '')
    if (!name && !value) continue
    const bytes = new TextEncoder().encode(value).length
    if (!validHeaderName(name) || seen.has(name.toLowerCase()) || bytes > 8192 || /\p{Cc}/u.test(value)) {
      errors.credentials = '额外请求头名称或值无效：不得重复、使用保留名称或包含控制字符；每个值最多 8192 字节。'
      continue
    }
    seen.add(name.toLowerCase())
    total += name.length + bytes
    headers[name] = value
  }
  if (Object.keys(headers).length > 32 || total > 32768) errors.credentials = '额外请求头最多 32 项，总大小不超过 32 KiB。'
  if (Object.keys(errors).length) return { errors }
  return { auth: { type, api_key: apiKey, ...(type === 'custom_header' ? { header_name: headerName } : {}), headers }, errors }
}
export function clearCredentials(form: HTMLFormElement) {
  form.querySelectorAll<HTMLInputElement>('[data-sensitive="true"]').forEach((input) => { input.value = '' })
}
export function validateTarget(input: TargetInput): FieldErrors {
  const errors: FieldErrors = {}
  if (!safeText(input.name, 128, true)) errors.name = '请输入目标名称，最多 128 个字符，不含控制字符。'
  if (!validEndpoint(input.endpoint)) errors.endpoint = '请输入 HTTPS 地址，不含账号、密码、查询参数、片段或转义字符。'
  if (!safeText(input.model, 128, true)) errors.model = '请输入上游模型名称，最多 128 个字符。'
  if (!safeText(input.environment, 64)) errors.environment = '环境最多 64 个字符，不含控制字符。'
  if (!safeText(input.channel_id, 128)) errors.channel_id = '渠道最多 128 个字符，不含控制字符。'
  if (input.tags.length > 20 || new Set(input.tags).size !== input.tags.length || input.tags.some((tag) => !safeText(tag, 64, true))) errors.tags = '最多 20 个不重复标签，每个最多 64 个字符。'
  for (const [key, max] of [['timeout_seconds', 180], ['concurrency', 100], ['rpm', 10000]] as const) {
    const value = input.options[key]
    if (!Number.isInteger(value) || value < 1 || value > max) errors[key] = `请输入 1～${max} 的整数。`
  }
  return errors
}
