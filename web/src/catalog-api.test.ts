import { describe, expect, it, vi } from 'vitest'
import { catalogApi, modelProfile, modelSummary, priceDecimal, priceInput, priceLabel, provider, type ModelInput, type ModelProfile, type Provider } from './catalog-api'
const org = '9007199254740993', providerID = '9007199254740995', modelID = '9007199254740997'
const providerFixture: Provider = { id: providerID, version: 1, name: 'Example', description: '', contact: '', status: 'active', created_at: '2026-09-07T08:00:00Z', updated_at: '2026-09-07T08:00:00Z' }
const modelFixture: ModelProfile = { id: modelID, provider_id: providerID, version: 1, name: 'example-model', display_name: '', protocol: 'openai_chat', status: 'active', input_price_micros_per_million: null, output_price_micros_per_million: 0, created_at: '2026-09-07T08:00:00Z', updated_at: '2026-09-07T08:00:00Z', supports_stream: true, supports_seed: false, reasoning_model: false, tokenizer_id: '', tokenizer_quality: 'unavailable' }
const input: ModelInput = { ...modelFixture, max_output_tokens: null, context_window: null }
function ok(data: unknown) { return Response.json({ data, request_id: 'catalog-test' }) }
describe('closed catalog DTO and exact monetary conversions', () => {
  it('accepts actual full provider and model detail shapes and requires a separate model summary', () => {
    expect(provider(providerFixture)).toBe(true); expect(modelProfile(modelFixture)).toBe(true)
    expect(modelSummary(modelFixture)).toBe(false)
    const { supports_stream: _stream, supports_seed: _seed, reasoning_model: _reasoning, tokenizer_id: _id, tokenizer_quality: _quality, ...summary } = modelFixture
    expect(modelSummary(summary)).toBe(true)
    expect(modelProfile(summary)).toBe(false)
  })
  it('rejects sensitive or undeclared fields, invalid identities, unsafe prices and contradictory metadata', () => {
    expect(provider({ ...providerFixture, api_key: 'not-permitted' })).toBe(false)
    for (const patch of [{ id: Number(modelID) }, { version: '1' }, { input_price_micros_per_million: Number.MAX_SAFE_INTEGER + 1 }, { supports_seed: null }, { tokenizer_quality: 'exact' }, { tokenizer_id: 'claimed', tokenizer_quality: ['exact'] }, { tokenizer_id: 'claimed', tokenizer_quality: 'unavailable' }, { max_output_tokens: null }, { max_output_tokens: 200, context_window: 100 }, { context_window: 4194305 }, { headers: {} }, { name: '\ud800' }]) expect(modelProfile({ ...modelFixture, ...patch })).toBe(false)
    expect(modelProfile({ ...modelFixture, tokenizer_quality: 'exact', tokenizer_id: 'declared-only', max_output_tokens: 100, context_window: 200 })).toBe(true)
  })
  it('round trips every safe integer micro-dollar boundary without floating point rounding and distinguishes zero from unknown', () => {
    for (const value of [0, 1, 999999, 1000000, 1234567, 9007199254740990, Number.MAX_SAFE_INTEGER]) expect(priceInput(priceDecimal(value))).toBe(value)
    expect(priceDecimal(Number.MAX_SAFE_INTEGER)).toBe('9007199254.740991')
    expect(priceInput('')).toBeNull(); expect(priceInput('0')).toBe(0)
    expect(priceLabel(null)).toBe('价格未知'); expect(priceLabel(0)).toBe('0.000000 USD / 百万 Token')
    for (const invalid of ['-1', '1e3', '0.0000001', '9007199254.740992', 'NaN']) expect(() => priceInput(invalid)).toThrow(/价格/)
  })
  it('uses scoped reads and exact CAS/delete bodies while projecting read metadata out of writes', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (url, options = {}) => {
      if (options.method === 'DELETE') return ok({ ok: true })
      return ok(String(url).includes('model-profiles') ? { ...modelFixture, version: 2 } : { ...providerFixture, version: 2 })
    }); vi.stubGlobal('fetch', fetch)
    await catalogApi.updateProvider(org, 'csrf', providerFixture, providerFixture)
    await catalogApi.updateModel(org, 'csrf', modelFixture, input)
    await catalogApi.remove('model-profiles', org, 'csrf', modelFixture)
    const [first, second, third] = fetch.mock.calls
    expect(JSON.parse(String(first[1]?.body))).toEqual({ name: 'Example', description: '', contact: '', status: 'active', version: 1 })
    expect(JSON.parse(String(second[1]?.body))).toEqual({ provider_id: providerID, name: 'example-model', display_name: '', protocol: 'openai_chat', status: 'active', supports_stream: true, supports_seed: false, reasoning_model: false, tokenizer_id: '', tokenizer_quality: 'unavailable', max_output_tokens: null, context_window: null, input_price_micros_per_million: null, output_price_micros_per_million: 0, version: 1 })
    expect(JSON.parse(String(third[1]?.body))).toEqual({ version: 1 })
    expect(new Headers(first[1]?.headers).get('X-Organization-ID')).toBe(org)
    expect(new Headers(first[1]?.headers).get('X-CSRF-Token')).toBe('csrf')
    expect(first[1]?.credentials).toBe('same-origin')
  })
  it('pins GET and update response identities and incremented versions', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ ...modelFixture, id: providerID })))
    await expect(catalogApi.model(org, modelID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    vi.stubGlobal('fetch', vi.fn(async () => ok(modelFixture)))
    await expect(catalogApi.updateModel(org, 'csrf', modelFixture, input)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('sends real q/cursor list queries and rejects invalid request identifiers before fetch', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => ok({ items: [], next_cursor: null })); vi.stubGlobal('fetch', fetch)
    await catalogApi.providers(org, 'signed+cursor', 'name%_')
    expect(String(fetch.mock.calls[0]?.[0])).toBe('/api/v1/providers?limit=25&cursor=signed%2Bcursor&q=name%25_')
    expect(() => catalogApi.provider(org, '../secret')).toThrow('MI_INVALID_REQUEST')
    expect(() => catalogApi.remove('providers', org, 'csrf', { id: providerID, version: 0 })).toThrow('MI_INVALID_REQUEST')
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
