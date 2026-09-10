import { describe, expect, it, vi } from 'vitest'
import { historyApi, historyItem, historyQuery } from './runs-history-api'
import { history, ok, org } from './components/results/test-fixtures'

describe('Run history read boundary', () => {
  it('keeps IDs as decimal strings and separates unknown cost/result from measured zero', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ items: [history(), { ...history(), id: '1', result: null, estimated_cost_micros: 0 }], next_cursor: 'opaque-cursor' })))
    const page = await historyApi.list(org)
    expect(page.items[0].id).toBe('9007199254741023'); expect(page.items[0].estimated_cost_micros).toBeNull()
    expect(page.items[1].estimated_cost_micros).toBe(0); expect(page.items[1].result).toBeNull()
  })
  it('encodes bounded filters/cursors, HTTP risk enums, exact dates, and scoped GET requests', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok({ items: [], next_cursor: null })); vi.stubGlobal('fetch', calls)
    await historyApi.list(org, { q: 'a&b', risk_level: 'critical', model: 'example-model', date_from: '2026-09-07T00:00:00Z' }, 'opaque/+')
    const url = new URL(String(calls.mock.calls[0][0]), 'http://localhost')
    expect(url.searchParams.get('q')).toBe('a&b'); expect(url.searchParams.get('cursor')).toBe('opaque/+'); expect(url.searchParams.get('limit')).toBe('25')
    expect(url.searchParams.get('risk_level')).toBe('critical'); expect(calls.mock.calls[0][1]?.method).toBe('GET')
    expect(new Headers(calls.mock.calls[0][1]?.headers).get('X-Organization-ID')).toBe(org)
  })
  it.each([{ target_id: '9223372036854775808' }, { q: '汉'.repeat(43) }, { q: 'x\n' }, { date_from: 'not-date' }, { date_from: '2026-09-08T00:00:00Z', date_to: '2026-09-07T00:00:00Z' }])('rejects invalid filters %#', (filters) => { expect(() => historyQuery(filters)).toThrow('MI_INVALID_REQUEST') })
  it.each([{ id: Number('9007199254740993') }, { version: 0 }, { request_count: -1 }, { planned_samples: 1 }, { seed: 'SECRET_BODY_CANARY' }, { result: { ...history().result, evidence_grade: 'A' } }])('rejects unsafe history records %#', (change) => { expect(historyItem({ ...history(), ...change })).toBe(false) })
  it('bounds page size and extra envelope fields', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok({ items: Array(101).fill(history()), next_cursor: null })); vi.stubGlobal('fetch', calls)
    await expect(historyApi.list(org)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    calls.mockImplementation(async () => ok({ items: [history()], next_cursor: null, prompt: 'SECRET_BODY_CANARY' }))
    await expect(historyApi.list(org)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
})
