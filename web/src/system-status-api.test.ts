import { describe, expect, it, vi } from 'vitest'
import { systemStatus, systemStatusApi, type SystemStatus } from './system-status-api'
import { fail, ok, org, otherOrg, otherUser, systemFixture, unavailableJobs, userID } from './components/system/test-fixtures'

describe('strict system status S1 boundary', () => {
  it('accepts current DTO, 64-bit string identity, nanoseconds and null build metadata', () => {
    expect(systemStatus(systemFixture(), org, userID)).toBe(true)
    const data = systemFixture(); data.build.commit = 'a'.repeat(40); data.build.built_at = '2026-09-07T00:00:00Z'
    data.database_driver = 'sqlite'; data.schema.expected_migrations = 16; data.schema.observed_migrations = 16
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  it('allows independent local and remote database clocks without guessing skew', () => {
    const data = systemFixture(); data.local_worker.checked_at = '2026-09-07T11:00:00Z'; data.master_key.checked_at = data.report_storage.checked_at = '2026-09-07T13:00:00Z'
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  it('distinguishes not-applicable local worker from unobserved remote workers', () => {
    const data = systemFixture(); data.process_role = 'server'; Object.assign(data.local_worker, { state: 'not_applicable', reason: 'server_role_has_no_local_worker' })
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  it('allows checksum mismatch at equal migration counts and observed local failure only as degraded', () => {
    const data = systemFixture(); data.observed_state = 'degraded'
    Object.assign(data.schema, { state: 'error', reason: 'migration_history_mismatch' })
    Object.assign(data.local_worker, { state: 'error', reason: 'local_runner_not_ready' })
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  it('preserves null counts on limits and audit unavailability, not fabricated errors or zero', () => {
    const data = systemFixture(); unavailableJobs(data)
    Object.assign(data.organization_audit, { state: 'unavailable', source: 'not_observed', reason: 'audit_signer_unavailable', checked_at: null, verified_tail_events: null, last_event_at: null })
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  it('accepts invalid-record signals with all counts suppressed and degraded observation', () => {
    const data = systemFixture(); unavailableJobs(data); data.observed_state = 'degraded'
    Object.assign(data.organization_jobs, { state: 'error', source: 'selected_organization', reason: 'active_job_records_invalid', checked_at: data.observed_at })
    Object.assign(data.organization_audit, { state: 'error', reason: 'audit_tail_invalid', verified_tail_events: null, last_event_at: null })
    expect(systemStatus(data, org, userID)).toBe(true)
  })
  const invalid: [string, (value: SystemStatus) => void][] = [
    ['foreign organization', (v) => { v.organization_id = otherOrg }], ['foreign user', (v) => { v.user_id = otherUser }],
    ['numeric identity', (v) => { Object.assign(v, { organization_id: Number(org) }) }],
    ['unknown top-level S2', (v) => { Object.assign(v, { credentials: 'PRIVATE_CANARY' }) }],
    ['missing field', (v) => { Reflect.deleteProperty(v, 'retention_cleanup') }],
    ['full coverage', (v) => { Object.assign(v, { coverage: 'full' }) }],
    ['global healthy claim', (v) => { Object.assign(v, { observed_state: 'healthy' }) }],
    ['unexplained degraded state', (v) => { v.observed_state = 'degraded' }],
    ['unknown role', (v) => { Object.assign(v, { process_role: 'worker' }) }],
    ['unknown driver', (v) => { Object.assign(v, { database_driver: 'mysql' }) }],
    ['non-UTC timestamp', (v) => { v.observed_at = '2026-09-07T20:00:00+08:00' }],
    ['invalid calendar', (v) => { v.observed_at = '2026-02-30T12:00:00Z' }],
    ['excess timestamp precision', (v) => { v.observed_at = '2026-09-07T12:00:00.1234567890Z' }],
    ['unknown build field', (v) => { Object.assign(v.build, { path: 'PRIVATE_CANARY' }) }],
    ['unsafe build version', (v) => { v.build.version = '<script>PRIVATE_CANARY</script>' }],
    ['oversized build version', (v) => { v.build.rule_bundle = '1'.repeat(130) }],
    ['unknown commit string', (v) => { v.build.commit = 'unknown' }],
    ['invalid build time', (v) => { v.build.built_at = '1999-12-31T23:59:59Z' }],
    ['DB falsely writable', (v) => { Object.assign(v.database, { reason: 'read_write_verified' }) }],
    ['DB check wrong snapshot', (v) => { v.database.checked_at = '2026-09-07T12:00:00Z' }],
    ['missing schema count', (v) => { Reflect.deleteProperty(v.schema, 'observed_migrations') }],
    ['schema count mismatch marked ok', (v) => { v.schema.observed_migrations++ }],
    ['schema unbounded count', (v) => { v.schema.observed_migrations += 2 }],
    ['negative migration count', (v) => { v.schema.expected_migrations = -1 }],
    ['server claims ready worker', (v) => { v.process_role = 'server' }],
    ['local worker stale source', (v) => { v.local_worker.source = 'local_process_startup' }],
    ['local failure ignored', (v) => { Object.assign(v.local_worker, { state: 'error', reason: 'local_runner_not_ready' }) }],
    ['remote falsely ready', (v) => { v.remote_workers.state = 'ok' }],
    ['unavailable invents observation time', (v) => { v.remote_workers.checked_at = v.observed_at }],
    ['unbounded job limit', (v) => { Object.assign(v.organization_jobs, { row_limit: 20000 }) }],
    ['job sum mismatch', (v) => { v.organization_jobs.pending_ready = 2 }],
    ['fractional job count', (v) => { v.organization_jobs.total_active_jobs = 10.5 }],
    ['infinite job count', (v) => { v.organization_jobs.total_active_jobs = Infinity }],
    ['null observed job count', (v) => { v.organization_jobs.pending_ready = null }],
    ['unknown job diagnostic', (v) => { Object.assign(v.organization_jobs, { error: 'PRIVATE_CANARY' }) }],
    ['unavailable job count falsely zero', (v) => { unavailableJobs(v); v.organization_jobs.total_active_jobs = 0 }],
    ['audit exceeds bounded tail', (v) => { v.organization_audit.verified_tail_events = 3 }],
    ['audit claims zero verified events', (v) => { v.organization_audit.verified_tail_events = 0 }],
    ['audit success missing event time', (v) => { v.organization_audit.last_event_at = null }],
    ['audit free body', (v) => { Object.assign(v.organization_audit, { event: 'PRIVATE_CANARY' }) }],
    ['audit claims whole chain', (v) => { Object.assign(v.organization_audit, { reason: 'full_chain_verified' }) }],
    ['key incorrectly current', (v) => { v.master_key.state = 'ok' }],
    ['mismatched startup record', (v) => { v.report_storage.checked_at = v.observed_at }],
    ['report storage path', (v) => { Object.assign(v.report_storage, { path: 'PRIVATE_CANARY' }) }],
    ['wrong reason for key', (v) => { v.master_key.reason = v.report_storage.reason }],
    ['retention negative', (v) => { v.retention_policy.configured_body_days = -1 }],
    ['retention too long', (v) => { v.retention_policy.configured_body_days = 181 }],
    ['retention silently bound to zero', (v) => { Object.assign(v.retention_policy, { current_write_policy_days: 0 }) }],
    ['cleanup false health', (v) => { v.retention_cleanup.state = 'ok' }],
    ['backup unknown reason', (v) => { Object.assign(v.backup_restore, { reason: 'MI_PRIVATE_CANARY' }) }],
  ]
  it.each(invalid)('rejects %s', (_, mutate) => { const value = systemFixture(); mutate(value); expect(systemStatus(value, org, userID)).toBe(false) })
})

describe('actual system status request contract', () => {
  it('makes exactly one no-query GET with same-origin scoped credentials, no client role preflight', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok(systemFixture())); vi.stubGlobal('fetch', calls)
    const controller = new AbortController(); const data = await systemStatusApi.read(org, userID, controller.signal)
    expect(data.organization_id).toBe(org); expect(calls).toHaveBeenCalledTimes(1)
    const [path, options] = calls.mock.calls[0]
    expect(path).toBe('/api/v1/system/health'); expect(options).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' })
    expect(options?.body).toBeUndefined(); expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org)
    expect(new Headers(options?.headers).get('X-CSRF-Token')).toBeNull()
    controller.abort(); expect(options?.signal?.aborted).toBe(true)
  })
  it.each(['', '0', '01', '-1', '1?scope=other', '9223372036854775808'])('rejects malformed identity %s before fetching', async (id) => {
    const calls = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', calls)
    await expect(systemStatusApi.read(id, userID)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    await expect(systemStatusApi.read(org, id)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    expect(calls).not.toHaveBeenCalled()
  })
  it('rejects valid JSON for a different scope without retaining text', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok(systemFixture(otherOrg))))
    await expect(systemStatusApi.read(org, userID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([401, 403])('invalidates malformed %i access-denied responses', async (status) => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('PRIVATE_CANARY', { status })))
    await expect(systemStatusApi.read(org, userID)).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
  })
  it('preserves forced-password response and never stores server messages', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => fail('MI_PASSWORD_CHANGE_REQUIRED')))
    await expect(systemStatusApi.read(org, userID)).rejects.toMatchObject({ code: 'MI_PASSWORD_CHANGE_REQUIRED', message: 'MI_PASSWORD_CHANGE_REQUIRED' })
  })
  it('aborts a pending network read and does not retry', async () => {
    const calls = vi.fn<typeof fetch>(() => new Promise(() => {})); vi.stubGlobal('fetch', calls)
    const controller = new AbortController(), pending = systemStatusApi.read(org, userID, controller.signal); controller.abort()
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' }); expect(calls).toHaveBeenCalledTimes(1)
  })
})
