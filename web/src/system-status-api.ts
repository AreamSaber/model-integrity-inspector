import { ApiError, request } from './api'
import { closed, decimalID, integer, readScope } from './runs-history-api'
import { trendInstant } from './trends-api'

export type CheckState = 'ok' | 'error' | 'unavailable' | 'startup_verified' | 'not_applicable'
export type CheckSource = 'authorized_database_snapshot' | 'selected_organization' | 'local_process' | 'local_process_startup' | 'not_observed'
export type CheckReason = 'read_connection_only' | 'migration_history_matches' | 'migration_history_mismatch' | 'local_runner_reports_ready' | 'local_runner_not_ready' | 'server_role_has_no_local_worker' | 'remote_consumer_registry_unavailable' | 'active_jobs_not_runs_or_samples' | 'active_job_records_invalid' | 'active_job_limit_exceeded' | 'tail_only_not_full_chain' | 'audit_tail_invalid' | 'audit_signer_unavailable' | 'current_key_file_and_all_credentials_not_probed' | 'current_capacity_writeability_and_all_artifacts_not_probed' | 'organization_setting_not_bound_to_write_policy' | 'organization_periodic_quotas_not_implemented' | 'retention_handler_not_registered' | 'backup_restore_receipts_unavailable'
export interface SystemCheck { state: CheckState; source: CheckSource; checked_at: string | null; reason: CheckReason }
export interface SystemStatus {
  organization_id: string; user_id: string; observed_at: string; observed_state: 'ok' | 'degraded'; coverage: 'partial'
  process_role: 'all' | 'server'; database_driver: 'sqlite' | 'postgres'
  build: { version: string; commit: string | null; built_at: string | null; rule_bundle: string; template_bundle: string; scoring: string; tokenizer_bundle: string }
  database: SystemCheck; schema: SystemCheck & { expected_migrations: number; observed_migrations: number }
  local_worker: SystemCheck; remote_workers: SystemCheck
  organization_jobs: SystemCheck & { row_limit: 10000; total_active_jobs: number | null; pending_ready: number | null; pending_delayed: number | null; running_leased: number | null; running_expired: number | null }
  organization_audit: SystemCheck & { verified_tail_events: number | null; last_event_at: string | null }
  master_key: SystemCheck; report_storage: SystemCheck
  retention_policy: SystemCheck & { configured_body_days: number; current_write_policy_days: 30 }
  organization_periodic_quotas: SystemCheck; retention_cleanup: SystemCheck; backup_restore: SystemCheck
}

const checkFields = ['state', 'source', 'checked_at', 'reason']
const jobFields = ['row_limit', 'total_active_jobs', 'pending_ready', 'pending_delayed', 'running_leased', 'running_expired']
const fields = ['organization_id', 'user_id', 'observed_at', 'observed_state', 'coverage', 'process_role', 'database_driver', 'build', 'database', 'schema', 'local_worker', 'remote_workers', 'organization_jobs', 'organization_audit', 'master_key', 'report_storage', 'retention_policy', 'organization_periodic_quotas', 'retention_cleanup', 'backup_restore']
function utc(value: unknown): value is string { return typeof value === 'string' && value.endsWith('Z') && trendInstant(value) !== null && Number(value.slice(0, 4)) >= 2000 && Number(value.slice(0, 4)) <= 2100 }
function version(value: unknown): value is string { return typeof value === 'string' && /^v?[0-9][0-9A-Za-z.+-]{0,127}$/.test(value) }
function check(value: unknown, state: CheckState, source: CheckSource, reason: CheckReason, extras: string[] = [], instant?: string): value is SystemCheck & Record<string, unknown> {
  return closed(value, [...checkFields, ...extras]) && value.state === state && value.source === source && value.reason === reason &&
    (state === 'unavailable' ? value.checked_at === null : utc(value.checked_at) && (instant === undefined || trendInstant(value.checked_at) === trendInstant(instant)))
}
function unavailable(value: unknown, reason: CheckReason, extras: string[] = []) { return check(value, 'unavailable', 'not_observed', reason, extras) }

// Exact S1 projection; reasons are component-specific tuples, not arbitrary
// strings or a generic MI_/"healthy" prefix. No paths, DSNs or diagnostics pass.
export function systemStatus(value: unknown, organizationID: string, userID: string): value is SystemStatus {
  if (!closed(value, fields) || !decimalID(value.organization_id) || !decimalID(value.user_id) || value.organization_id !== organizationID || value.user_id !== userID || !utc(value.observed_at) || value.coverage !== 'partial' || !['all', 'server'].includes(String(value.process_role)) || !['sqlite', 'postgres'].includes(String(value.database_driver))) return false
  const now = value.observed_at, build = value.build, schema = value.schema, jobs = value.organization_jobs, audit = value.organization_audit, retention = value.retention_policy
  if (!closed(build, ['version', 'commit', 'built_at', 'rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle']) || !['version', 'rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle'].every((key) => version(build[key])) || !(build.commit === null || typeof build.commit === 'string' && /^[0-9a-f]{40}$/.test(build.commit)) || !(build.built_at === null || utc(build.built_at))) return false
  if (!check(value.database, 'ok', 'authorized_database_snapshot', 'read_connection_only', [], now)) return false
  const schemaFields = ['expected_migrations', 'observed_migrations']
  if (!(check(schema, 'ok', 'authorized_database_snapshot', 'migration_history_matches', schemaFields, now) || check(schema, 'error', 'authorized_database_snapshot', 'migration_history_mismatch', schemaFields, now)) || !integer(schema.expected_migrations, 1, 2147483647) || !integer(schema.observed_migrations, 0, schema.expected_migrations + 1) || schema.state === 'ok' && schema.observed_migrations !== schema.expected_migrations) return false
  // Database and local-process observations use distinct clocks (possibly a
  // remote PostgreSQL host). Never invent an ordering or clock-skew tolerance.
  if (value.process_role === 'server' ? !check(value.local_worker, 'not_applicable', 'local_process', 'server_role_has_no_local_worker') : !(check(value.local_worker, 'ok', 'local_process', 'local_runner_reports_ready') || check(value.local_worker, 'error', 'local_process', 'local_runner_not_ready'))) return false
  if (!unavailable(value.remote_workers, 'remote_consumer_registry_unavailable')) return false
  if (!(check(jobs, 'ok', 'selected_organization', 'active_jobs_not_runs_or_samples', jobFields, now) || check(jobs, 'error', 'selected_organization', 'active_job_records_invalid', jobFields, now) || unavailable(jobs, 'active_job_limit_exceeded', jobFields)) || jobs.row_limit !== 10000) return false
  const counts = [jobs.total_active_jobs, jobs.pending_ready, jobs.pending_delayed, jobs.running_leased, jobs.running_expired]
  if (jobs.state === 'ok') {
    if (!counts.every((n): n is number => integer(n, 0, 10000)) || counts.slice(1).reduce((sum, n) => sum + n, 0) !== counts[0]) return false
  } else if (!counts.every((n) => n === null)) return false
  const auditFields = ['verified_tail_events', 'last_event_at']
  if (!(check(audit, 'ok', 'selected_organization', 'tail_only_not_full_chain', auditFields, now) || check(audit, 'error', 'selected_organization', 'audit_tail_invalid', auditFields, now) || unavailable(audit, 'audit_signer_unavailable', auditFields))) return false
  if (audit.state === 'ok' ? !integer(audit.verified_tail_events, 1, 2) || !utc(audit.last_event_at) : audit.verified_tail_events !== null || audit.last_event_at !== null) return false
  if (!check(value.master_key, 'startup_verified', 'local_process_startup', 'current_key_file_and_all_credentials_not_probed') || !check(value.report_storage, 'startup_verified', 'local_process_startup', 'current_capacity_writeability_and_all_artifacts_not_probed') || value.master_key.checked_at !== value.report_storage.checked_at) return false
  if (!unavailable(retention, 'organization_setting_not_bound_to_write_policy', ['configured_body_days', 'current_write_policy_days']) || !integer(retention.configured_body_days, 0, 180) || retention.current_write_policy_days !== 30) return false
  if (!unavailable(value.organization_periodic_quotas, 'organization_periodic_quotas_not_implemented') || !unavailable(value.retention_cleanup, 'retention_handler_not_registered') || !unavailable(value.backup_restore, 'backup_restore_receipts_unavailable')) return false
  const degraded = [schema, value.local_worker, jobs, audit].some((item) => (item as SystemCheck).state === 'error')
  return value.observed_state === (degraded ? 'degraded' : 'ok') && new TextEncoder().encode(JSON.stringify(value)).length <= 31 * 1024
}

export const systemStatusApi = {
  async read(organizationID: string, userID: string, signal?: AbortSignal): Promise<SystemStatus> {
    if (!decimalID(userID)) throw new ApiError('MI_INVALID_REQUEST')
    // A navigation systemAdmin hint is not authorization. The actual endpoint
    // rechecks persisted system role, session, membership and both org grants.
    return request('/system/health', (value): value is SystemStatus => systemStatus(value, organizationID, userID), { headers: readScope(organizationID), signal })
  },
}
