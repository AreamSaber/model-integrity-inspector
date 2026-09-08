import type { CheckReason, SystemCheck, SystemStatus } from '../../system-status-api'

export const org = '9007199254740995', userID = '9007199254740993', otherOrg = '9007199254740997', otherUser = '9007199254740999'
export function systemFixture(organizationID = org, user = userID): SystemStatus {
  const now = '2026-09-07T12:00:00.123456Z', startup = '2026-09-07T11:00:00.000000001Z'
  const unavailable = (reason: CheckReason): SystemCheck => ({ state: 'unavailable', source: 'not_observed', checked_at: null, reason })
  return {
    organization_id: organizationID, user_id: user, observed_at: now, observed_state: 'ok', coverage: 'partial', process_role: 'all', database_driver: 'postgres',
    build: { version: '0.1.0-dev', commit: null, built_at: null, rule_bundle: '1.0.0-dev.1', template_bundle: '1.0.0-dev.1', scoring: '1.0.0-dev.1', tokenizer_bundle: '1.0.0' },
    database: { state: 'ok', source: 'authorized_database_snapshot', checked_at: now, reason: 'read_connection_only' },
    schema: { state: 'ok', source: 'authorized_database_snapshot', checked_at: now, reason: 'migration_history_matches', expected_migrations: 15, observed_migrations: 15 },
    local_worker: { state: 'ok', source: 'local_process', checked_at: '2026-09-07T12:00:00.223456789Z', reason: 'local_runner_reports_ready' },
    remote_workers: unavailable('remote_consumer_registry_unavailable'),
    organization_jobs: { state: 'ok', source: 'selected_organization', checked_at: now, reason: 'active_jobs_not_runs_or_samples', row_limit: 10000, total_active_jobs: 10, pending_ready: 1, pending_delayed: 2, running_leased: 3, running_expired: 4 },
    organization_audit: { state: 'ok', source: 'selected_organization', checked_at: now, reason: 'tail_only_not_full_chain', verified_tail_events: 2, last_event_at: '2026-09-07T11:59:59Z' },
    master_key: { state: 'startup_verified', source: 'local_process_startup', checked_at: startup, reason: 'current_key_file_and_all_credentials_not_probed' },
    report_storage: { state: 'startup_verified', source: 'local_process_startup', checked_at: startup, reason: 'current_capacity_writeability_and_all_artifacts_not_probed' },
    retention_policy: { ...unavailable('organization_setting_not_bound_to_write_policy'), configured_body_days: 0, current_write_policy_days: 30 },
    organization_periodic_quotas: unavailable('organization_periodic_quotas_not_implemented'), retention_cleanup: unavailable('retention_handler_not_registered'), backup_restore: unavailable('backup_restore_receipts_unavailable'),
  }
}
export function unavailableJobs(data: SystemStatus) {
  Object.assign(data.organization_jobs, { state: 'unavailable', source: 'not_observed', checked_at: null, reason: 'active_job_limit_exceeded', total_active_jobs: null, pending_ready: null, pending_delayed: null, running_leased: null, running_expired: null })
}
export const ok = (data: unknown) => Response.json({ data, request_id: 'system-status-request' })
export const fail = (code: string, status = 403) => Response.json({ error: { code, message: 'PRIVATE_SYSTEM_STATUS_ERROR' }, request_id: 'system-status-error' }, { status })
