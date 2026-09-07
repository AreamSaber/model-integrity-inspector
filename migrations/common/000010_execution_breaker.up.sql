-- Completion order is a per-Run transaction sequence, never wall-clock order.
ALTER TABLE integrity_runs ADD COLUMN finalized_sample_count BIGINT NOT NULL DEFAULT 0 CHECK (finalized_sample_count >= 0);
ALTER TABLE integrity_runs ADD COLUMN circuit_breaker_code TEXT NOT NULL DEFAULT '' CHECK (circuit_breaker_code IN ('', 'MI_CIRCUIT_AUTH_FAILURES', 'MI_CIRCUIT_MODEL_FAILURES', 'MI_CIRCUIT_PROTOCOL_FAILURES'));
ALTER TABLE integrity_runs ADD COLUMN circuit_breaker_opened_at TIMESTAMP;
ALTER TABLE integrity_logical_samples ADD COLUMN completion_sequence BIGINT CHECK (completion_sequence > 0);
-- Legacy rows have no transaction-order evidence. Their one-time historical
-- backfill is explicitly deterministic by completed_at,id; new writes allocate
-- their sequence under the Run lock, including same-timestamp completions.
UPDATE integrity_logical_samples SET completion_sequence = (
 SELECT COUNT(*) FROM integrity_logical_samples previous
 WHERE previous.organization_id = integrity_logical_samples.organization_id
 AND previous.run_id = integrity_logical_samples.run_id
 AND previous.completed_at IS NOT NULL
 AND (previous.completed_at < integrity_logical_samples.completed_at
   OR (previous.completed_at = integrity_logical_samples.completed_at AND previous.id <= integrity_logical_samples.id))
) WHERE completed_at IS NOT NULL;
UPDATE integrity_runs SET finalized_sample_count = (
 SELECT COUNT(*) FROM integrity_logical_samples s
 WHERE s.organization_id = integrity_runs.organization_id AND s.run_id = integrity_runs.id AND s.completed_at IS NOT NULL
);
