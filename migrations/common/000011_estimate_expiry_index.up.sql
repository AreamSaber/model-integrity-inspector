-- Bounded maintenance must not scan retained Run/evidence payloads.
CREATE INDEX idx_run_estimates_expiry ON integrity_run_estimates(expires_at, organization_id, id);
