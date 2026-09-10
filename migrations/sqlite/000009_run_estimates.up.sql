CREATE INDEX idx_run_estimates_owner_expiry ON integrity_run_estimates (organization_id, created_by, expires_at, id);
