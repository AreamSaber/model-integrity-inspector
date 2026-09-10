CREATE INDEX idx_baseline_status_expiry ON integrity_baselines(organization_id,status,expires_at,id);
CREATE INDEX idx_baseline_run_revision ON integrity_baselines(organization_id,run_id,analysis_revision,id);
