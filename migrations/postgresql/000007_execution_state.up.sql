CREATE UNIQUE INDEX integrity_runs_request_key ON integrity_runs(organization_id, request_key) WHERE request_key <> '';
CREATE INDEX integrity_attempt_active ON integrity_sample_attempts(status, job_id, lease_generation);
CREATE INDEX integrity_attempt_rpm ON integrity_sample_attempts(organization_id, run_id, started_at);
CREATE INDEX integrity_sample_execution ON integrity_logical_samples(organization_id, run_id, completed_at);
