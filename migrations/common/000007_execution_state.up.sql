-- Expand only. Versions 1..6 remain immutable.
ALTER TABLE integrity_runs ADD COLUMN request_key TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_runs ADD COLUMN plan_job_id BIGINT REFERENCES integrity_jobs(id);
ALTER TABLE integrity_runs ADD COLUMN deadline_at TIMESTAMP;
ALTER TABLE integrity_runs ADD COLUMN reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0);
ALTER TABLE integrity_runs ADD COLUMN reserved_cost_micros BIGINT NOT NULL DEFAULT 0 CHECK (reserved_cost_micros >= 0);
ALTER TABLE integrity_runs ADD COLUMN cost_known BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE integrity_logical_samples ADD COLUMN job_id BIGINT REFERENCES integrity_jobs(id);
ALTER TABLE integrity_logical_samples ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0);
ALTER TABLE integrity_logical_samples ADD COLUMN execution_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (execution_ordinal >= 0);
ALTER TABLE integrity_sample_attempts ADD COLUMN run_id BIGINT REFERENCES integrity_runs(id);
ALTER TABLE integrity_sample_attempts ADD COLUMN job_id BIGINT REFERENCES integrity_jobs(id);
ALTER TABLE integrity_sample_attempts ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0);
ALTER TABLE integrity_sample_attempts ADD COLUMN reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0);
ALTER TABLE integrity_sample_attempts ADD COLUMN reserved_cost_micros BIGINT NOT NULL DEFAULT 0 CHECK (reserved_cost_micros >= 0);
ALTER TABLE integrity_sample_attempts ADD COLUMN cost_known BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE integrity_sample_attempts ADD COLUMN validity TEXT NOT NULL DEFAULT 'PENDING';
CREATE TABLE integrity_execution_mutex (
 lock_name TEXT PRIMARY KEY CHECK (lock_name = 'global-reservation'),
 touched INTEGER NOT NULL DEFAULT 0
);
INSERT INTO integrity_execution_mutex (lock_name, touched) VALUES ('global-reservation', 0);
