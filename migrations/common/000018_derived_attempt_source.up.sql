-- Frozen SQL mirrors are checked against the signed plan; no legacy backfill.
ALTER TABLE integrity_runs ADD COLUMN analysis_source_version TEXT NOT NULL DEFAULT 'legacy_response_v1' CHECK (analysis_source_version IN ('legacy_response_v1','mii.derived-s1.v1'));
ALTER TABLE integrity_sample_attempts ADD COLUMN derived_receipt TEXT NOT NULL DEFAULT 'legacy_not_recorded' CHECK (derived_receipt IN ('legacy_not_recorded','derived_pending','derived_recorded','derived_recovered_unavailable'));
ALTER TABLE integrity_sample_attempts ADD COLUMN response_body_receipt TEXT NOT NULL DEFAULT 'legacy_not_recorded' CHECK (response_body_receipt IN ('legacy_not_recorded','not_captured','not_retained','recorded'));
CREATE TABLE integrity_attempt_derived (
 organization_id BIGINT NOT NULL,
 run_id BIGINT NOT NULL,
 logical_sample_id BIGINT NOT NULL,
 attempt_id BIGINT NOT NULL,
 request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
 status TEXT NOT NULL CHECK (status IN ('COMPLETED','UNCERTAIN')),
 validity TEXT NOT NULL CHECK (validity IN ('VALID','VALID_WITH_WARNING','INVALID_RETRYABLE','INVALID_PROTOCOL','INVALID_SAFETY_LIMIT','NOT_APPLICABLE')),
 error_code TEXT NOT NULL CHECK (length(error_code) <= 128),
 version TEXT NOT NULL CHECK (version = 'mii.derived-s1.v1'),
 key_version TEXT NOT NULL CHECK (length(key_version) BETWEEN 1 AND 64),
 payload BYTEA NOT NULL CHECK (length(payload) BETWEEN 1 AND 32768),
 mac BYTEA NOT NULL CHECK (length(mac) = 32),
 created_at TIMESTAMP NOT NULL,
 PRIMARY KEY (organization_id, attempt_id),
 CHECK (status <> 'UNCERTAIN' OR (validity = 'INVALID_RETRYABLE' AND error_code = 'MI_UNCERTAIN_ATTEMPT')),
 FOREIGN KEY (organization_id, run_id, logical_sample_id) REFERENCES integrity_logical_samples(organization_id, run_id, id),
 FOREIGN KEY (organization_id, logical_sample_id, attempt_id) REFERENCES integrity_sample_attempts(organization_id, logical_sample_id, id),
 FOREIGN KEY (organization_id, attempt_id, request_hash) REFERENCES integrity_sample_attempts(organization_id, id, request_hash)
);
CREATE INDEX integrity_attempt_derived_run ON integrity_attempt_derived(organization_id, run_id, logical_sample_id, attempt_id);
