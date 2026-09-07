-- S2 response evidence is always encrypted; no body/header/plaintext columns.
ALTER TABLE integrity_logical_samples ADD COLUMN failure_code TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX integrity_sample_run_binding ON integrity_logical_samples(organization_id, run_id, id);
CREATE UNIQUE INDEX integrity_attempt_request_binding ON integrity_sample_attempts(organization_id, id, request_hash);
CREATE TABLE integrity_response_evidence (
 organization_id BIGINT NOT NULL,
 run_id BIGINT NOT NULL,
 logical_sample_id BIGINT NOT NULL,
 attempt_id BIGINT NOT NULL,
 request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
 key_version TEXT NOT NULL,
 nonce BYTEA NOT NULL CHECK (length(nonce) = 12),
 ciphertext BYTEA NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 1048592),
 plaintext_bytes INTEGER NOT NULL CHECK (plaintext_bytes BETWEEN 1 AND 1048576),
 content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
 created_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 PRIMARY KEY (organization_id, attempt_id),
 CHECK (length(ciphertext) = plaintext_bytes + 16),
 FOREIGN KEY (organization_id, run_id, logical_sample_id) REFERENCES integrity_logical_samples(organization_id, run_id, id),
 FOREIGN KEY (organization_id, logical_sample_id, attempt_id) REFERENCES integrity_sample_attempts(organization_id, logical_sample_id, id),
 FOREIGN KEY (organization_id, attempt_id, request_hash) REFERENCES integrity_sample_attempts(organization_id, id, request_hash)
);
