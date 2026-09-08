-- Independent S2 display copies; no raw body, key, custom headers or URL.
-- Legacy response evidence is deliberately not backfilled or certified.
CREATE TABLE integrity_display_evidence (
 organization_id BIGINT NOT NULL,
 run_id BIGINT NOT NULL,
 logical_sample_id BIGINT NOT NULL,
 attempt_id BIGINT NOT NULL,
 request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
 policy TEXT NOT NULL CHECK (policy = 'display-redaction-v1'),
 state TEXT NOT NULL CHECK (state IN ('captured','unavailable_redaction_policy','unavailable_safety_limit','unavailable_source_invalid','unavailable_cancelled','unavailable_capture','unavailable_seal')),
 source_hash TEXT NOT NULL,
 version INTEGER NOT NULL,
 key_version TEXT NOT NULL,
 nonce BYTEA,
 ciphertext BYTEA,
 plaintext_bytes INTEGER NOT NULL,
 payload_hash TEXT NOT NULL,
 captured_at_micros BIGINT NOT NULL,
 expires_at_micros BIGINT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 PRIMARY KEY (organization_id, attempt_id, policy),
 CHECK ((state = 'captured' AND length(source_hash) = 64 AND version = 1 AND length(key_version) BETWEEN 1 AND 64 AND nonce IS NOT NULL AND length(nonce) = 12 AND ciphertext IS NOT NULL AND plaintext_bytes BETWEEN 1 AND 4194304 AND length(ciphertext) = plaintext_bytes + 16 AND length(payload_hash) = 64 AND captured_at_micros > 0 AND expires_at_micros > captured_at_micros AND expires_at_micros - captured_at_micros = 2592000000000)
 OR (state <> 'captured' AND source_hash = '' AND version = 0 AND key_version = '' AND nonce IS NULL AND ciphertext IS NULL AND plaintext_bytes = 0 AND payload_hash = '' AND captured_at_micros = 0 AND expires_at_micros = 0)),
 FOREIGN KEY (organization_id, run_id, logical_sample_id) REFERENCES integrity_logical_samples(organization_id, run_id, id),
 FOREIGN KEY (organization_id, logical_sample_id, attempt_id) REFERENCES integrity_sample_attempts(organization_id, logical_sample_id, id),
 FOREIGN KEY (organization_id, attempt_id, request_hash) REFERENCES integrity_sample_attempts(organization_id, id, request_hash)
);
