-- Replace only the display duration CHECK; existing ciphertext/AAD stay exact.
ALTER TABLE integrity_display_evidence RENAME TO integrity_display_evidence_v16;
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
 CHECK ((state = 'captured' AND length(source_hash) = 64 AND version = 1 AND length(key_version) BETWEEN 1 AND 64 AND nonce IS NOT NULL AND length(nonce) = 12 AND ciphertext IS NOT NULL AND plaintext_bytes BETWEEN 1 AND 4194304 AND length(ciphertext) = plaintext_bytes + 16 AND length(payload_hash) = 64 AND captured_at_micros > 0 AND expires_at_micros > captured_at_micros AND expires_at_micros - captured_at_micros BETWEEN 86400000000 AND 15552000000000 AND (expires_at_micros - captured_at_micros) % 86400000000 = 0)
 OR (state <> 'captured' AND source_hash = '' AND version = 0 AND key_version = '' AND nonce IS NULL AND ciphertext IS NULL AND plaintext_bytes = 0 AND payload_hash = '' AND captured_at_micros = 0 AND expires_at_micros = 0)),
 FOREIGN KEY (organization_id, run_id, logical_sample_id) REFERENCES integrity_logical_samples(organization_id, run_id, id),
 FOREIGN KEY (organization_id, logical_sample_id, attempt_id) REFERENCES integrity_sample_attempts(organization_id, logical_sample_id, id),
 FOREIGN KEY (organization_id, attempt_id, request_hash) REFERENCES integrity_sample_attempts(organization_id, id, request_hash)
);
INSERT INTO integrity_display_evidence SELECT * FROM integrity_display_evidence_v16;
DROP TABLE integrity_display_evidence_v16;
CREATE INDEX integrity_display_evidence_expiry ON integrity_display_evidence(organization_id, expires_at_micros, attempt_id) WHERE state = 'captured';
CREATE INDEX integrity_display_evidence_run ON integrity_display_evidence(organization_id, run_id, logical_sample_id);
CREATE TRIGGER integrity_run_source_immutable BEFORE UPDATE OF analysis_source_version ON integrity_runs WHEN NEW.analysis_source_version <> OLD.analysis_source_version BEGIN SELECT RAISE(ABORT, 'MI_DERIVED_SOURCE_IMMUTABLE'); END;
CREATE TRIGGER integrity_attempt_source_update BEFORE UPDATE ON integrity_sample_attempts WHEN (EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = NEW.organization_id AND r.id = NEW.run_id AND r.analysis_source_version = 'mii.derived-s1.v1') AND NEW.derived_receipt = 'legacy_not_recorded') OR (NOT EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = NEW.organization_id AND r.id = NEW.run_id AND r.analysis_source_version = 'mii.derived-s1.v1') AND NEW.derived_receipt <> 'legacy_not_recorded') OR (OLD.derived_receipt IN ('derived_recorded','derived_recovered_unavailable') AND NEW.derived_receipt <> OLD.derived_receipt) BEGIN SELECT RAISE(ABORT, 'MI_DERIVED_RECEIPT_INVALID'); END;
CREATE TRIGGER integrity_derived_insert_guard BEFORE INSERT ON integrity_attempt_derived WHEN NOT EXISTS (SELECT 1 FROM integrity_sample_attempts a JOIN integrity_runs r ON r.organization_id = a.organization_id AND r.id = a.run_id WHERE a.organization_id = NEW.organization_id AND a.id = NEW.attempt_id AND a.run_id = NEW.run_id AND a.logical_sample_id = NEW.logical_sample_id AND a.request_hash = NEW.request_hash AND a.status = 'DISPATCHED' AND a.derived_receipt = 'derived_pending' AND r.analysis_source_version = 'mii.derived-s1.v1') BEGIN SELECT RAISE(ABORT, 'MI_DERIVED_SOURCE_INVALID'); END;
CREATE TRIGGER integrity_attempt_derived_insert BEFORE INSERT ON integrity_sample_attempts WHEN (EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = NEW.organization_id AND r.id = NEW.run_id AND r.analysis_source_version = 'mii.derived-s1.v1') AND (NEW.derived_receipt <> 'derived_pending' OR NEW.status <> 'DISPATCHED')) OR (NOT EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = NEW.organization_id AND r.id = NEW.run_id AND r.analysis_source_version = 'mii.derived-s1.v1') AND NEW.derived_receipt <> 'legacy_not_recorded') BEGIN SELECT RAISE(ABORT, 'MI_DERIVED_RECEIPT_INVALID'); END;
CREATE TRIGGER integrity_attempt_derived_update BEFORE UPDATE ON integrity_sample_attempts WHEN (OLD.derived_receipt <> 'legacy_not_recorded' AND NEW.derived_receipt = 'legacy_not_recorded') OR (NEW.derived_receipt = 'derived_pending' AND NEW.status <> 'DISPATCHED') OR (NEW.derived_receipt IN ('derived_recorded','derived_recovered_unavailable') AND (NOT EXISTS (SELECT 1 FROM integrity_attempt_derived d WHERE d.organization_id = NEW.organization_id AND d.attempt_id = NEW.id AND d.run_id = NEW.run_id AND d.logical_sample_id = NEW.logical_sample_id AND d.request_hash = NEW.request_hash AND d.status = NEW.status AND d.validity = NEW.validity AND d.error_code = COALESCE(NEW.error_code, '')) OR (NEW.derived_receipt = 'derived_recorded' AND NEW.status <> 'COMPLETED') OR (NEW.derived_receipt = 'derived_recovered_unavailable' AND (NEW.status <> 'UNCERTAIN' OR NEW.validity <> 'INVALID_RETRYABLE' OR COALESCE(NEW.error_code, '') <> 'MI_UNCERTAIN_ATTEMPT')))) BEGIN SELECT RAISE(ABORT, 'MI_DERIVED_RECEIPT_INVALID'); END;
