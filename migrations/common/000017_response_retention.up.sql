-- UTC Unix microseconds; zero means no cutoff has yet been recorded.
-- Existing response bytes are NOT backfilled, decrypted, certified or deleted.
ALTER TABLE organizations ADD COLUMN response_evidence_not_before_micros BIGINT NOT NULL DEFAULT 0 CHECK (response_evidence_not_before_micros >= 0);
