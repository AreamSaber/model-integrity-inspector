-- S1-only authorization receipts. No response/request, endpoint, key or session
-- hash is stored. The audit object's ID also binds the canonical receipt hash.
CREATE TABLE integrity_evidence_disclosures (
 id BIGINT NOT NULL PRIMARY KEY CHECK (id > 0),
 organization_id BIGINT NOT NULL,
 actor_id BIGINT NOT NULL,
 action TEXT NOT NULL CHECK (action = 'evidence.body.read'),
 run_id BIGINT NOT NULL,
 logical_sample_id BIGINT NOT NULL,
 attempt_id BIGINT NOT NULL,
 analysis_revision INTEGER NOT NULL CHECK (analysis_revision = 1),
 source_kind TEXT NOT NULL CHECK (source_kind = 'response-display'),
 policy TEXT NOT NULL CHECK (policy = 'display-redaction-v1'),
 source_digest TEXT NOT NULL CHECK (length(source_digest) = 64),
 payload_hash TEXT NOT NULL CHECK (payload_hash = '' OR length(payload_hash) = 64),
 format_version TEXT NOT NULL CHECK (format_version = 'mii.evidence-display-output.v1'),
 output_hash TEXT NOT NULL CHECK (length(output_hash) = 64),
 output_bytes BIGINT NOT NULL CHECK (output_bytes BETWEEN 1 AND 8388608),
 policy_version INTEGER NOT NULL CHECK (policy_version > 0),
 policy_cutoff_micros BIGINT NOT NULL CHECK (policy_cutoff_micros >= 0),
 authorized_at TIMESTAMP NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('authorized','unavailable')),
 receipt_hash TEXT NOT NULL CHECK (length(receipt_hash) = 64),
 UNIQUE (organization_id, id),
 FOREIGN KEY (organization_id, actor_id) REFERENCES organization_members(organization_id, user_id),
 FOREIGN KEY (organization_id, run_id, analysis_revision) REFERENCES integrity_run_results(organization_id, run_id, analysis_revision),
 FOREIGN KEY (organization_id, run_id, logical_sample_id) REFERENCES integrity_logical_samples(organization_id, run_id, id),
 FOREIGN KEY (organization_id, logical_sample_id, attempt_id) REFERENCES integrity_sample_attempts(organization_id, logical_sample_id, id)
);
