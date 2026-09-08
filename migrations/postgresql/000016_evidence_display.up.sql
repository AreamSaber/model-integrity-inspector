CREATE INDEX integrity_display_evidence_expiry ON integrity_display_evidence(organization_id, expires_at_micros, attempt_id) WHERE state = 'captured';
CREATE INDEX integrity_display_evidence_run ON integrity_display_evidence(organization_id, run_id, logical_sample_id);
