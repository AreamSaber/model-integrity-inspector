CREATE INDEX idx_evidence_disclosures_history ON integrity_evidence_disclosures(organization_id, run_id, authorized_at, id);
CREATE TRIGGER integrity_evidence_disclosure_immutable BEFORE UPDATE ON integrity_evidence_disclosures BEGIN SELECT RAISE(ABORT, 'immutable disclosure receipt'); END;
CREATE TRIGGER integrity_evidence_disclosure_no_delete BEFORE DELETE ON integrity_evidence_disclosures BEGIN SELECT RAISE(ABORT, 'immutable disclosure receipt'); END;
