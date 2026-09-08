CREATE INDEX idx_evidence_disclosures_history ON integrity_evidence_disclosures(organization_id, run_id, authorized_at, id);
CREATE FUNCTION integrity_evidence_disclosure_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable disclosure receipt'; END; $$;
CREATE TRIGGER integrity_evidence_disclosure_immutable BEFORE UPDATE OR DELETE ON integrity_evidence_disclosures FOR EACH ROW EXECUTE FUNCTION integrity_evidence_disclosure_immutable_guard();
