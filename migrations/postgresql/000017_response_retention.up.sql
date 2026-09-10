-- Function body is one physical line for the restricted migration splitter.
CREATE FUNCTION integrity_response_retention_monotonic_guard() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.response_evidence_not_before_micros < OLD.response_evidence_not_before_micros THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'MI_RETENTION_CUTOFF_REGRESSION'; END IF; RETURN NEW; END;$$;
CREATE TRIGGER integrity_response_retention_monotonic BEFORE UPDATE OF response_evidence_not_before_micros ON organizations FOR EACH ROW EXECUTE FUNCTION integrity_response_retention_monotonic_guard();
