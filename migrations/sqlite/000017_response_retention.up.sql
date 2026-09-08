-- Applications can advance the cutoff but cannot lower it by another SQL path.
CREATE TRIGGER integrity_response_retention_monotonic BEFORE UPDATE OF response_evidence_not_before_micros ON organizations FOR EACH ROW WHEN NEW.response_evidence_not_before_micros < OLD.response_evidence_not_before_micros BEGIN SELECT RAISE(ABORT, 'MI_RETENTION_CUTOFF_REGRESSION'); END;
