CREATE INDEX system_maintenance_operation_history ON system_maintenance_operations(created_at_micros, id);
CREATE UNIQUE INDEX system_maintenance_operation_generation ON system_maintenance_operations(generation);
CREATE INDEX system_maintenance_audit_source ON integrity_audit_logs(organization_id, object_type, object_id);
CREATE FUNCTION system_maintenance_events_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable system maintenance event'; END; $$;
CREATE TRIGGER system_maintenance_events_immutable BEFORE UPDATE OR DELETE ON system_maintenance_events FOR EACH ROW EXECUTE FUNCTION system_maintenance_events_immutable_guard();
CREATE FUNCTION system_maintenance_operation_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP = 'DELETE' OR OLD.status <> 'active' THEN RAISE EXCEPTION 'terminal system maintenance operation'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER system_maintenance_operation_immutable BEFORE UPDATE OR DELETE ON system_maintenance_operations FOR EACH ROW EXECUTE FUNCTION system_maintenance_operation_immutable_guard();
