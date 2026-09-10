ALTER TABLE system_maintenance_operations DROP CONSTRAINT system_maintenance_operations_status_check;
ALTER TABLE system_maintenance_operations ADD CONSTRAINT system_maintenance_operations_status_check CHECK (status IN ('active','aborted','superseded','completed'));
ALTER TABLE system_maintenance_events DROP CONSTRAINT system_maintenance_events_status_check;
ALTER TABLE system_maintenance_events ADD CONSTRAINT system_maintenance_events_status_check CHECK (status IN ('active','aborted','superseded','completed'));
ALTER TABLE system_maintenance_events DROP CONSTRAINT system_maintenance_events_action_check;
ALTER TABLE system_maintenance_events ADD CONSTRAINT system_maintenance_events_action_check CHECK (action IN ('begin','renew','abort','supersede','complete'));
CREATE FUNCTION system_backup_receipts_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable backup completion receipt'; END; $$;
CREATE TRIGGER system_backup_receipts_immutable BEFORE UPDATE OR DELETE ON system_backup_receipts FOR EACH ROW EXECUTE FUNCTION system_backup_receipts_immutable_guard();
