CREATE INDEX system_maintenance_operation_history ON system_maintenance_operations(created_at_micros, id);
CREATE UNIQUE INDEX system_maintenance_operation_generation ON system_maintenance_operations(generation);
CREATE INDEX system_maintenance_audit_source ON integrity_audit_logs(organization_id, object_type, object_id);
CREATE TRIGGER system_maintenance_events_immutable BEFORE UPDATE ON system_maintenance_events BEGIN SELECT RAISE(ABORT, 'immutable system maintenance event'); END;
CREATE TRIGGER system_maintenance_events_no_delete BEFORE DELETE ON system_maintenance_events BEGIN SELECT RAISE(ABORT, 'immutable system maintenance event'); END;
CREATE TRIGGER system_maintenance_operation_no_delete BEFORE DELETE ON system_maintenance_operations BEGIN SELECT RAISE(ABORT, 'immutable system maintenance history'); END;
CREATE TRIGGER system_maintenance_operation_terminal BEFORE UPDATE ON system_maintenance_operations WHEN OLD.status <> 'active' BEGIN SELECT RAISE(ABORT, 'terminal system maintenance operation'); END;
