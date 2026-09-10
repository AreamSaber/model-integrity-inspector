CREATE INDEX idx_targets_current_org_status ON integrity_targets(organization_id,status,id) WHERE deleted_at IS NULL;
