CREATE TABLE integrity_run_estimates (
 id BIGINT NOT NULL PRIMARY KEY CHECK (id > 0),
 organization_id BIGINT NOT NULL REFERENCES organizations(id),
 target_id BIGINT NOT NULL,
 target_version BIGINT NOT NULL CHECK (target_version > 0),
 created_by BIGINT NOT NULL,
 manifest_hash TEXT NOT NULL,
 snapshot_json TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL,
 expires_at TIMESTAMP NOT NULL,
 UNIQUE (organization_id, id),
 FOREIGN KEY (organization_id, target_id) REFERENCES integrity_targets(organization_id, id),
 FOREIGN KEY (organization_id, created_by) REFERENCES organization_members(organization_id, user_id)
);
