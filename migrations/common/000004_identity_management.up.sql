-- Identity and organization management: additive, portable expansion.
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE organizations ADD COLUMN full_response_retention_days INTEGER NOT NULL DEFAULT 30 CHECK (full_response_retention_days BETWEEN 0 AND 180);
ALTER TABLE organizations ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE organization_members ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE organization_members ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';
UPDATE organization_members SET updated_at = created_at WHERE updated_at = '1970-01-01 00:00:00';
CREATE TABLE member_permissions (
 organization_id BIGINT NOT NULL,
 member_id BIGINT NOT NULL,
 permission_code TEXT NOT NULL REFERENCES permissions(code),
 PRIMARY KEY (organization_id, member_id, permission_code),
 FOREIGN KEY (organization_id, member_id) REFERENCES organization_members(organization_id, id)
);
