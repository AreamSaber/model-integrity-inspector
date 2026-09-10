-- Completion facts are immutable and authenticated by the v2 maintenance event.
-- IDs are opaque object names, never paths or connection strings.
CREATE TABLE system_backup_receipts (
 backup_id BIGINT NOT NULL PRIMARY KEY REFERENCES system_maintenance_operations(id),
 snapshot_at_micros BIGINT NOT NULL CHECK (snapshot_at_micros > 0),
 manifest_version TEXT NOT NULL CHECK (manifest_version IN ('mii.backup-manifest.v1','mii.backup-manifest.v2','mii.backup-manifest.v3')),
 manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
 database_sha256 TEXT NOT NULL CHECK (length(database_sha256) = 64),
 archive_sha256 TEXT NOT NULL CHECK (length(archive_sha256) = 64),
 archive_bytes BIGINT NOT NULL CHECK (archive_bytes > 0 AND archive_bytes <= 1099511627776),
 plaintext_bytes BIGINT NOT NULL CHECK (plaintext_bytes > 0 AND plaintext_bytes < archive_bytes),
 entries INTEGER NOT NULL CHECK (entries >= 3 AND entries <= 65536),
 wrapping_key_version TEXT NOT NULL CHECK (length(wrapping_key_version) BETWEEN 1 AND 64),
 object_id TEXT NOT NULL UNIQUE CHECK (length(object_id) = 64),
 generation BIGINT NOT NULL CHECK (generation > 0),
 initiated_by BIGINT NOT NULL REFERENCES users(id),
 initiating_session_id BIGINT NOT NULL REFERENCES user_sessions(id),
 completed_by BIGINT NOT NULL REFERENCES users(id),
 completing_session_id BIGINT NOT NULL REFERENCES user_sessions(id),
 reason_code TEXT NOT NULL CHECK (reason_code IN ('backup.manual','backup.upgrade','backup.recovery')),
 started_at_micros BIGINT NOT NULL CHECK (started_at_micros > 0 AND started_at_micros <= snapshot_at_micros),
 completed_at_micros BIGINT NOT NULL CHECK (completed_at_micros >= snapshot_at_micros),
 digest TEXT NOT NULL CHECK (length(digest) = 64)
);
CREATE INDEX system_backup_receipts_history ON system_backup_receipts(completed_at_micros, backup_id);
