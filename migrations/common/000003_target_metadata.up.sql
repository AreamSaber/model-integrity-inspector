-- Expand-only metadata and optimistic concurrency for target management.
ALTER TABLE integrity_targets ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0);
ALTER TABLE integrity_targets ADD COLUMN environment TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_targets ADD COLUMN channel_id TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_targets ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE integrity_targets ADD COLUMN auth_header_name TEXT NOT NULL DEFAULT '';
