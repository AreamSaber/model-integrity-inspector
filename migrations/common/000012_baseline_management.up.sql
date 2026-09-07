-- Expand-only baseline approval metadata. Historical unsigned rows do not
-- inherit trust merely because they previously carried an approval label.
ALTER TABLE integrity_baselines ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 2147483647);
ALTER TABLE integrity_baselines ADD COLUMN created_by BIGINT REFERENCES users(id);
ALTER TABLE integrity_baselines ADD COLUMN source TEXT NOT NULL DEFAULT 'historical' CHECK (source IN ('official','historical'));
ALTER TABLE integrity_baselines ADD COLUMN region TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE integrity_baselines ADD COLUMN retired_at TIMESTAMP;
ALTER TABLE integrity_baselines ADD COLUMN source_manifest_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN source_result_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN parameters_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN snapshot_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE integrity_baselines ADD COLUMN snapshot_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN approval_key_version TEXT;
ALTER TABLE integrity_baselines ADD COLUMN approval_mac TEXT;
ALTER TABLE integrity_baselines ADD COLUMN review_explanation TEXT NOT NULL DEFAULT '';
ALTER TABLE integrity_baselines ADD COLUMN retirement_reason TEXT NOT NULL DEFAULT '';
UPDATE integrity_baselines SET updated_at=created_at,status=CASE WHEN status='pending' THEN 'draft' ELSE status END;
