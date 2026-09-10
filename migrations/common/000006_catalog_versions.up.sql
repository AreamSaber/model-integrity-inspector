-- Versioned catalog edits retain all historical identifiers and associations.
ALTER TABLE providers ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 2147483647);
ALTER TABLE model_profiles ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 2147483647);
