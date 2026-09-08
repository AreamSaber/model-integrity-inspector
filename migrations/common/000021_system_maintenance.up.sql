-- A system-wide admission gate, not a tenant Job and never a timer-based restore activation.
CREATE TABLE system_maintenance_operations (
 id BIGINT NOT NULL PRIMARY KEY CHECK (id > 0),
 scope TEXT NOT NULL CHECK (scope = 'system'),
 mode TEXT NOT NULL CHECK (mode = 'backup_freeze'),
 generation BIGINT NOT NULL CHECK (generation > 0),
 owner TEXT NOT NULL CHECK (length(owner) = 64),
 initiated_by BIGINT NOT NULL REFERENCES users(id),
 session_id BIGINT NOT NULL REFERENCES user_sessions(id),
 reason_code TEXT NOT NULL CHECK (reason_code IN ('backup.manual','backup.upgrade','backup.recovery')),
 status TEXT NOT NULL CHECK (status IN ('active','aborted','superseded')),
 created_at_micros BIGINT NOT NULL CHECK (created_at_micros > 0),
 updated_at_micros BIGINT NOT NULL CHECK (updated_at_micros >= created_at_micros),
 lease_until_micros BIGINT NOT NULL CHECK (lease_until_micros > 0),
 deadline_micros BIGINT NOT NULL CHECK (deadline_micros >= lease_until_micros),
 event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
 event_digest TEXT NOT NULL CHECK (length(event_digest) = 64)
);
CREATE TABLE system_maintenance (
 id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
 version BIGINT NOT NULL CHECK (version > 0),
 mode TEXT NOT NULL CHECK (mode IN ('normal','backup_freeze','restore_isolated')),
 generation BIGINT NOT NULL CHECK (generation >= 0),
 operation_id BIGINT REFERENCES system_maintenance_operations(id),
 owner TEXT NOT NULL DEFAULT '',
 lease_until_micros BIGINT NOT NULL DEFAULT 0 CHECK (lease_until_micros >= 0),
 deadline_micros BIGINT NOT NULL DEFAULT 0 CHECK (deadline_micros >= 0),
 updated_at_micros BIGINT NOT NULL DEFAULT 0 CHECK (updated_at_micros >= 0),
 CHECK ((mode = 'normal' AND owner = '' AND lease_until_micros = 0 AND deadline_micros = 0 AND ((operation_id IS NULL AND version = 1 AND generation = 0 AND updated_at_micros = 0) OR (operation_id IS NOT NULL AND version > 1 AND generation > 0 AND updated_at_micros > 0))) OR (mode = 'backup_freeze' AND operation_id IS NOT NULL AND generation > 0 AND length(owner) = 64 AND lease_until_micros > 0 AND deadline_micros >= lease_until_micros) OR (mode = 'restore_isolated' AND owner = '' AND lease_until_micros = 0 AND deadline_micros = 0))
);
INSERT INTO system_maintenance (id, version, mode, generation) VALUES (1, 1, 'normal', 0);
CREATE TABLE system_maintenance_events (
 operation_id BIGINT NOT NULL REFERENCES system_maintenance_operations(id),
 sequence BIGINT NOT NULL CHECK (sequence > 0),
 scope TEXT NOT NULL CHECK (scope = 'system'),
 action TEXT NOT NULL CHECK (action IN ('begin','renew','abort','supersede')),
 actor_id BIGINT NOT NULL REFERENCES users(id),
 session_id BIGINT NOT NULL REFERENCES user_sessions(id),
 reason_code TEXT NOT NULL CHECK (reason_code IN ('backup.manual','backup.upgrade','backup.recovery')),
 before_mode TEXT NOT NULL CHECK (before_mode IN ('normal','backup_freeze','restore_isolated')),
 after_mode TEXT NOT NULL CHECK (after_mode IN ('normal','backup_freeze','restore_isolated')),
 before_version BIGINT NOT NULL CHECK (before_version > 0),
 after_version BIGINT NOT NULL CHECK (after_version > 0),
 before_generation BIGINT NOT NULL CHECK (before_generation >= 0),
 after_generation BIGINT NOT NULL CHECK (after_generation >= before_generation),
 generation BIGINT NOT NULL CHECK (generation > 0),
 initiated_by BIGINT NOT NULL REFERENCES users(id),
 initiating_session_id BIGINT NOT NULL REFERENCES user_sessions(id),
 previous_status TEXT NOT NULL CHECK (previous_status IN ('none','active')),
 status TEXT NOT NULL CHECK (status IN ('active','aborted','superseded')),
 observed_at_micros BIGINT NOT NULL CHECK (observed_at_micros > 0),
 lease_until_micros BIGINT NOT NULL CHECK (lease_until_micros > 0),
 deadline_micros BIGINT NOT NULL CHECK (deadline_micros >= lease_until_micros),
 digest TEXT NOT NULL CHECK (length(digest) = 64),
 PRIMARY KEY (operation_id, sequence)
);
