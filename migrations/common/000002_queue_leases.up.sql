-- Forward-only queue coordination, preserving all version 1 business objects.
CREATE TABLE integrity_queue_consumer_leases (
 lock_name TEXT NOT NULL PRIMARY KEY,
 owner TEXT NOT NULL,
 lease_until TIMESTAMP NOT NULL,
 CHECK (lock_name = 'sqlite-primary')
);
CREATE TABLE integrity_queue_fairness (
 organization_id BIGINT NOT NULL PRIMARY KEY REFERENCES organizations(id),
 last_claimed_at TIMESTAMP NOT NULL
);
