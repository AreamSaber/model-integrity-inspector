CREATE INDEX idx_queue_fairness_claim ON integrity_queue_fairness(last_claimed_at, organization_id);
INSERT INTO integrity_queue_fairness (organization_id, last_claimed_at) SELECT DISTINCT organization_id, TIMESTAMP '1970-01-01 00:00:00' FROM integrity_jobs WHERE 1 = 1 ON CONFLICT (organization_id) DO NOTHING;
CREATE INDEX idx_jobs_org_ready ON integrity_jobs(organization_id, available_at, priority DESC, id) WHERE status = 'pending';
