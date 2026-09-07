-- Reviews are append-only application history. A retry receives the original
-- review identity even after another reviewer appends a newer decision.
CREATE TABLE integrity_review_receipts (
 organization_id BIGINT NOT NULL,
 created_by BIGINT NOT NULL,
 request_key_hash TEXT NOT NULL CHECK (length(request_key_hash) = 64),
 request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
 run_id BIGINT NOT NULL,
 analysis_revision INTEGER NOT NULL CHECK (analysis_revision > 0),
 review_id BIGINT NOT NULL,
 PRIMARY KEY (organization_id, created_by, request_key_hash),
 FOREIGN KEY (organization_id, created_by) REFERENCES organization_members(organization_id, user_id),
 FOREIGN KEY (organization_id, run_id, analysis_revision) REFERENCES integrity_run_results(organization_id, run_id, analysis_revision),
 FOREIGN KEY (organization_id, review_id) REFERENCES integrity_reviews(organization_id, id)
);
