CREATE INDEX idx_reviews_run_history ON integrity_reviews(organization_id, run_id, analysis_revision, created_at, id);
