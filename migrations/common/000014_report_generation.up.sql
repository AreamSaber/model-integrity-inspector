ALTER TABLE integrity_reports ADD COLUMN created_by BIGINT REFERENCES users(id);
ALTER TABLE integrity_reports ADD COLUMN job_id BIGINT REFERENCES integrity_jobs(id);
ALTER TABLE integrity_reports ADD COLUMN source_json TEXT;
ALTER TABLE integrity_reports ADD COLUMN source_hash TEXT;
ALTER TABLE integrity_reports ADD COLUMN file_hash TEXT;
ALTER TABLE integrity_reports ADD COLUMN file_size BIGINT;
ALTER TABLE integrity_reports ADD COLUMN frozen_at TIMESTAMP;
CREATE TABLE integrity_report_receipts (
 organization_id BIGINT NOT NULL,
 created_by BIGINT NOT NULL,
 request_key_hash TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 run_id BIGINT NOT NULL,
 analysis_revision INTEGER NOT NULL,
 report_id BIGINT NOT NULL,
 PRIMARY KEY (organization_id, created_by, request_key_hash),
 FOREIGN KEY (organization_id, report_id) REFERENCES integrity_reports(organization_id, id),
 FOREIGN KEY (created_by) REFERENCES users(id)
);
