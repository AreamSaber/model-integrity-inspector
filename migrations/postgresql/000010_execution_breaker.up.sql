CREATE UNIQUE INDEX integrity_sample_completion_order ON integrity_logical_samples(organization_id, run_id, completion_sequence) WHERE completion_sequence IS NOT NULL;
