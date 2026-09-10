package repository

import (
	"bytes"
	"encoding/json"
	"strings"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func backupDrainExecutionData(tx *TenantTransaction, job Job, runID int64) (ExecutionReconciliationData, error) {
	zero := ExecutionReconciliationData{}
	if _, err := tx.LockResponseRetentionPolicy(); err != nil {
		return zero, err
	}
	if err := tx.serializeReservations(); err != nil {
		return zero, err
	}
	if err := backupDrainExecutionBounds(tx.db, job, runID); err != nil {
		return zero, err
	}
	data, err := tx.reconciliationData(job, 0)
	if err != nil {
		return zero, err
	}
	if data.Run.ID != runID || data.Run.OrganizationID != job.OrganizationID || data.Run.ManifestHash != data.Plan.ManifestHash || !validateExecutionPlan(data.Plan) || !validRunAnalysisSource(data.Run, data.Plan) || data.Run.RuleBundleVersion != data.Plan.Versions.Rule || data.Run.TemplateBundleVersion != data.Plan.Versions.Template || data.Run.ScoringVersion != data.Plan.Versions.Scoring || data.Run.TokenizerBundleVersion != data.Plan.Versions.Tokenizer || data.Run.TargetID != data.Plan.Target.ID {
		return zero, ErrBackupDrainSource
	}
	for _, body := range []string{data.Run.ConfigSnapshot, data.Sample.RequestPlan} {
		if body != "" {
			if err := snapshotKeyStrictJSON(tx.ctx, []byte(body)); err != nil {
				return zero, ErrBackupDrainSource
			}
		}
	}
	if job.Type == string(JobRunPlan) {
		if data.Run.PlanJobID == nil || *data.Run.PlanJobID != job.ID || (data.Run.Status != "QUEUED" && data.Run.Status != "CANCELLING") || data.Run.RequestCount != 0 || data.Run.ReservedTokens != 0 || data.Run.ReservedCostMicros != 0 || data.Run.StartedAt != nil {
			return zero, ErrBackupDrainUnsupported
		}
		var intent bool
		if err := tx.db.Raw(`SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts a JOIN integrity_logical_samples s ON s.organization_id=a.organization_id AND s.id=a.logical_sample_id WHERE s.organization_id=? AND s.run_id=?)`, job.OrganizationID, runID).Scan(&intent).Error; err != nil {
			return zero, err
		}
		if intent {
			return zero, ErrBackupDrainUnsupported
		}
		return data, nil
	}
	if err := backupDrainExecutionSample(tx.db, data); err != nil {
		return zero, err
	}
	var active []struct{ ID int64 }
	if err := tx.db.Table("integrity_sample_attempts").Select("id").Where("organization_id=? AND logical_sample_id=? AND status='DISPATCHED'", job.OrganizationID, data.Sample.ID).Limit(2).Find(&active).Error; err != nil {
		return zero, err
	}
	if len(active) > 1 {
		return zero, ErrBackupDrainSource
	}
	if len(active) == 1 && (data.Attempt == nil || data.Attempt.ID != active[0].ID) {
		// The existing narrow reader must not hide a nullable/G0 old intent and
		// turn it into the core's no-attempt NOT_APPLICABLE path.
		return zero, ErrBackupDrainUnsupported
	}
	if data.Attempt != nil {
		a := data.Attempt
		if a.Status != "DISPATCHED" || a.FinishedAt != nil || a.StartedAt == nil || a.JobID != job.ID || a.OrganizationID != job.OrganizationID || a.RunID != runID || a.LogicalSampleID != data.Sample.ID || a.LeaseGeneration < 1 || a.LeaseGeneration > job.AttemptCount || a.AttemptNo < 1 || a.AttemptNo != data.Sample.AttemptCount || a.ReservedTokens < 0 || a.ReservedCostMicros < 0 {
			return zero, ErrBackupDrainSource
		}
		if err := snapshotKeyStrictJSON(tx.ctx, []byte(a.RequestSnapshot)); err != nil {
			return zero, ErrBackupDrainSource
		}
		var plan domain.SamplePlan
		var request domain.RequestSnapshot
		if json.Unmarshal([]byte(data.Sample.RequestPlan), &plan) != nil || json.Unmarshal([]byte(a.RequestSnapshot), &request) != nil || request.RequestHash != a.RequestHash || !validDispatchSnapshot(plan, request) {
			return zero, ErrBackupDrainSource
		}
	}
	return data, nil
}

// Preflight the sum BEFORE loading any of the original payload columns. The
// shared reader repeats its own individual 8/2/2 MiB checks under these locks.
func backupDrainExecutionBounds(db *gorm.DB, job Job, runID int64) error {
	if runID <= 0 {
		return ErrBackupDrainSource
	}
	queries := []struct {
		query   *gorm.DB
		body    string
		maximum int64
	}{
		{db.Model(&RunRecord{}).Where("organization_id=? AND id=?", job.OrganizationID, runID), "config_snapshot", 8 << 20},
	}
	if job.Type == string(JobSampleExecute) {
		queries = append(queries, struct {
			query   *gorm.DB
			body    string
			maximum int64
		}{db.Model(&LogicalSampleRecord{}).Where("organization_id=? AND id=? AND job_id=?", job.OrganizationID, job.ObjectID, job.ID), "request_plan", 2 << 20}, struct {
			query   *gorm.DB
			body    string
			maximum int64
		}{db.Model(&AttemptRecord{}).Where("organization_id=? AND logical_sample_id=? AND status='DISPATCHED'", job.OrganizationID, job.ObjectID), "request_snapshot", 2 << 20})
	}
	var total int64
	for i, query := range queries {
		size, err := analysisRowByteSize(query.query, db.Name(), query.body)
		if err != nil {
			return err
		}
		if size.Rows > 1 || size.Bytes > query.maximum || size.Largest > query.maximum {
			return ErrAnalysisLimit
		}
		if i < 2 && size.Rows != 1 {
			return ErrBackupDrainSource
		}
		total += size.Bytes
	}
	if total > 8<<20 {
		return ErrAnalysisLimit
	}
	if err := backupDrainExecutionMetadata(db, "integrity_runs", job.OrganizationID, runID, []string{"analysis_source_version", "package", "observation_mode", "status", "manifest_hash", "rule_bundle_version", "template_bundle_version", "scoring_version", "tokenizer_bundle_version", "error_summary", "request_key", "circuit_breaker_code"}); err != nil {
		return err
	}
	if job.Type == string(JobSampleExecute) {
		if err := backupDrainExecutionMetadata(db, "integrity_logical_samples", job.OrganizationID, job.ObjectID, []string{"pair_id", "idempotency_key", "validity", "failure_code"}); err != nil {
			return err
		}
		var ids []int64
		if err := db.Table("integrity_sample_attempts").Select("id").Where("organization_id=? AND logical_sample_id=? AND status='DISPATCHED'", job.OrganizationID, job.ObjectID).Limit(2).Find(&ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			if err := backupDrainExecutionMetadata(db, "integrity_sample_attempts", job.OrganizationID, id, []string{"derived_receipt", "response_body_receipt", "status", "validity", "request_hash", "error_code", "tokenizer_id", "tokenizer_quality"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func backupDrainExecutionSample(db *gorm.DB, data ExecutionReconciliationData) error {
	sample, run := data.Sample, data.Run
	if sample.ID != data.Job.ObjectID || sample.OrganizationID != data.Job.OrganizationID || sample.RunID != run.ID || sample.JobID == nil || *sample.JobID != data.Job.ID || sample.CompletedAt != nil || sample.FinalAttemptID != nil || sample.CompletionSequence != nil || sample.ExecutionOrdinal < 0 {
		return ErrBackupDrainStale
	}
	ordinal := 0
	for _, probe := range data.Plan.Probes {
		for _, planned := range probe.Samples {
			if ordinal == sample.ExecutionOrdinal {
				encoded, err := json.Marshal(planned)
				if err != nil || !bytes.Equal(encoded, []byte(sample.RequestPlan)) || planned.Ordinal != sample.Ordinal || (sample.PairID == nil && planned.PairID != "") || (sample.PairID != nil && *sample.PairID != planned.PairID) {
					return ErrBackupDrainSource
				}
				var count int64
				if err := db.Table("integrity_probe_instances").Where("organization_id=? AND run_id=? AND id=? AND template_id=? AND template_version=? AND probe_type=? AND category=? AND variant=?", sample.OrganizationID, sample.RunID, sample.ProbeInstanceID, probe.TemplateID, probe.TemplateVersion, probe.Type, probe.Category, probe.Variant).Count(&count).Error; err != nil {
					return err
				}
				if count != 1 {
					return ErrBackupDrainSource
				}
				return nil
			}
			ordinal++
		}
	}
	return ErrBackupDrainSource
}

// Metadata is also bounded before the shared typed models materialize it.
// This is an active-source support limit, not a static history admission rule.
func backupDrainExecutionMetadata(db *gorm.DB, table string, org, id int64, fields []string) error {
	checks := make([]string, 0, len(fields))
	for _, field := range fields {
		checks = append(checks, backupDrainText(db, field, 4096, true))
	}
	var count int64
	if err := db.Table(table).Where("organization_id=? AND id=?", org, id).Where(strings.Join(checks, " AND ")).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return ErrBackupDrainUnsupported
	}
	return nil
}
