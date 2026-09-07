package repository

import (
	"strings"
	"time"

	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

// Development policy v1: two consecutive authentication/model failures or five
// protocol failures. These thresholds implement PRD 8.3, are not a calibrated
// model-risk signal, and cannot be changed by a Run/HTTP request.
type executionFinalClass struct {
	Validity   string
	ErrorCode  string
	HTTPStatus int
}

func (c executionFinalClass) breakerClass() (string, int) {
	if c.Validity != "INVALID_PROTOCOL" {
		return "", 0
	}
	switch c.ErrorCode {
	case "MI_AUTH_FAILED":
		if c.HTTPStatus == 401 || c.HTTPStatus == 403 {
			return "MI_CIRCUIT_AUTH_FAILURES", 2
		}
	case "MI_MODEL_NOT_FOUND":
		if c.HTTPStatus == 404 {
			return "MI_CIRCUIT_MODEL_FAILURES", 2
		}
	case "MI_PROTOCOL_UNSUPPORTED":
		return "MI_CIRCUIT_PROTOCOL_FAILURES", 5
	}
	return "", 0
}

// sequenceFinalSamples assigns each newly final LogicalSample exactly once.
// Every caller is already in a short business transaction. The Run row lock
// serializes completed results even when timestamps tie or the clock reverses.
// A batch of local skips uses completed_at,id order inside that one transaction.
func (tx *TenantTransaction) sequenceFinalSamples(runID int64) (RunRecord, bool, error) {
	run, _, err := tx.lockRun(runID)
	if err != nil {
		return run, false, err
	}
	var sampleIDs []int64
	err = tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NOT NULL AND completion_sequence IS NULL", tx.orgID, runID).Order("completed_at,id").Pluck("id", &sampleIDs).Error
	if err != nil {
		return run, false, err
	}
	// A hard-stop can finalize up to 1000 planned samples. Allocate them in one
	// bounded UPDATE instead of one network round trip per row, without loading
	// S2 request plans. IDs/sequence values remain bound SQL parameters.
	var expression strings.Builder
	expression.WriteString("CASE id")
	bindings := make([]any, 0, 2*len(sampleIDs))
	for _, sampleID := range sampleIDs {
		run.FinalizedSampleCount, err = scheduler.Add(run.FinalizedSampleCount, 1)
		if err != nil {
			return run, false, err
		}
		expression.WriteString(" WHEN ? THEN CAST(? AS BIGINT)")
		bindings = append(bindings, sampleID, run.FinalizedSampleCount)
	}
	if len(sampleIDs) > 0 {
		expression.WriteString(" END")
		result := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NOT NULL AND completion_sequence IS NULL", tx.orgID, runID).Update("completion_sequence", clause.Expr{SQL: expression.String(), Vars: bindings})
		if result.Error != nil {
			return run, false, result.Error
		}
		if result.RowsAffected != int64(len(sampleIDs)) {
			return run, false, ErrConflict
		}
		err = tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, runID).Update("finalized_sample_count", run.FinalizedSampleCount).Error
	}
	return run, len(sampleIDs) > 0, err
}

func (tx *TenantTransaction) advanceExecutionBreaker(runID int64, now time.Time) error {
	run, changed, err := tx.sequenceFinalSamples(runID)
	if err != nil {
		return err
	}
	if !changed || run.CircuitBreakerCode != "" || run.CancelRequestedAt != nil || run.ExecutionClosedAt != nil || run.Status != "RUNNING" {
		return nil
	}
	var finals []executionFinalClass
	err = tx.db.Table("integrity_logical_samples s").Select("s.validity, COALESCE(a.error_code,'') AS error_code, COALESCE(a.http_status,0) AS http_status").Joins("LEFT JOIN integrity_sample_attempts a ON a.organization_id = s.organization_id AND a.id = s.final_attempt_id AND a.logical_sample_id = s.id").Where("s.organization_id = ? AND s.run_id = ? AND s.completion_sequence IS NOT NULL", tx.orgID, runID).Order("s.completion_sequence DESC").Limit(5).Scan(&finals).Error
	if err != nil || len(finals) == 0 {
		return err
	}
	code, threshold := finals[0].breakerClass()
	if code == "" || len(finals) < threshold {
		return nil
	}
	for _, final := range finals[:threshold] {
		other, _ := final.breakerClass()
		if other != code {
			return nil
		}
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ? AND circuit_breaker_code = ''", tx.orgID, runID).Updates(map[string]any{"circuit_breaker_code": code, "circuit_breaker_opened_at": now, "error_summary": code, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	// Do not acquire other Job locks (job -> reservation mutex -> Run is the
	// established lock order). End only samples with no active dispatch intent;
	// delayed retry Jobs later finish as fenced no-ops, not new HTTP requests.
	err = tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NULL", tx.orgID, runID).Where("NOT EXISTS (SELECT 1 FROM integrity_sample_attempts a WHERE a.organization_id = integrity_logical_samples.organization_id AND a.logical_sample_id = integrity_logical_samples.id AND a.status = 'DISPATCHED')").Updates(map[string]any{"validity": "NOT_APPLICABLE", "failure_code": "MI_EXECUTION_CIRCUIT_OPEN", "completed_at": now}).Error
	if err != nil {
		return err
	}
	if _, _, err := tx.sequenceFinalSamples(runID); err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.circuit.open", "run", runID), nil)
}
