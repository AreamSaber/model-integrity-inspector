package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

// BackupExecutionSource holds one original request source, not a JobLease,
// consumer, response/evidence reader, credential reader or commit permission.
// A borrower cannot replace the source used by Apply through mutable aliases.
type BackupExecutionSource struct {
	source  BackupDrainSource
	binding [32]byte
	data    ExecutionReconciliationData
}

func (BackupExecutionSource) String() string               { return "[protected backup execution source]" }
func (s BackupExecutionSource) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (s BackupExecutionSource) LogValue() slog.Value       { return slog.StringValue(s.String()) }
func (BackupExecutionSource) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (*BackupExecutionSource) UnmarshalJSON([]byte) error  { return ErrAnalysisSensitive }
func (BackupExecutionSource) MarshalYAML() (any, error)    { return nil, ErrAnalysisSensitive }

// Use deliberately has the same synchronous protected borrowing contract as
// ExecutionReconciliationSource. It does not extend the maintenance lease or
// grant a later database write. The narrow worker preparer owns cancellation.
func (s *BackupExecutionSource) Use(fn func(ExecutionReconciliationData) error) error {
	if s == nil || s.source.store == nil || fn == nil {
		return ErrBackupDrainSource
	}
	binding, err := reconciliationBinding(s.data)
	if err != nil || binding != s.binding {
		return ErrBackupDrainSource
	}
	clone := ExecutionReconciliationSource{store: s.source.store, data: s.data}
	return clone.Use(fn)
}

func backupDrainExecutionError(err error) error {
	if errors.Is(err, ErrAnalysisLimit) {
		return ErrBackupDrainUnsupported
	}
	for _, known := range []error{ErrAnalysisSource, ErrConfiguration, ErrJobInvalid, ErrJobLeaseLost, ErrConflict, ErrNotFound, gorm.ErrRecordNotFound} {
		if errors.Is(err, known) {
			return ErrBackupDrainSource
		}
	}
	return err
}

func backupDrainExecutionOwned(lease *MaintenanceLease, source *BackupDrainSource) bool {
	return lease.valid() && source != nil && source.store == lease.store && source.operationID == lease.operationID && source.generation == lease.generation && source.owner == lease.owner
}

func backupDrainExecutionEligible(source *BackupDrainSource) bool {
	return source != nil && (source.job.Type == string(JobRunPlan) || source.job.Type == string(JobSampleExecute)) && (source.kind == BackupDrainExecutionRequired || source.kind == BackupDrainTerminalRequired)
}

func backupDrainExecutionFresh(db *gorm.DB, source *BackupDrainSource, now time.Time) (Job, error) {
	job, err := backupDrainReadJob(db, source.job.ID, now)
	if errors.Is(err, ErrBackupDrainSource) {
		return Job{}, ErrBackupDrainStale
	}
	if err != nil {
		return Job{}, err
	}
	if job != source.job {
		return Job{}, ErrBackupDrainStale
	}
	domain, err := backupDrainReadDomain(db, job)
	if err != nil {
		return Job{}, err
	}
	if domain != source.domain || backupDrainClassify(job, domain) != source.kind {
		return Job{}, ErrBackupDrainStale
	}
	// The preceding locked, SQL-bounded metadata projection covers every Job
	// text field. Only now materialize its native timestamps for the shared core.
	var result Job
	if err := db.Where("organization_id=? AND id=?", job.OrganizationID, job.ID).Take(&result).Error; err != nil {
		return Job{}, err
	}
	return result, nil
}

// LoadBackupExecutionSource reauthorizes a previously observed candidate and
// reads the original frozen request under the same lock order as settlement.
// It never terminalizes a Job or prepares/signs an unavailable S1.
func (lease *MaintenanceLease) LoadBackupExecutionSource(ctx context.Context, source *BackupDrainSource) (*BackupExecutionSource, error) {
	if !backupDrainExecutionOwned(lease, source) {
		return nil, ErrBackupDrainSource
	}
	if !backupDrainExecutionEligible(source) {
		return nil, ErrBackupDrainUnsupported
	}
	var result *BackupExecutionSource
	err := lease.backupDrainTransaction(ctx, func(db *gorm.DB, now time.Time, _ maintenanceOperation) error {
		job, err := backupDrainExecutionFresh(db, source, now)
		if err != nil {
			return err
		}
		capability := &TenantTransaction{store: lease.store, db: db, ctx: db.Statement.Context, orgID: job.OrganizationID, leaseJobID: job.ID, leaseGeneration: job.AttemptCount}
		defer capability.closed.Store(true)
		data, err := backupDrainExecutionData(capability, job, source.domain.RunID)
		if err != nil {
			return backupDrainExecutionError(err)
		}
		if _, _, _, err := backupDrainExecutionDecision(source.job, data); err != nil {
			return err
		}
		binding, err := reconciliationBinding(data)
		if err != nil {
			return ErrBackupDrainSource
		}
		result = &BackupExecutionSource{source: *source, binding: binding, data: data}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ApplyBackupExecutionSource atomically terminalizes only an expired/pending
// intent (or retains its original terminal state) and executes the existing
// private reconciliation core. Candidates are the internal trusted preparer's
// opaque S1: this repository verifies scope/outcome/structure, NOT their MAC.
func (lease *MaintenanceLease) ApplyBackupExecutionSource(ctx context.Context, source *BackupExecutionSource, candidates *AttemptDerivedCandidates) (ExecutionReconciliationResult, error) {
	if source == nil || !backupDrainExecutionOwned(lease, &source.source) {
		return "", ErrBackupDrainSource
	}
	if !backupDrainExecutionEligible(&source.source) {
		return "", ErrBackupDrainUnsupported
	}
	err := lease.backupDrainTransaction(ctx, func(db *gorm.DB, now time.Time, op maintenanceOperation) error {
		job, err := backupDrainExecutionFresh(db, &source.source, now)
		if err != nil {
			return err
		}
		actorCtx, err := workerAuditContext(db.Statement.Context, db, job)
		if err != nil {
			return backupDrainExecutionError(err)
		}
		capability := &TenantTransaction{store: lease.store, db: db, ctx: actorCtx, orgID: job.OrganizationID, leaseJobID: job.ID, leaseGeneration: job.AttemptCount, completing: true, enqueueAdmitted: true}
		defer capability.closed.Store(true)
		data, err := backupDrainExecutionData(capability, job, source.source.domain.RunID)
		if err != nil {
			return backupDrainExecutionError(err)
		}
		binding, err := reconciliationBinding(data)
		if err != nil || binding != source.binding {
			return ErrBackupDrainStale
		}
		status, code, action, err := backupDrainExecutionDecision(source.source.job, data)
		if err != nil {
			return err
		}
		heads, err := backupDrainExecutionAuditHeads(lease.store, db, job.OrganizationID, now)
		if err != nil {
			return err
		}
		if job.Status != "failed" && job.Status != "cancelled" {
			changed := db.Model(&Job{}).Where("organization_id=? AND id=? AND status=? AND attempt_count=?", job.OrganizationID, job.ID, job.Status, job.AttemptCount).
				Updates(map[string]any{"status": status, "last_error_code": code, "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
			if changed.Error != nil {
				return changed.Error
			}
			if changed.RowsAffected != 1 {
				return ErrBackupDrainStale
			}
			job.Status, job.LastErrorCode, job.LeaseOwner, job.LeaseUntil, job.CompletedAt, job.UpdatedAt = status, &code, nil, nil, &now, now
		}
		// The immutable source binding was compared BEFORE the Job transition.
		// Only this transaction's actual terminal Job is passed to the shared core.
		data.Job = job
		result, err := capability.reconcileExecutionData(job, data, candidates)
		if err != nil {
			return backupDrainExecutionError(err)
		}
		if result != ReconciliationApplied {
			return ErrBackupDrainStale
		}
		if err := backupDrainExecutionAudit(lease, db, op, job, action); err != nil {
			return err
		}
		return backupDrainExecutionVerifyHeads(lease.store, db, heads)
	})
	if err != nil {
		return "", err
	}
	return ReconciliationApplied, nil
}

func backupDrainExecutionDecision(job backupDrainJob, data ExecutionReconciliationData) (string, string, string, error) {
	if data.Run.ExecutionClosedAt != nil || data.Sample.CompletedAt != nil {
		return "", "", "", ErrBackupDrainStale
	}
	if job.Status == "failed" || job.Status == "cancelled" {
		return job.Status, job.LastErrorCode.String, "project_terminal", nil
	}
	if job.Status != "pending" && (job.Status != "running" || !job.Expired) {
		return "", "", "", ErrBackupDrainStale
	}
	switch {
	case job.CancelRequestedAt.Valid:
		return "cancelled", "JOB_CANCELLED", "terminal_rule", nil
	case job.Status == "running" && !job.LeaseUntil.Valid:
		return "failed", "JOB_LEASE_INVALID", "terminal_rule", nil
	case job.AttemptCount >= job.MaxAttempts:
		return "failed", "JOB_ATTEMPTS_EXHAUSTED", "terminal_rule", nil
	case job.Inactive:
		return "cancelled", "JOB_ORGANIZATION_INACTIVE", "terminal_rule", nil
	case job.Type == string(JobSampleExecute) && data.Attempt != nil && data.Attempt.Status == "DISPATCHED":
		return "failed", "JOB_BACKUP_UNCERTAIN", "uncertain", nil
	default:
		return "", "", "", ErrBackupDrainUnsupported
	}
}
