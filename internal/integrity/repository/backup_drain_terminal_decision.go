package repository

import (
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type backupDrainTerminalDecision struct {
	status, code, action string
	changeJob, project   bool
}

func backupDrainTerminalDecide(job backupDrainJob, d backupDrainDomain) (backupDrainTerminalDecision, error) {
	deny := func() (backupDrainTerminalDecision, error) {
		return backupDrainTerminalDecision{}, ErrBackupDrainUnsupported
	}
	if !backupDrainTerminalType(job.Type) || job.Unsettled || job.UnsettledLegacy || (job.Status == "running" && !job.Expired) {
		return deny()
	}
	decision := backupDrainTerminalDecision{project: true}
	switch JobType(job.Type) {
	case JobRunAnalyze:
		if d.Legacy || d.State != "ANALYZING" || !d.Completed.Valid || d.Published || d.ReservedTokens != 0 || d.ReservedCost != 0 || (d.SourceVersion != AnalysisSourceLegacyV1 && d.SourceVersion != domain.AnalysisSourceDerivedV1) || job.IdempotencyKey != "analyze:"+strconv.FormatInt(job.ObjectID, 10)+":1" {
			return deny()
		}
	case JobReportGenerate:
		if d.Legacy || !d.Safe || d.JobID != job.ID {
			return deny()
		}
	case JobTargetPrecheck:
		if d.Legacy || d.JobID != job.ID || d.Completed.Valid || (d.State != "queued" && d.State != "running") {
			return deny()
		}
	case JobRetentionDelete:
		decision.project = false
		if job.ObjectID == job.OrganizationID {
			if !d.Legacy {
				return deny()
			}
		} else if d.Legacy || !d.Safe || d.JobID != job.ID {
			return deny()
		}
	case JobNotificationSend:
		decision.project = false // Outbox delivery facts remain entirely untouched.
	}
	if job.Status == "failed" || job.Status == "cancelled" {
		if !decision.project {
			return deny() // No new fact to apply or audit on an old terminal queue-only job.
		}
		decision.status, decision.code, decision.action = job.Status, job.LastErrorCode.String, "project_terminal"
		return decision, nil
	}
	if (job.Status != "pending" && job.Status != "running") || job.CompletedAt.Valid {
		return deny()
	}
	decision.changeJob, decision.action = true, "terminalize"
	// Preserve the actual queue's precedence, including disabled-retention's
	// existing exception already represented by job.Inactive.
	switch {
	case job.CancelRequestedAt.Valid:
		decision.status, decision.code = "cancelled", "JOB_CANCELLED"
	case job.Status == "running" && !job.LeaseUntil.Valid:
		decision.status, decision.code = "failed", "JOB_LEASE_INVALID"
	case job.AttemptCount >= job.MaxAttempts:
		decision.status, decision.code = "failed", "JOB_ATTEMPTS_EXHAUSTED"
	case job.Inactive:
		decision.status, decision.code = "cancelled", "JOB_ORGANIZATION_INACTIVE"
	case JobType(job.Type) == JobTargetPrecheck && d.Count > 0 && job.AttemptCount > 0:
		decision.status, decision.code, decision.action = "failed", "JOB_BACKUP_UNCERTAIN", "precheck_uncertain"
	case JobType(job.Type) == JobNotificationSend && job.AttemptCount > 0:
		decision.status, decision.code, decision.action = "failed", "JOB_DELIVERY_UNCERTAIN", "notification_uncertain"
	default:
		return deny()
	}
	return decision, nil
}
