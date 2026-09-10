package repository

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

// Pure capability boundary checks only: the dummy DB must NEVER be used. Real
// settlement/rollback, no-request and legacy behavior remain covered through the
// public queue API, and actual S1 MAC/TLS behavior through the Worker tests.
func TestExecutionReconciliationCoreRejectsDetachedOrMismatchedCapability(t *testing.T) {
	for _, mode := range []string{"nil", "store", "database", "context", "closed", "not_completing", "not_admitted", "organization", "job", "generation", "running", "pending", "unknown_type", "source_job", "source_organization", "source_type", "source_object", "source_generation", "source_status"} {
		t.Run(mode, func(t *testing.T) {
			job := Job{ID: 2, OrganizationID: 1, ObjectID: 4, Type: string(JobSampleExecute), Status: "failed", AttemptCount: 3}
			data := ExecutionReconciliationData{Job: job}
			tx := &TenantTransaction{store: &Store{}, db: &gorm.DB{}, ctx: t.Context(), orgID: 1, leaseJobID: 2, leaseGeneration: 3, completing: true, enqueueAdmitted: true}
			switch mode {
			case "nil":
				tx = nil
			case "store":
				tx.store = nil
			case "database":
				tx.db = nil
			case "context":
				tx.ctx = nil
			case "closed":
				tx.closed.Store(true)
			case "not_completing":
				tx.completing = false
			case "not_admitted":
				tx.enqueueAdmitted = false
			case "organization":
				tx.orgID++
			case "job":
				tx.leaseJobID++
			case "generation":
				tx.leaseGeneration++
			case "running", "pending":
				job.Status, data.Job.Status = mode, mode
			case "unknown_type":
				job.Type, data.Job.Type = "unsupported", "unsupported"
			case "source_job":
				data.Job.ID++
			case "source_organization":
				data.Job.OrganizationID++
			case "source_type":
				data.Job.Type = string(JobRunPlan)
			case "source_object":
				data.Job.ObjectID++
			case "source_generation":
				data.Job.AttemptCount++
			case "source_status":
				data.Job.Status = "cancelled"
			}
			got, err := tx.reconcileExecutionData(job, data, nil)
			if !errors.Is(err, ErrAnalysisSource) || got != "" {
				t.Fatal("detached/mismatched internal scope reached settlement", err)
			}
		})
	}
}
