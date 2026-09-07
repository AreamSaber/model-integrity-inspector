package repository

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrJobInvalid        = errors.New("JOB_PAYLOAD_INVALID")
	ErrJobLeaseLost      = errors.New("JOB_LEASE_LOST")
	ErrConsumerActive    = errors.New("SQLITE_CONSUMER_ALREADY_ACTIVE")
	ErrConsumerLost      = errors.New("QUEUE_CONSUMER_LEASE_LOST")
	ErrTransactionClosed = errors.New("ORGANIZATION_TRANSACTION_CLOSED")
)

type JobType string

const (
	JobRunPlan          JobType = "integrity.run.plan"
	JobSampleExecute    JobType = "integrity.sample.execute"
	JobRunAnalyze       JobType = "integrity.run.analyze"
	JobReportGenerate   JobType = "integrity.report.generate"
	JobRetentionDelete  JobType = "integrity.retention.delete"
	JobNotificationSend JobType = "integrity.notification.send"
)

// JobSpec deliberately has no JSON payload, headers, credentials or body fields.
type JobSpec struct {
	Type           JobType
	ObjectID       int64
	IdempotencyKey string
	Priority       int
	AvailableAt    time.Time
	MaxAttempts    int
}

// TenantTransaction is a short-lived typed capability, not a raw GORM handle.
// Future run/sample persistence methods can be added here so business state and
// its initial/dependent job commit together. It must not escape the callback.
type TenantTransaction struct {
	store  *Store
	db     *gorm.DB
	ctx    context.Context
	orgID  int64
	closed atomic.Bool
}

func (t *Tenant) InTransaction(fn func(*TenantTransaction) error) error {
	if fn == nil {
		return ErrConfiguration
	}
	err := t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		capability := &TenantTransaction{store: t.store, db: tx, ctx: t.ctx, orgID: t.orgID}
		defer capability.closed.Store(true)
		return fn(capability)
	})
	return queueError(err)
}

func (t *Tenant) Enqueue(spec JobSpec) (Job, error) {
	var job Job
	err := t.InTransaction(func(tx *TenantTransaction) error {
		var err error
		job, err = tx.Enqueue(spec)
		return err
	})
	return job, err
}

func (tx *TenantTransaction) Enqueue(spec JobSpec) (Job, error) {
	if tx.closed.Load() {
		return Job{}, ErrTransactionClosed
	}
	if spec.ObjectID <= 0 || strings.TrimSpace(spec.IdempotencyKey) == "" || len(spec.IdempotencyKey) > 128 || spec.Priority < -100 || spec.Priority > 100 || spec.MaxAttempts < 0 || spec.MaxAttempts > 10 {
		return Job{}, ErrJobInvalid
	}
	if spec.MaxAttempts == 0 {
		spec.MaxAttempts = 3
	}
	if err := validateJobObject(tx.db, tx.orgID, spec.Type, spec.ObjectID); err != nil {
		return Job{}, err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return Job{}, err
	}
	if spec.AvailableAt.IsZero() {
		spec.AvailableAt = now
	}
	id, err := NewID()
	if err != nil {
		return Job{}, err
	}
	job := Job{ID: id, OrganizationID: tx.orgID, Type: string(spec.Type), ObjectID: spec.ObjectID,
		IdempotencyKey: spec.IdempotencyKey, Status: "pending", Priority: spec.Priority,
		AvailableAt: spec.AvailableAt.UTC().Truncate(time.Microsecond), MaxAttempts: spec.MaxAttempts, CreatedAt: now, UpdatedAt: now}
	// The existing job wins on retries of the same command. Never reschedule or
	// overwrite a previously queued/completed job merely because the caller retried.
	result := tx.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "organization_id"}, {Name: "idempotency_key"}}, DoNothing: true}).Create(&job)
	if result.Error != nil {
		return Job{}, queueError(result.Error)
	}
	if result.RowsAffected == 0 {
		job = Job{} // Do not let GORM add the attempted new ID to the key lookup.
		if err := tx.db.Where("organization_id = ? AND idempotency_key = ?", tx.orgID, spec.IdempotencyKey).First(&job).Error; err != nil {
			return Job{}, queueError(err)
		}
		if job.Type != string(spec.Type) || job.ObjectID != spec.ObjectID || job.Priority != spec.Priority || job.MaxAttempts != spec.MaxAttempts {
			return Job{}, ErrConflict
		}
	}
	if err := tx.db.Exec("INSERT INTO integrity_queue_fairness (organization_id, last_claimed_at) VALUES (?, ?) ON CONFLICT (organization_id) DO NOTHING", tx.orgID, time.Unix(0, 0).UTC()).Error; err != nil {
		return Job{}, queueError(err)
	}
	return job, nil
}

func (t *Tenant) GetJob(id int64) (Job, error) {
	var job Job
	err := t.scoped().Where("id = ?", id).First(&job).Error
	return job, queueError(err)
}

func validateJobObject(tx *gorm.DB, organizationID int64, jobType JobType, objectID int64) error {
	if organizationID <= 0 || objectID <= 0 {
		return ErrJobInvalid
	}
	var table string
	switch jobType {
	case JobRunPlan, JobRunAnalyze:
		table = "integrity_runs"
	case JobSampleExecute:
		table = "integrity_logical_samples"
	case JobReportGenerate:
		table = "integrity_reports"
	case JobNotificationSend:
		table = "integrity_outbox"
	case JobRetentionDelete:
		if objectID != organizationID {
			return ErrJobInvalid
		}
		var count int64
		if err := tx.Table("organizations").Where("id = ? AND status = ?", organizationID, "active").Count(&count).Error; err != nil {
			return queueError(err)
		}
		if count != 1 {
			return ErrJobInvalid
		}
		return nil
	default:
		return ErrJobInvalid
	}
	var count int64
	if err := tx.Table(table).Where("organization_id = ? AND id = ?", organizationID, objectID).Count(&count).Error; err != nil {
		return queueError(err)
	}
	if count != 1 {
		return ErrJobInvalid
	}
	return nil
}

func queueTime(tx *gorm.DB, driver string) (time.Time, error) {
	if driver == "postgres" {
		var now time.Time
		// Lease authority is the database clock, not potentially skewed Worker clocks.
		if err := tx.Raw("SELECT clock_timestamp()").Scan(&now).Error; err != nil {
			return time.Time{}, ErrUnavailable
		}
		return now.UTC().Truncate(time.Microsecond), nil
	}
	// SQLite processes share the same host clock; no network clock authority exists.
	return time.Now().UTC().Truncate(time.Microsecond), nil
}

func queueError(err error) error {
	for _, known := range []error{ErrJobInvalid, ErrJobLeaseLost, ErrConsumerActive, ErrConsumerLost, ErrTransactionClosed} {
		if errors.Is(err, known) {
			return known
		}
	}
	return persistenceError(err)
}
