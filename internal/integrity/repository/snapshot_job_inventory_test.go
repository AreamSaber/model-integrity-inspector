package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/migrations"
)

func snapshotJobTestObserve(t *testing.T, s *Store, cfg Config, want error) snapshotJobInventory {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := (&Store{driver: s.driver}).snapshotJobInventory(ctx, tx)
	if !errors.Is(err, want) || (want != nil && (got.organizations != nil || got.classification != snapshotJobUnverified || err.Error() != want.Error())) {
		t.Fatalf("inventory error/zero candidate: %v", err)
	}
	return got
}

func snapshotJobTestInsert(t *testing.T, s *Store, table string, row map[string]any) {
	t.Helper()
	if err := s.db.Table(table).Create(row).Error; err != nil {
		t.Fatalf("insert constrained %s fixture: %v", table, err)
	}
}

func snapshotJobTestOrganizations(t *testing.T, s *Store, count int) []int64 {
	t.Helper()
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	ids := make([]int64, 0, count)
	for i := range count {
		id := int64(i + 1)
		status := "active"
		if i%2 == 0 {
			status = "disabled"
		}
		snapshotJobTestInsert(t, s, "organizations", map[string]any{"id": id, "name": fmt.Sprintf("snapshot-org-%d", id), "status": status, "created_at": stamp, "updated_at": stamp})
		ids = append(ids, id)
	}
	return ids
}

func snapshotJobTestRetention(t *testing.T, s *Store, org, id int64, state string) {
	t.Helper()
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	snapshotJobTestInsert(t, s, "integrity_jobs", map[string]any{"id": id, "organization_id": org, "type": string(JobRetentionDelete), "object_id": org, "idempotency_key": fmt.Sprintf("snapshot-retention-%d", id), "status": state, "available_at": stamp, "created_at": stamp, "updated_at": stamp})
}

func snapshotJobTestPrecheckPermission(t *testing.T, tenant *Tenant) {
	t.Helper()
	var role int64
	if err := tenant.store.db.Table("roles").Select("id").Where("organization_id=? AND name='administrator'", tenant.orgID).Scan(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := tenant.store.db.Exec("INSERT INTO permissions (code) VALUES ('target.precheck') ON CONFLICT (code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := tenant.store.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) VALUES (?,?,'target.precheck') ON CONFLICT DO NOTHING", tenant.orgID, role).Error; err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotJobInventoryAllKindsCurrentBindings(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		// Real create/claim/reserve/complete/publish transactions cover plan,
		// sample and analyze. Report and precheck use their real enqueue APIs.
		// Notification/retention below are constrained historical row fixtures;
		// this test does not claim delivery of a notification or a disk cleanup.
		tenant, _, run := reportFixture(t, s)
		snapshotJobTestPrecheckPermission(t, tenant)
		if _, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "csv", IdempotencyKey: "snapshot-job-report"}); err != nil {
			t.Fatal(err)
		}
		var target TargetRecord
		if err := s.db.Where("id=?", run.TargetID).Take(&target).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: target.ID, TargetVersion: target.Version, SecretID: target.SecretID, SecretVersion: 1, RequestKey: "snapshot-job-precheck", SnapshotJSON: "{}"}); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		snapshotJobTestInsert(t, s, "integrity_outbox", map[string]any{"id": int64(11), "organization_id": tenant.orgID, "event_type": "run.completed", "object_id": run.ID, "idempotency_key": "snapshot-notification", "available_at": stamp, "created_at": stamp})
		if _, err := tenant.Enqueue(JobSpec{Type: JobNotificationSend, ObjectID: 11, IdempotencyKey: "snapshot-notification-job"}); err != nil {
			t.Fatal(err)
		}
		for i, state := range []string{"pending", "completed", "failed", "cancelled"} {
			snapshotJobTestRetention(t, s, tenant.orgID, int64(100+i), state)
		}
		// A completed batch is valid historical data although current enqueue
		// admission only accepts planned batches. Its original receipt stays.
		snapshotJobTestInsert(t, s, "integrity_response_retention_batches", map[string]any{"id": int64(201), "organization_id": tenant.orgID, "run_id": run.ID, "created_by": run.CreatedBy, "created_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_jobs", map[string]any{"id": int64(202), "organization_id": tenant.orgID, "type": string(JobRetentionDelete), "object_id": int64(201), "idempotency_key": "response-retention:201", "status": "completed", "available_at": stamp, "created_at": stamp, "updated_at": stamp, "attempt_count": 1})
		if err := s.db.Table("integrity_response_retention_batches").Where("id=201").Updates(map[string]any{"job_id": int64(202), "state": "completed", "completed_at": stamp, "policy_version": 1, "observed_at_micros": stamp.UnixMicro(), "receipt_hash": strings.Repeat("a", 64)}).Error; err != nil {
			t.Fatal(err)
		}
		// Disabled organizations must retain their queued and historical work.
		if err := s.db.Table("organizations").Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotJobTestObserve(t, s, cfg, nil)
		want := snapshotJobOrganization{organizationID: tenant.orgID, pending: 4, completed: 6, failed: 1, cancelled: 1, completedAttempts: 2}
		if got.classification != snapshotJobVerifiedCurrent || len(got.organizations) != 1 || got.organizations[0] != want {
			t.Fatalf("seven-kind exact counts mismatch: %#v", got)
		}
		var kinds int64
		if err := s.db.Table("integrity_jobs").Distinct("type").Count(&kinds).Error; err != nil || kinds != 7 {
			t.Fatal("fixture did not actually cover all seven job kinds")
		}
	})
}

func TestSnapshotJobInventoryPagesOwnedSameViewAndPopulation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ids := snapshotJobTestOrganizations(t, s, 101)
		for _, id := range ids {
			snapshotJobTestRetention(t, s, id, id+1000, "pending")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		var pages []int
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_job_pages", func(q *gorm.DB) {
			if rows, ok := q.Statement.Dest.(*[]int64); ok && q.Statement.Table == "organizations" && q.Error == nil {
				pages = append(pages, len(*rows))
			}
		}); err != nil {
			t.Fatal(err)
		}
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotJobInventory(ctx, tx.Where("1=0").Select("id").Limit(1).Order("id DESC"))
		if err != nil || len(got.organizations) != 101 || !reflect.DeepEqual(pages, []int{100, 1}) {
			t.Fatalf("real complete organization pages: %v %v", pages, err)
		}
		for i, row := range got.organizations {
			if row != (snapshotJobOrganization{organizationID: ids[i], pending: 1}) {
				t.Fatal("disabled/late organization omitted or mixed")
			}
		}
		owned := slices.Clone(got.organizations)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if err := other.db.Table("integrity_jobs").Where("organization_id=101").Update("status", "failed").Error; err != nil {
			t.Fatal(err)
		}
		got.organizations[0].pending = 999
		again, err := poolless.snapshotJobInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again.organizations, owned) {
			t.Fatal("read drifted to independent committed writer or aliased owned result")
		}
		var one int
		if err := tx.Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
			t.Fatal("inventory closed caller transaction")
		}
		for _, limit := range []int{1, 100, 101} {
			limited, err := poolless.snapshotJobInventoryLimited(ctx, tx, limit)
			if limit == 101 {
				if err != nil || len(limited.organizations) != 101 {
					t.Fatal("exact organization limit rejected")
				}
			} else if !errors.Is(err, errSnapshotJobLimit) || limited.organizations != nil || limited.classification != snapshotJobUnverified {
				t.Fatal("late organization limit returned partial inventory")
			}
		}
		closeView()
		live := snapshotJobTestObserve(t, s, cfg, nil)
		if live.organizations[100].pending != 0 || live.organizations[100].failed != 1 {
			t.Fatal("new actual snapshot did not see committed change")
		}
		// There is no arbitrary total-Job cap: one organization can own more
		// jobs than the manifest's per-entry cap; only scalar counts cross SQL.
		if err := s.db.Exec(`WITH RECURSIVE many(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM many WHERE n<65537)
INSERT INTO integrity_jobs (id,organization_id,type,object_id,idempotency_key,status,available_at,created_at,updated_at)
SELECT n+2000,1,'integrity.retention.delete',1,'large-' || CAST(n AS TEXT),'completed',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM many`).Error; err != nil {
			t.Fatal("insert actual large job population", err)
		}
		many := snapshotJobTestObserve(t, s, cfg, nil)
		if many.organizations[0].completed != 65537 || many.organizations[0].pending != 1 {
			t.Fatal("large population was truncated or rejected")
		}
	})
}

func TestSnapshotJobInventoryBusyRecoveryAndHistoricalRetry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, samples := executionStart(t, tenant, plan, policy)
		first := mustClaim(t, q)
		firstAttempt := reserveTestAttempt(t, tenant, q, first, samples[0])
		retryOutcome := domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_RATE_LIMITED", HTTPStatus: 429, RetryAfterSeconds: 10}
		if err := q.CompleteWith(tenant.ctx, first, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, firstAttempt.ID, retryOutcome, 0)
		}); err != nil {
			t.Fatal(err)
		}
		// A normal retry really changes sample.job_id. UNCERTAIN recovery
		// below deliberately does not replay a possibly billed request.
		var current LogicalSampleRecord
		if err := s.db.Where("id=?", samples[0].ID).Take(&current).Error; err != nil {
			t.Fatal(err)
		}
		if current.JobID == nil || *current.JobID == first.Job.ID {
			t.Fatal("normal retry did not create a new pointer")
		}
		snapshotJobTestObserve(t, s, cfg, nil)
		if err := s.db.Model(&Job{}).Where("id=?", *current.JobID).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		old := mustClaim(t, q)
		attempt := reserveTestAttempt(t, tenant, q, old, samples[0])
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobBusy)
		if err := s.db.Model(&Job{}).Where("id=?", old.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobBusy)
		fresh := mustClaim(t, q)
		if fresh.Generation <= old.Generation {
			t.Fatal("actual queue did not reclaim expired lease")
		}
		if err := q.CompleteWith(tenant.ctx, fresh, func(tx *TenantTransaction) error { return tx.RecoverInterruptedSample(samples[0].ID) }); err != nil {
			t.Fatal(err)
		}
		got := snapshotJobTestObserve(t, s, cfg, nil)
		if got.classification != snapshotJobVerifiedCurrent || got.organizations[0].uncertain != 1 || got.organizations[0].completedAttempts != 1 {
			t.Fatal("actual uncertain recovery was not retained")
		}
		// Retry updates sample.job_id; the old attempt must retain old.job_id.
		current = LogicalSampleRecord{}
		if err := s.db.Where("id=?", samples[0].ID).Take(&current).Error; err != nil {
			t.Fatal(err)
		}
		if current.JobID == nil || *current.JobID == first.Job.ID {
			t.Fatal("current retry pointer reverted to a historical job")
		}
		var retained AttemptRecord
		if err := s.db.Where("id=?", attempt.ID).Take(&retained).Error; err != nil || retained.JobID != old.Job.ID {
			t.Fatal("history lost original attempt job")
		}
		// A dispatched row is still busy even if its Job was marked terminal.
		if err := s.db.Model(&AttemptRecord{}).Where("id=?", attempt.ID).Update("status", "DISPATCHED").Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobBusy)
	})
}

func TestSnapshotJobInventoryRealLegacyMigrationsPreserved(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		set, err := migrations.ForDialect(cfg.Driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), set[:17]); err != nil {
			t.Fatal(err)
		}
		org := derivedUpgradeLegacyRows(t, s)
		// These nullable identities and PLANNED default predate execution
		// bindings. They are inserted on the actual historical schema, then
		// upgraded without any repair of the original row identities.
		snapshotJobTestInsert(t, s, "integrity_sample_attempts", map[string]any{"id": int64(9), "organization_id": org, "logical_sample_id": int64(3), "attempt_no": 3, "request_snapshot": "{}", "request_hash": strings.Repeat("c", 64)})
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		for _, legacy := range []struct {
			id, object int64
			kind       JobType
		}{{21, 1, JobRunPlan}, {22, 3, JobSampleExecute}} {
			snapshotJobTestInsert(t, s, "integrity_jobs", map[string]any{"id": legacy.id, "organization_id": org, "type": string(legacy.kind), "object_id": legacy.object, "idempotency_key": fmt.Sprintf("legacy-%d", legacy.id), "status": "completed", "available_at": stamp, "created_at": stamp, "updated_at": stamp})
		}
		var before []map[string]any
		if err := s.db.Table("integrity_sample_attempts").Order("id").Find(&before).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotJobTestObserve(t, s, cfg, nil)
		want := snapshotJobOrganization{organizationID: org, completed: 2, completedAttempts: 2, plannedAttempts: 1, legacyJobs: 2, legacyAttempts: 3}
		if got.classification != snapshotJobLegacyIncomplete || len(got.organizations) != 1 || got.organizations[0] != want {
			t.Fatal("legal migrated history was rejected, omitted or promoted to current proof")
		}
		var after []map[string]any
		if err := s.db.Table("integrity_sample_attempts").Order("id").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("inventory rewrote original legacy execution identities")
		}
		if err := s.db.Table("integrity_jobs").Where("id=21").Update("status", "pending").Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
		if err := s.db.Table("integrity_jobs").Where("id=21").Update("status", "completed").Error; err != nil {
			t.Fatal(err)
		}
		// Provided-but-wrong identities never become a legacy compatibility
		// escape hatch, even though the schema's single-column FK permits it.
		if err := s.db.Table("integrity_sample_attempts").Where("id=4").Update("run_id", 6).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
	})
}

func TestSnapshotJobInventoryLateBusyCancelAndQueryFailures(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotJobTestOrganizations(t, s, 101)
		snapshotJobTestRetention(t, s, 101, 201, "running")
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobBusy)
		if err := s.db.Table("integrity_jobs").Where("id=201").Update("status", "completed").Error; err != nil {
			t.Fatal(err)
		}
		for _, cause := range []string{"cancel", "query"} {
			t.Run(cause, func(t *testing.T) {
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				work, cancel := context.WithCancel(ctx)
				defer cancel()
				observed := 0
				if err := tx.Callback().Query().After("gorm:query").Register("snapshot_job_late_fault", func(q *gorm.DB) {
					if rows, ok := q.Statement.Dest.(*[]int64); ok && q.Statement.Table == "organizations" && q.Error == nil {
						observed += len(*rows)
						if observed > 100 {
							if cause == "cancel" {
								cancel()
							} else {
								_ = q.AddError(errors.New("private-query-error-canary"))
							}
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				got, err := s.snapshotJobInventory(work, tx)
				if !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() || got.organizations != nil || got.classification != snapshotJobUnverified || observed != 101 {
					t.Fatal("late real-page cancellation/fault leaked partial candidate")
				}
			})
		}
	})
}

func TestSnapshotJobInventoryActualCorruptionNeverPartial(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, run := reportFixture(t, s)
		snapshotJobTestPrecheckPermission(t, tenant)
		var sample LogicalSampleRecord
		var attempt AttemptRecord
		var target TargetRecord
		if err := s.db.Where("run_id=?", run.ID).First(&sample).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("logical_sample_id=?", sample.ID).First(&attempt).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("id=?", run.TargetID).Take(&target).Error; err != nil {
			t.Fatal(err)
		}
		precheck, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: target.ID, TargetVersion: target.Version, SecretID: target.SecretID, SecretVersion: 1, RequestKey: "corruption-precheck", SnapshotJSON: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		snapshotJobTestOrganizations(t, s, 1) // Real other (disabled) tenant.
		snapshotJobTestObserve(t, s, cfg, nil)
		// First prove actual production constraints reject selected bad rows.
		for _, statement := range []string{"UPDATE integrity_jobs SET id=NULL", "UPDATE integrity_jobs SET attempt_count=-1", "UPDATE integrity_jobs SET status='UNKNOWN'", "UPDATE integrity_sample_attempts SET attempt_no=0", "UPDATE integrity_sample_attempts SET logical_sample_id=1"} {
			if err := s.db.Exec(statement).Error; err == nil {
				t.Fatal("production constraints unexpectedly accepted invalid fixture")
			}
		}
		// Replace only four tables in this test-owned database. No migration,
		// live data, production constraint or unrelated test schema is changed.
		tables := []string{"integrity_jobs", "integrity_sample_attempts", "integrity_logical_samples", "integrity_target_prechecks"}
		for i, table := range tables {
			original := fmt.Sprintf("snapshot_job_original_%d", i)
			for _, statement := range []string{"ALTER TABLE " + table + " RENAME TO " + original, "CREATE TABLE " + table + " AS SELECT * FROM " + original} {
				if err := s.db.Exec(statement).Error; err != nil {
					t.Fatal("prepare isolated offline corruption fixture", err)
				}
			}
		}
		t.Cleanup(func() {
			for i, table := range tables {
				for _, statement := range []string{"DROP TABLE " + table, fmt.Sprintf("ALTER TABLE snapshot_job_original_%d RENAME TO %s", i, table)} {
					if err := s.db.Exec(statement).Error; err != nil {
						t.Error("restore isolated original constrained table", err)
					}
				}
			}
		})
		reset := func() {
			t.Helper()
			for i, table := range tables {
				for _, statement := range []string{"DELETE FROM " + table, fmt.Sprintf("INSERT INTO %s SELECT * FROM snapshot_job_original_%d", table, i)} {
					if err := s.db.Exec(statement).Error; err != nil {
						t.Fatal("restore actual fixture rows", err)
					}
				}
			}
		}
		for _, tc := range []struct {
			name, table, field string
			id                 int64
			value              any
		}{
			{"job_null_id", "integrity_jobs", "id", attempt.JobID, nil},
			{"job_zero_id", "integrity_jobs", "id", attempt.JobID, 0},
			{"job_org_null", "integrity_jobs", "organization_id", attempt.JobID, nil},
			{"job_org_orphan", "integrity_jobs", "organization_id", attempt.JobID, 999},
			{"job_org_foreign", "integrity_jobs", "organization_id", attempt.JobID, 1},
			{"job_object_null", "integrity_jobs", "object_id", attempt.JobID, nil},
			{"job_object_orphan", "integrity_jobs", "object_id", attempt.JobID, 999},
			{"job_type_null", "integrity_jobs", "type", attempt.JobID, nil},
			{"job_type_alias", "integrity_jobs", "type", attempt.JobID, "sample.execute"},
			{"job_type_large", "integrity_jobs", "type", attempt.JobID, strings.Repeat("界", 350000)},
			{"job_status_null", "integrity_jobs", "status", attempt.JobID, nil},
			{"job_status_unknown", "integrity_jobs", "status", attempt.JobID, "complete"},
			{"job_status_large", "integrity_jobs", "status", attempt.JobID, strings.Repeat("x", 1<<20)},
			{"job_count_null", "integrity_jobs", "attempt_count", attempt.JobID, nil},
			{"job_count_negative", "integrity_jobs", "attempt_count", attempt.JobID, -1},
			{"job_count_generation_lost", "integrity_jobs", "attempt_count", attempt.JobID, 0},
			{"job_count_above_max", "integrity_jobs", "attempt_count", attempt.JobID, 100},
			{"job_max_null", "integrity_jobs", "max_attempts", attempt.JobID, nil},
			{"job_max_zero", "integrity_jobs", "max_attempts", attempt.JobID, 0},
			{"attempt_id_null", "integrity_sample_attempts", "id", attempt.ID, nil},
			{"attempt_org_null", "integrity_sample_attempts", "organization_id", attempt.ID, nil},
			{"attempt_org_foreign", "integrity_sample_attempts", "organization_id", attempt.ID, 1},
			{"attempt_sample_null", "integrity_sample_attempts", "logical_sample_id", attempt.ID, nil},
			{"attempt_sample_orphan", "integrity_sample_attempts", "logical_sample_id", attempt.ID, 1},
			{"attempt_run_zero", "integrity_sample_attempts", "run_id", attempt.ID, 0},
			{"attempt_run_orphan", "integrity_sample_attempts", "run_id", attempt.ID, 1},
			{"attempt_job_zero", "integrity_sample_attempts", "job_id", attempt.ID, 0},
			{"attempt_job_wrong_type", "integrity_sample_attempts", "job_id", attempt.ID, *precheck.JobID},
			{"attempt_job_missing_nonzero_generation", "integrity_sample_attempts", "job_id", attempt.ID, nil},
			{"attempt_no_null", "integrity_sample_attempts", "attempt_no", attempt.ID, nil},
			{"attempt_no_zero", "integrity_sample_attempts", "attempt_no", attempt.ID, 0},
			{"attempt_no_gt_sample", "integrity_sample_attempts", "attempt_no", attempt.ID, 4},
			{"attempt_generation_null", "integrity_sample_attempts", "lease_generation", attempt.ID, nil},
			{"attempt_generation_negative", "integrity_sample_attempts", "lease_generation", attempt.ID, -1},
			{"attempt_generation_future", "integrity_sample_attempts", "lease_generation", attempt.ID, 100},
			{"attempt_state_null", "integrity_sample_attempts", "status", attempt.ID, nil},
			{"attempt_state_alias", "integrity_sample_attempts", "status", attempt.ID, "completed"},
			{"attempt_state_large", "integrity_sample_attempts", "status", attempt.ID, strings.Repeat("x", 1<<20)},
			{"sample_count_null", "integrity_logical_samples", "attempt_count", sample.ID, nil},
			{"sample_job_wrong_type", "integrity_logical_samples", "job_id", sample.ID, *precheck.JobID},
			{"sample_run_orphan", "integrity_logical_samples", "run_id", sample.ID, 1},
			{"sample_probe_orphan", "integrity_logical_samples", "probe_instance_id", sample.ID, 1},
			{"sample_final_orphan", "integrity_logical_samples", "final_attempt_id", sample.ID, 1},
			{"precheck_job_orphan", "integrity_target_prechecks", "job_id", precheck.ID, 1},
			{"precheck_job_wrong_type", "integrity_target_prechecks", "job_id", precheck.ID, attempt.JobID},
			{"precheck_org_foreign", "integrity_target_prechecks", "organization_id", precheck.ID, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.db.Table(tc.table).Where("id=?", tc.id).Update(tc.field, tc.value).Error; err != nil {
					t.Fatal("write actual corruption", err)
				}
				snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
				reset()
			})
		}
		for _, statement := range []string{"INSERT INTO integrity_jobs SELECT * FROM integrity_jobs LIMIT 1", "INSERT INTO integrity_sample_attempts SELECT * FROM integrity_sample_attempts LIMIT 1"} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
			snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
			reset()
		}
		if cfg.Driver == "sqlite" {
			for _, statement := range []string{"UPDATE integrity_jobs SET id=1.5", "UPDATE integrity_jobs SET attempt_count=X'31'", "UPDATE integrity_sample_attempts SET lease_generation=1.5", "UPDATE integrity_sample_attempts SET attempt_no=X'31'", "UPDATE integrity_logical_samples SET attempt_count=1.5"} {
				if err := s.db.Exec(statement).Error; err != nil {
					t.Fatal(err)
				}
				snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
				reset()
			}
		}
		snapshotJobTestObserve(t, s, cfg, nil)
	})
}

func TestSnapshotJobInventoryCountAndRepresentationGuards(t *testing.T) {
	for _, tc := range []struct {
		row   snapshotJobCountRow
		valid bool
	}{
		{snapshotJobCountRow{}, true},
		{snapshotJobCountRow{Pending: math.MaxInt64, Total: math.MaxInt64, Legacy: math.MaxInt64}, true},
		{snapshotJobCountRow{Pending: math.MaxInt64, Completed: 1, Total: math.MaxInt64}, false},
		{snapshotJobCountRow{Uncertain: -1, Total: -1}, false},
		{snapshotJobCountRow{Pending: 2, Total: 1}, false},
		{snapshotJobCountRow{Total: 1}, false},
		{snapshotJobCountRow{Legacy: 1}, false},
		{snapshotJobCountRow{Legacy: -1}, false},
		{snapshotJobCountRow{Pending: 1, Running: 1, Completed: 1, Failed: 1, Cancelled: 1, Dispatched: 1, Uncertain: 1, Planned: 1, Total: 8, Legacy: 2}, true},
	} {
		if snapshotJobValidCounts(tc.row) != tc.valid {
			t.Fatal("count sum/sign/overflow/subset check")
		}
	}
	row := snapshotJobOrganization{organizationID: 123456789, pending: 987654321}
	value := snapshotJobInventory{organizations: []snapshotJobOrganization{row}, classification: snapshotJobLegacyIncomplete}
	for _, item := range []struct {
		input any
		want  string
	}{{value, "[private snapshot job inventory]"}, {&value, "[private snapshot job inventory]"}, {row, "[private snapshot job organization]"}, {&row, "[private snapshot job organization]"}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, item.input) != item.want {
				t.Fatal("private inventory leaked via formatting")
			}
		}
		if _, err := json.Marshal(item.input); err == nil {
			t.Fatal("private JSON serialization accepted")
		}
		if _, err := yaml.Marshal(item.input); err == nil {
			t.Fatal("private YAML serialization accepted")
		}
		output := snapshotInventoryLogText(t, item.input)
		if output != item.want {
			t.Fatal("private structured logging disclosure")
		}
	}
}

func TestSnapshotJobInventoryDuplicateOrganizationBoundary(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotJobTestOrganizations(t, s, 101)
		if err := s.db.Exec("INSERT INTO organizations SELECT * FROM organizations WHERE id=100").Error; err == nil {
			t.Fatal("normal schema accepted duplicate organization")
		}
		for _, statement := range []string{"ALTER TABLE organizations RENAME TO snapshot_job_org_original", "CREATE TABLE organizations AS SELECT * FROM snapshot_job_org_original"} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			for _, statement := range []string{"DROP TABLE organizations", "ALTER TABLE snapshot_job_org_original RENAME TO organizations"} {
				if err := s.db.Exec(statement).Error; err != nil {
					t.Error(err)
				}
			}
		})
		for _, statement := range []string{
			"INSERT INTO organizations SELECT * FROM organizations WHERE id=1",
			"INSERT INTO organizations SELECT * FROM organizations WHERE id=100",
			"INSERT INTO organizations SELECT * FROM organizations WHERE id=101",
			"UPDATE organizations SET id=NULL WHERE id=101",
			"UPDATE organizations SET id=0 WHERE id=101",
			"UPDATE organizations SET id=-1 WHERE id=101",
			"UPDATE organizations SET status=NULL WHERE id=101",
			"UPDATE organizations SET status='unknown' WHERE id=101",
		} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
			snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
			for _, reset := range []string{"DELETE FROM organizations", "INSERT INTO organizations SELECT * FROM snapshot_job_org_original"} {
				if err := s.db.Exec(reset).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := s.db.Exec("UPDATE organizations SET status=? WHERE id=101", strings.Repeat("x", 1<<20)).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
	})
}

func TestSnapshotJobInventoryRetentionBatchIdentityCannotUseLegacyBypass(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotJobTestOrganizations(t, s, 1)
		snapshotJobTestRetention(t, s, 1, 10, "completed")
		snapshotJobTestObserve(t, s, cfg, nil)
		for _, key := range []string{"response-retention:1", "response-retention:999", "response-retention:"} {
			if err := s.db.Table("integrity_jobs").Where("id=10").Update("idempotency_key", key).Error; err != nil {
				t.Fatal(err)
			}
			snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
		}
	})
}

func TestSnapshotJobInventoryMissingTablesDoesNotCreateThem(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		snapshotJobTestObserve(t, s, cfg, ErrUnavailable)
		if s.db.Migrator().HasTable("integrity_jobs") || s.db.Migrator().HasTable("organizations") {
			t.Fatal("inventory created schema")
		}
		requireMigrate(t, s)
		snapshotJobTestObserve(t, s, cfg, errSnapshotJobSource)
	})
}

func TestSnapshotJobInventoryTransactionGuards(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotJobTestOrganizations(t, s, 1)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		for _, db := range []*gorm.DB{nil, {}, {Config: &gorm.Config{}}, s.db, typedNil} {
			if got, err := s.snapshotJobInventory(ctx, db); !errors.Is(err, ErrConfiguration) || got.organizations != nil || got.classification != snapshotJobUnverified {
				t.Fatal("malformed/naked pool transaction accepted")
			}
		}
		for _, store := range []*Store{nil, {driver: "wrong"}} {
			if got, err := store.snapshotJobInventory(ctx, tx); !errors.Is(err, ErrConfiguration) || got.organizations != nil {
				t.Fatal("bad store/dialect accepted")
			}
		}
		for _, missing := range []context.Context{nil, context.Background()} {
			if got, err := s.snapshotJobInventory(missing, tx); !errors.Is(err, ErrConfiguration) || got.organizations != nil {
				t.Fatal("missing context/deadline accepted")
			}
		}
		for _, limit := range []int{-1, 0, backupmanifest.MaxOrganizations + 1} {
			if got, err := s.snapshotJobInventoryLimited(ctx, tx, limit); !errors.Is(err, ErrConfiguration) || got.organizations != nil {
				t.Fatal("private cap bypassed hard limit")
			}
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotJobInventory(cancelled, tx); !errors.Is(err, ErrUnavailable) || got.organizations != nil {
			t.Fatal("already cancelled context accepted")
		}
		if err := tx.Statement.ConnPool.(*sql.Tx).Rollback(); err != nil {
			t.Fatal(err)
		}
		if got, err := s.snapshotJobInventory(ctx, tx); !errors.Is(err, ErrUnavailable) || got.organizations != nil {
			t.Fatal("closed caller transaction accepted")
		}
		closeView()
		if cfg.Driver == "sqlite" {
			ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, nil, false)
			defer closeWeak()
			if got, err := s.snapshotJobInventory(ctx, weak); !errors.Is(err, ErrConfiguration) || got.organizations != nil {
				t.Fatal("SQLite missing query_only accepted")
			}
		} else {
			for _, options := range []sql.TxOptions{{ReadOnly: true, Isolation: sql.LevelReadCommitted}, {ReadOnly: false, Isolation: sql.LevelRepeatableRead}} {
				ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, &options, true)
				got, err := s.snapshotJobInventory(ctx, weak)
				closeWeak()
				if !errors.Is(err, ErrConfiguration) || got.organizations != nil {
					t.Fatal("weak PostgreSQL transaction accepted")
				}
			}
		}
	})
}
