package repository

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/migrations"
)

func TestResponseRetentionDeletionReasonBoundaries(t *testing.T) {
	now := int64(1000) * responseRetentionDayMicros
	p := ResponseRetentionPolicy{organizationID: 1, version: 1, days: 30, observedAtMicros: now, notBeforeMicros: now - 60*responseRetentionDayMicros}
	for _, test := range []struct {
		name    string
		change  func(*ResponseRetentionPolicy, *int64, *int64)
		want    string
		invalid bool
	}{
		{"retained", nil, "", false},
		{"organization_disabled", func(p *ResponseRetentionPolicy, _, _ *int64) { p.active = false }, "", false},
		{"expiry_equal", func(_ *ResponseRetentionPolicy, _, expiry *int64) { *expiry = now }, "sealed_expiry", false},
		{"day_equal", func(_ *ResponseRetentionPolicy, captured, _ *int64) { *captured = now - 30*responseRetentionDayMicros }, "day_window", false},
		{"cutoff_equal", func(p *ResponseRetentionPolicy, captured, _ *int64) { p.notBeforeMicros = *captured }, "policy_cutoff", false},
		{"zero", func(p *ResponseRetentionPolicy, _, _ *int64) { p.days = 0 }, "policy_zero", false},
		{"future_capture", func(_ *ResponseRetentionPolicy, captured, expiry *int64) { *captured = now + 1; *expiry = now + 2 }, "", true},
		{"bad_policy", func(p *ResponseRetentionPolicy, _, _ *int64) { p.days = 181 }, "", true},
		{"bad_expiry", func(_ *ResponseRetentionPolicy, captured, expiry *int64) { *expiry = *captured }, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := p
			captured, expiry := now-responseRetentionDayMicros, now+responseRetentionDayMicros
			if test.change != nil {
				test.change(&policy, &captured, &expiry)
			}
			actual, err := responseDeletionReason(policy, captured, expiry)
			if actual != test.want || (err != nil) != test.invalid {
				t.Fatalf("reason %q invalid %v", actual, err != nil)
			}
		})
	}
}

func responseCleanupFixture(t *testing.T, s *Store, derived bool) (*Tenant, *JobQueue, DisplaySelection) {
	t.Helper()
	return responseCleanupFixtureWithDisplayState(t, s, derived, DisplayCaptured)
}

func responseCleanupFixtureWithDisplayState(t *testing.T, s *Store, derived bool, displayState string) (*Tenant, *JobQueue, DisplaySelection) {
	t.Helper()
	var tenant *Tenant
	var run RunRecord
	var queue *JobQueue
	var sample LogicalSampleRecord
	var attempt AttemptRecord
	var lease JobLease
	if derived {
		tenant, run, queue, sample, attempt, lease = derivedExecutionFixture(t, s)
	} else {
		tenant, run, queue, sample, attempt, lease = legacyBodyFixture(t, s)
	}
	var body *AttemptBodyCapture
	if displayState == DisplayCaptured {
		body = derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
	} else {
		var capture *AttemptBodyCapture
		if err := queue.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
			var err error
			capture, err = tx.BindAttemptResponseCapture(sample.ID, attempt.ID, attempt.RequestHash)
			return err
		}); err != nil {
			t.Fatal("bind unavailable display capture", err)
		}
		display := capture.DisplayBinding()
		display.State, display.CapturedAtMicros, display.ExpiresAtMicros = displayState, 0, 0
		var err error
		body, err = capture.WithRecords(testEvidenceRecord(tenant, sample, attempt), display)
		if err != nil {
			t.Fatal("attach raw body with unavailable display fact", err)
		}
	}
	if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
		if derived {
			return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, successOutcome(), 0, derivedFixtureCandidates(run, sample, attempt, successOutcome()), body)
		}
		return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
	}); err != nil {
		t.Fatal("body settlement", err)
	}
	analysis, err := queue.Claim(tenant.ctx)
	if err != nil || analysis == nil {
		t.Fatal("claim analysis", err)
	}
	source, err := queue.LoadRunAnalysis(tenant.ctx, *analysis)
	if err != nil {
		t.Fatal("load analysis", err)
	}
	run, _ = tenant.GetRun(run.ID)
	samples, _ := tenant.ListExecutionSamples(run.ID)
	if err := queue.CompleteWith(tenant.ctx, *analysis, func(tx *TenantTransaction) error {
		return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
	}); err != nil {
		t.Fatal("publish", err)
	}
	readPermissions(t, tenant)
	if err := s.db.Exec("INSERT INTO permissions(code) VALUES ('evidence.body') ON CONFLICT(code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) SELECT organization_id,id,'evidence.body' FROM roles WHERE organization_id=? AND name='administrator'", tenant.orgID).Error; err != nil {
		t.Fatal(err)
	}
	return tenant, queue, DisplaySelection{RunID: run.ID, SampleID: sample.ID, AttemptID: attempt.ID, AnalysisRevision: 1}
}

func claimResponseCleanup(t *testing.T, tenant *Tenant, q *JobQueue) JobLease {
	t.Helper()
	if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
		t.Fatal("schedule cleanup", err)
	}
	lease, err := q.Claim(tenant.ctx)
	if err != nil || lease == nil || JobType(lease.Job.Type) != JobRetentionDelete || lease.Job.ObjectID == tenant.orgID {
		t.Fatal("claim actual cleanup batch", err)
	}
	return *lease
}

func assertCleanupRows(t *testing.T, s *Store, orgID int64, raw, display, items int64) {
	t.Helper()
	for _, check := range []struct {
		model any
		want  int64
	}{{&ResponseEvidenceRecord{}, raw}, {&DisplayEvidenceRecord{}, display}, {&evidenceDeletion{}, items}} {
		var count int64
		if err := s.db.Model(check.model).Where("organization_id=?", orgID).Count(&count).Error; err != nil || count != check.want {
			t.Fatalf("row count %T = %d want %d (%v)", check.model, count, check.want, err)
		}
	}
}

func TestResponseRetentionCleanupActualModesDeleteAndDoNotResurrect(t *testing.T) {
	for _, derived := range []bool{false, true} {
		t.Run(fmt.Sprint(derived), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, q, selection := responseCleanupFixture(t, s, derived)
				var beforeRun RunRecord
				var beforeResult RunResultRecord
				var beforeS1 []AttemptDerivedRecord
				var beforeAttempt AttemptRecord
				if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, selection.RunID).Take(&beforeRun).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Where("organization_id=? AND run_id=?", tenant.orgID, selection.RunID).Take(&beforeResult).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Where("organization_id=? AND run_id=?", tenant.orgID, selection.RunID).Find(&beforeS1).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, selection.AttemptID).Take(&beforeAttempt).Error; err != nil {
					t.Fatal(err)
				}
				var originalRaw ResponseEvidenceRecord
				var originalDisplay DisplayEvidenceRecord
				if err := s.db.First(&originalRaw).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.First(&originalDisplay).Error; err != nil {
					t.Fatal(err)
				}
				oldSource, err := tenant.PrepareEvidenceDisplay(selection)
				if err != nil {
					t.Fatal(err)
				}
				defer oldSource.Close()
				derivedFixtureRetention(t, tenant, 0)
				derivedFixtureRetention(t, tenant, 30)
				lease := claimResponseCleanup(t, tenant, q)
				if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
					t.Fatal("cleanup", err)
				}
				assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
				if _, err := tenant.CommitEvidenceDisplayRead(oldSource, displaySummaryFixture()); !errors.Is(err, ErrDisplaySource) {
					t.Fatal("old display source survived deletion", err)
				}
				source, err := tenant.PrepareEvidenceDisplay(selection)
				if err != nil {
					t.Fatal("prepare deleted", err)
				}
				defer source.Close()
				if source.Metadata().Status != DisplayReadDeleted {
					t.Fatal("deleted fact not explained", source.Metadata().Status)
				}
				permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture())
				if err != nil || permit == nil {
					t.Fatal("audited unavailable projection", err)
				}
				permit.Close()
				summary, err := tenant.ReadResponseRetentionSummary(selection.RunID)
				if err != nil || summary.AttemptCount != 1 || summary.RawDeletedCount != 1 || summary.DisplayDeletedCount != 1 || summary.DisplayRetainedCount != 0 || summary.LastDeletedAt == nil {
					t.Fatal("retention summary", summary, err)
				}
				var afterRun RunRecord
				var afterResult RunResultRecord
				var afterS1 []AttemptDerivedRecord
				var afterAttempt AttemptRecord
				s.db.Where("organization_id=? AND id=?", tenant.orgID, selection.RunID).Take(&afterRun)
				s.db.Where("organization_id=? AND run_id=?", tenant.orgID, selection.RunID).Take(&afterResult)
				s.db.Where("organization_id=? AND run_id=?", tenant.orgID, selection.RunID).Find(&afterS1)
				s.db.Where("organization_id=? AND id=?", tenant.orgID, selection.AttemptID).Take(&afterAttempt)
				if !reflect.DeepEqual(beforeRun, afterRun) || !reflect.DeepEqual(beforeResult, afterResult) || !reflect.DeepEqual(beforeS1, afterS1) || !reflect.DeepEqual(beforeAttempt, afterAttempt) {
					t.Fatal("cleanup changed immutable run/result/attempt/S1")
				}
				if err := s.db.Create(&originalRaw).Error; err == nil {
					t.Fatal("raw resurrection accepted")
				}
				if err := s.db.Create(&originalDisplay).Error; err == nil {
					t.Fatal("display resurrection accepted")
				}
				for range 3 {
					if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
						t.Fatal(err)
					}
				}
				if another, err := q.Claim(tenant.ctx); err != nil || another != nil {
					t.Fatal("same day recreated deletion job", err)
				}
				if _, err := tenant.VerifyAuditFull(); err != nil {
					t.Fatal("cleanup broke audit chain", err)
				}
			})
		})
	}
}

func TestResponseRetentionCleanupIndependentExpiryAndPermission(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, selection := responseCleanupFixture(t, s, false)
		now := time.Now().UTC().Truncate(time.Microsecond)
		captured := now.Add(-31 * 24 * time.Hour)
		expired := now.Add(-24 * time.Hour)
		if err := s.db.Model(&AttemptRecord{}).Where("organization_id=? AND id=?", tenant.orgID, selection.AttemptID).Update("started_at", captured.Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&ResponseEvidenceRecord{}).Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID).Updates(map[string]any{"created_at": captured, "expires_at": expired}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		lease := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 1, 1)
		if err := s.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "active").Error; err != nil {
			t.Fatal(err)
		}
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if source.Metadata().Status != DisplayReadAvailable {
			t.Fatal("raw expiry incorrectly deleted display")
		}
		summary, err := tenant.ReadResponseRetentionSummary(selection.RunID)
		if err != nil || summary.RawDeletedCount != 1 || summary.DisplayDeletedCount != 0 || summary.DisplayRetainedCount != 1 {
			t.Fatal(summary, err)
		}
		if err := s.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='evidence.read'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ReadResponseRetentionSummary(selection.RunID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("summary bypassed evidence.read", err)
		}
	})
}

func TestResponseRetentionCleanupFairDailyProgressAndFailedBatchRetry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, _ := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		other := Organization{ID: id, Name: "synthetic empty organization", Status: "disabled", Timezone: "UTC", FullResponseRetentionDays: 30, Version: 1, QuotaJSON: "{}", CreatedAt: now, UpdatedAt: now}
		if err := s.db.Create(&other).Error; err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
				t.Fatal(err)
			}
		}
		var schedules []responseRetentionSchedule
		if err := s.db.Order("organization_id").Find(&schedules).Error; err != nil || len(schedules) != 2 {
			t.Fatal("organization discovery", err)
		}
		for _, schedule := range schedules {
			if !schedule.LastCheckedAt.After(time.Unix(0, 0)) {
				t.Fatal("organization starved")
			}
			if schedule.OrganizationID == other.ID && schedule.ActiveBatchID != nil {
				t.Fatal("empty organization got false batch")
			}
		}
		lease, err := q.Claim(tenant.ctx)
		if err != nil || lease == nil || lease.Job.OrganizationID != tenant.orgID {
			t.Fatal("scoped pending batch", err)
		}
		if err := q.Fail(tenant.ctx, *lease, "RETENTION_FIXTURE_FAILED"); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
				t.Fatal(err)
			}
		}
		if again, err := q.Claim(tenant.ctx); err != nil || again != nil {
			t.Fatal("failed batch retried every maintenance tick", err)
		}
		assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
		// Only persisted scheduling state is advanced to a prior day. Object and
		// policy times are real; the next actual daily Job must revalidate them.
		if err := s.db.Model(&responseRetentionSchedule{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"next_due_at": now.Add(-time.Hour), "sweep_day": now.Unix()/86400 - 1}).Error; err != nil {
			t.Fatal(err)
		}
		retry := claimResponseCleanup(t, tenant, q)
		if retry.Job.ID == lease.Job.ID || retry.Job.ObjectID == lease.Job.ObjectID {
			t.Fatal("failed job history overwritten")
		}
		if err := q.CompleteWith(tenant.ctx, retry, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
		var failed responseRetentionBatch
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ObjectID).Take(&failed).Error; err != nil || failed.State != "planned" || failed.ReceiptHash != "" {
			t.Fatal("failed batch falsely acquired receipt", err)
		}
	})
}

func TestResponseRetentionCleanupFailedFirstRunDoesNotStarveOrganization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		bad, q, samples := executionStart(t, tenant, plan, policy)
		finish := func(sample LogicalSampleRecord) {
			t.Helper()
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil || lease.Job.ObjectID != sample.ID {
				t.Fatal("claim sample", err)
			}
			attempt := reserveTestAttempt(t, tenant, q, *lease, sample)
			body := derivedFixtureBody(t, tenant, q, *lease, sample, attempt)
			if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
			}); err != nil {
				t.Fatal(err)
			}
			analysis, err := q.Claim(tenant.ctx)
			if err != nil || analysis == nil || JobType(analysis.Job.Type) != JobRunAnalyze {
				t.Fatal("claim analysis", err)
			}
			if err := q.Fail(tenant.ctx, *analysis, "RETENTION_FIXTURE_ANALYSIS_UNUSED"); err != nil {
				t.Fatal(err)
			}
		}
		finish(samples[0])
		good, err := tenant.CreateRun(plan, policy, "retention-second-run")
		if err != nil {
			t.Fatal("create later healthy run", err)
		}
		start, err := q.Claim(tenant.ctx)
		if err != nil || start == nil || start.Job.ObjectID != good.ID {
			t.Fatal("claim later plan", err)
		}
		if err := q.CompleteWith(tenant.ctx, *start, func(tx *TenantTransaction) error { return tx.StartRun(good.ID) }); err != nil {
			t.Fatal(err)
		}
		goodSamples, err := tenant.ListExecutionSamples(good.ID)
		if err != nil || len(goodSamples) != 1 {
			t.Fatal("later samples", err)
		}
		finish(goodSamples[0])
		// IDs are CSPRNG values, not creation-order counters. Poison the lower
		// actual ID because the persistent sweep is explicitly ordered by ID.
		if bad.ID > good.ID {
			bad, good = good, bad
		}
		// Preserve the SQL row shape while making the first Run's actual capture
		// contradict its Attempt receipt. Cleanup must fail closed for this Run.
		if err := s.db.Model(&ResponseEvidenceRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, bad.ID).Update("created_at", time.Now().UTC().Add(-time.Hour)).Error; err != nil {
			t.Fatal(err)
		}
		derivedFixtureRetention(t, tenant, 0)
		failed := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, failed, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err == nil {
			t.Fatal("malformed first Run cleanup succeeded")
		}
		if err := q.Fail(tenant.ctx, failed, "RETENTION_SOURCE_INVALID"); err != nil {
			t.Fatal(err)
		}
		if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
			t.Fatal("advance failed Run", err)
		}
		later := claimResponseCleanup(t, tenant, q)
		var laterBatch responseRetentionBatch
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, later.Job.ObjectID).Take(&laterBatch).Error; err != nil || laterBatch.RunID != good.ID {
			t.Fatal("healthy later Run starved behind failed first Run", err)
		}
		if err := q.CompleteWith(tenant.ctx, later, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal("healthy later Run cleanup", err)
		}
		assertCleanupRows(t, s, tenant.orgID, 1, 1, 2)
		for range 3 {
			if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
				t.Fatal(err)
			}
		}
		if lease, err := q.Claim(tenant.ctx); err != nil || lease != nil {
			t.Fatal("failed first Run retried within same day", err)
		}
		// Advancing only durable sweep metadata lets the next real daily Job
		// reattempt the still-invalid first Run instead of permanently skipping it.
		now := time.Now().UTC()
		if err := s.db.Model(&responseRetentionSchedule{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"next_due_at": now.Add(-time.Hour), "sweep_day": now.Unix()/86400 - 1}).Error; err != nil {
			t.Fatal(err)
		}
		nextDay := claimResponseCleanup(t, tenant, q)
		var nextBatch responseRetentionBatch
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, nextDay.Job.ObjectID).Take(&nextBatch).Error; err != nil || nextBatch.RunID != bad.ID || nextBatch.ID == failed.Job.ObjectID {
			t.Fatal("failed first Run was permanently skipped", err)
		}
		var old Job
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, failed.Job.ID).Take(&old).Error; err != nil || old.Status != "failed" {
			t.Fatal("failed Job history overwritten", err)
		}
	})
}

func TestResponseRetentionCleanupLegacyOrgJobAndUnfencedDenied(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, selection := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		if err := tenant.InTransaction(func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err == nil {
			t.Fatal("unfenced deletion succeeded")
		}
		_, err := tenant.Enqueue(JobSpec{Type: JobRetentionDelete, ObjectID: tenant.orgID, IdempotencyKey: "legacy-queue-only"})
		if err != nil {
			t.Fatal(err)
		}
		lease, err := q.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err == nil {
			t.Fatal("old org-only job deleted bodies")
		}
		assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
		if err := q.Complete(tenant.ctx, *lease); err != nil {
			t.Fatal("old queue-only job no longer completes", err)
		}
		actual := claimResponseCleanup(t, tenant, q)
		stale := actual
		stale.Generation++
		if err := q.CompleteWith(tenant.ctx, stale, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("stale lease", err)
		}
		if err := q.CompleteWith(tenant.ctx, actual, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
		if _, err := tenant.ReadResponseRetentionSummary(selection.RunID); err != nil {
			t.Fatal(err)
		}
	})
}

func TestResponseRetentionCleanupMigration20RollbackAndHistory(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		list, err := migrations.ForDialect(cfg.Driver)
		if err != nil || len(list) < 20 {
			t.Fatal("migration20 absent", err)
		}
		list = list[:20]
		if err := s.migrate(t.Context(), list[:19]); err != nil {
			t.Fatal(err)
		}
		org := derivedUpgradeLegacyRows(t, s)
		var beforeRaw []ResponseEvidenceRecord
		var beforeDisplay []DisplayEvidenceRecord
		s.db.Where("organization_id=?", org).Find(&beforeRaw)
		s.db.Where("organization_id=?", org).Find(&beforeDisplay)
		broken := append([]migrations.Migration(nil), list...)
		broken[19].SQL += "\nSELECT * FROM retention_migration_forced_missing_table;"
		if err := s.migrate(t.Context(), broken); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("broken migration committed", err)
		}
		for _, table := range []string{"integrity_response_retention_batches", "integrity_response_retention_schedule", "integrity_evidence_deletions"} {
			if s.db.Migrator().HasTable(table) {
				t.Fatal("failed migration left table", table)
			}
		}
		var ledger int64
		if err := s.db.Table("schema_migrations").Count(&ledger).Error; err != nil || ledger != 19 {
			t.Fatal("migration changed ledger", err)
		}
		if err := s.migrate(t.Context(), list); err != nil {
			t.Fatal("migration20 retry", err)
		}
		var afterRaw []ResponseEvidenceRecord
		var afterDisplay []DisplayEvidenceRecord
		s.db.Where("organization_id=?", org).Find(&afterRaw)
		s.db.Where("organization_id=?", org).Find(&afterDisplay)
		if !reflect.DeepEqual(beforeRaw, afterRaw) || !reflect.DeepEqual(beforeDisplay, afterDisplay) {
			t.Fatal("migration rewrote historical bodies")
		}
		var items int64
		if err := s.db.Model(&evidenceDeletion{}).Count(&items).Error; err != nil || items != 0 {
			t.Fatal("migration invented deletion history", err)
		}
	})
}
