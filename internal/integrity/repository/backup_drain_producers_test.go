package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func backupDrainRealProducer(t *testing.T, s *Store, kind JobType) (*Tenant, *JobQueue, JobLease) {
	t.Helper()
	switch kind {
	case JobRunPlan:
		tenant, _, plan, policy := executionFixture(t, s, 1)
		if _, err := tenant.CreateRun(plan, policy, "backup-drain-plan"); err != nil {
			t.Fatal(err)
		}
		q, err := s.OpenJobQueue(tenant.ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = q.Close(context.Background()) })
		return tenant, q, mustClaim(t, q)
	case JobSampleExecute:
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, _ := executionStart(t, tenant, plan, policy)
		return tenant, q, mustClaim(t, q)
	case JobRunAnalyze:
		tenant, q, _, _, job := analysisReadyFixture(t, s, 1)
		return tenant, q, job
	case JobReportGenerate:
		tenant, q, run := reportFixture(t, s)
		if _, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "backup-drain-report"}); err != nil {
			t.Fatal(err)
		}
		return tenant, q, mustClaim(t, q)
	case JobTargetPrecheck:
		tenant, _, _, q, job := precheckFixture(t, s)
		return tenant, q, job
	case JobRetentionDelete:
		tenant, q, _ := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		return tenant, q, claimResponseCleanup(t, tenant, q)
	default:
		t.Fatal("unsupported test producer")
		return nil, nil, JobLease{}
	}
}

func backupDrainAssertSafeProducer(t *testing.T, kind JobType) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, job := backupDrainRealProducer(t, s, kind)
		expireJob(t, s, job.Job)
		auth := backupDrainTestAuthority(t, s, tenant.ctx)
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		before := backupDrainDomainRows(t, s)
		source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source == nil || source.Kind() != BackupDrainPauseSafe || source.job.ID != job.Job.ID || !observation.ExpiredJobPresent || !observation.CandidatePresent {
			t.Fatal("actual producer not safely classified", source, observation, err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("safe producer pause", result, err)
		}
		if after := backupDrainDomainRows(t, s); !reflect.DeepEqual(before, after) {
			t.Fatal("pause mutated domain rows")
		}
		next, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || next != nil || observation.RunningJobPresent || observation.UnsettledAttemptPresent || observation.CandidatePresent {
			t.Fatal("paused pending was reselected as actionable work", next, observation, err)
		}
		var events []audit.Event
		if err := s.db.Where("action='system.backup.drain.pause_running'").Find(&events).Error; err != nil || len(events) != 1 || events[0].ActorID == nil || *events[0].ActorID != auth.UserID || audit.Verify(events[0], s.auditSigner) != nil {
			t.Fatal("real current administrator audit missing", err)
		}
	})
}

// Exact database row observations in tests only: fixed tables and raw values
// never leave this fixture; assertions report no body/SQL or secret content.
func backupDrainDomainRows(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	rows := map[string][]map[string]any{}
	for _, table := range []string{"integrity_runs", "integrity_logical_samples", "integrity_sample_attempts", "integrity_attempt_derived", "integrity_target_prechecks", "integrity_reports", "integrity_run_results", "integrity_response_retention_batches", "integrity_evidence_deletions", "integrity_outbox"} {
		var values []map[string]any
		// All identifiers are fixed in this test-only literal table list.
		if err := s.db.Table(table).Find(&values).Error; err != nil {
			t.Fatal("domain observation", err)
		}
		rows[table] = values
	}
	return rows
}

func TestBackupDrainSafePlanProducer(t *testing.T) { backupDrainAssertSafeProducer(t, JobRunPlan) }
func TestBackupDrainSafeSampleProducer(t *testing.T) {
	backupDrainAssertSafeProducer(t, JobSampleExecute)
}
func TestBackupDrainSafeAnalyzeProducer(t *testing.T) {
	backupDrainAssertSafeProducer(t, JobRunAnalyze)
}
func TestBackupDrainSafeReportProducer(t *testing.T) {
	backupDrainAssertSafeProducer(t, JobReportGenerate)
}
func TestBackupDrainSafePrecheckProducer(t *testing.T) {
	backupDrainAssertSafeProducer(t, JobTargetPrecheck)
}
func TestBackupDrainSafeRetentionProducer(t *testing.T) {
	backupDrainAssertSafeProducer(t, JobRetentionDelete)
}

func backupDrainAssertBlocked(t *testing.T, freeze *MaintenanceLease, ctx context.Context, want BackupDrainKind) *BackupDrainSource {
	t.Helper()
	source, observation, err := freeze.LoadBackupDrainCandidate(ctx)
	if err != nil || source == nil || source.Kind() != want || !observation.CandidatePresent {
		t.Fatal("blocker omitted/misclassified", source, observation, err)
	}
	before := backupDrainDomainRows(t, freeze.store)
	var jobBefore Job
	if err := freeze.store.db.First(&jobBefore, source.job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if result, err := freeze.PauseBackupDrainCandidate(ctx, source); !errors.Is(err, ErrBackupDrainUnsupported) || result != (BackupDrainPauseResult{}) {
		t.Fatal("blocked kind acquired pause authority", result, err)
	}
	var jobAfter Job
	if err := freeze.store.db.First(&jobAfter, source.job.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(jobBefore, jobAfter) || !reflect.DeepEqual(before, backupDrainDomainRows(t, freeze.store)) {
		t.Fatal("blocked candidate mutated original facts")
	}
	return source
}
