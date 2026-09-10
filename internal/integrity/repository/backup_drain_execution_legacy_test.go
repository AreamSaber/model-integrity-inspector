package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestBackupDrainExecutionOldUnboundIntentNeverInventsS1(t *testing.T) {
	for _, field := range []string{"job_id", "run_id", "lease_generation"} {
		t.Run(field, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, freeze, _, _, _, _ := backupDrainExecutionFixture(t, s, "failed", true)
				var value any
				if field == "lease_generation" {
					value = 0
				}
				if err := s.db.Model(&AttemptRecord{}).Where("status='DISPATCHED'").UpdateColumn(field, value).Error; err != nil {
					t.Fatal(err)
				}
				before := reconciliationAtomicRows(t, s)
				candidate, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
				// A NULL Job cannot be routed to any execution candidate. The
				// stage-one global observer already rejects that orphan intent;
				// it must not invent a Job association so this loader can run.
				if field == "job_id" && errors.Is(err, ErrBackupDrainSource) && candidate == nil {
					if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
						t.Fatal("orphan intent modified")
					}
					return
				}
				if err != nil || candidate == nil {
					t.Fatal("old intent must remain observed", err)
				}
				if source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate); source != nil || !errors.Is(err, ErrBackupDrainUnsupported) {
					t.Fatal("old unbound intent accepted", err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("old intent modified")
				}
			})
		})
	}
}

func TestBackupDrainExecutionPlanCounterZeroCannotHideIntent(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, _, sampleJob, run, _ := backupDrainExecutionFixture(t, s, "pending", true)
		if err := s.db.Model(&Job{}).Where("id=?", sampleJob.Job.ID).Updates(map[string]any{"status": "completed", "completed_at": time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&Job{}).Where("organization_id=? AND type=?", tenant.orgID, string(JobRunPlan)).Updates(map[string]any{"status": "failed", "last_error_code": "JOB_TEST_ORIGINAL"}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&RunRecord{}).Where("id=?", run.ID).Updates(map[string]any{"status": "QUEUED", "started_at": nil, "request_count": 0, "reserved_tokens": 0, "reserved_cost_micros": 0}).Error; err != nil {
			t.Fatal(err)
		}
		candidate, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || candidate == nil || candidate.job.Type != string(JobRunPlan) {
			t.Fatal("plan candidate", err)
		}
		before := reconciliationAtomicRows(t, s)
		if source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate); source != nil || !errors.Is(err, ErrBackupDrainUnsupported) {
			t.Fatal("zero counters hid physical intent", err)
		}
		if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
			t.Fatal("unsupported plan projected")
		}
	})
}

func TestBackupDrainExecutionLegacyUnicodeAndProbeLocalOrdinal(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		plan.Probes[0].Samples[0].Request.Messages[0].Content = "中文 é 🦉 <tag> & \u2028 保留原始 Unicode"
		second := plan.Probes[0]
		second.Samples = append([]domain.SamplePlan(nil), second.Samples...)
		second.TemplateID = "legacy-second-probe"
		second.Samples[0].PairID = "pair-second"
		plan.Probes = append(plan.Probes, second)
		_, queue, samples := executionStart(t, tenant, plan, policy)
		for range samples {
			job := mustClaim(t, queue)
			if err := queue.Fail(tenant.ctx, job, "JOB_TEST_ORIGINAL"); err != nil {
				t.Fatal(err)
			}
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		for range samples {
			candidate, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
			if err != nil || candidate == nil {
				t.Fatal(err)
			}
			source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
			if err != nil || source == nil {
				t.Fatal("actual legacy original encoding rejected", err)
			}
			if source.data.Sample.Ordinal != 0 {
				t.Fatal("legacy ordinal normalized")
			}
			if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); err != nil || got != ReconciliationApplied {
				t.Fatal("legacy projection", got, err)
			}
		}
	})
}

func TestBackupDrainExecutionPayloadBoundBeforeReadAndBindingDrift(t *testing.T) {
	for _, mode := range []string{"run", "sample", "attempt", "aggregate", "changed_original"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, freeze, candidate, _, run, samples := backupDrainExecutionFixture(t, s, "pending", true)
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "changed_original" {
					if err := s.db.Model(&RunRecord{}).Where("id=?", run.ID).UpdateColumn("config_snapshot", source.data.Run.ConfigSnapshot+" ").Error; err != nil {
						t.Fatal(err)
					}
					before := reconciliationAtomicRows(t, s)
					if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); !errors.Is(err, ErrBackupDrainStale) || got != "" {
						t.Fatal("changed original binding", got, err)
					}
					if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
						t.Fatal("stale original wrote")
					}
					return
				}
				updates := map[string]string{}
				switch mode {
				case "run":
					updates["run"] = strings.Repeat(" ", 8<<20+1)
				case "sample":
					updates["sample"] = strings.Repeat(" ", 2<<20+1)
				case "attempt":
					updates["attempt"] = strings.Repeat(" ", 2<<20+1)
				case "aggregate":
					updates["run"] = strings.Repeat(" ", 7<<20)
					updates["sample"] = strings.Repeat(" ", 2<<20)
				}
				for key, value := range updates {
					var err error
					switch key {
					case "run":
						err = s.db.Model(&RunRecord{}).Where("id=?", run.ID).UpdateColumn("config_snapshot", value).Error
					case "sample":
						err = s.db.Model(&LogicalSampleRecord{}).Where("id=?", samples[0].ID).UpdateColumn("request_plan", value).Error
					case "attempt":
						err = s.db.Model(&AttemptRecord{}).Where("logical_sample_id=?", samples[0].ID).UpdateColumn("request_snapshot", value).Error
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				read := false
				name := "backup_execution_body_bound"
				if err := s.db.Callback().Query().Before("gorm:query").Register(name, func(db *gorm.DB) {
					switch db.Statement.Dest.(type) {
					case *RunRecord, *LogicalSampleRecord, *[]AttemptRecord:
						read = true
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove(name) }()
				if source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate); source != nil || !errors.Is(err, ErrBackupDrainUnsupported) || read {
					t.Fatal("payload not bounded before native read", read, err)
				}
			})
		})
	}
}
