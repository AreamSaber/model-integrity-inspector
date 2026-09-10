package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Test-only bridge keeps real generator/MAC/worker dependencies out of the
// production repository import graph. The SQL side still uses actual writers.
func BackupDrainExecutionActualTLSBridge(t *testing.T, compile func(int64, TargetState) domain.ExecutionPlan, wire func(context.Context, domain.ExecutionPlan) (domain.RequestSnapshot, func() error), prepare func(context.Context, *BackupExecutionSource) (*AttemptDerivedCandidates, error), verify func(context.Context, ExecutionReconciliationData, DerivedRecord)) {
	t.Helper()
	for _, mode := range []string{"pending", "expired"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, target, _, policy := executionFixture(t, s, 1)
				// Route the owned TLS fixture through the same public test hostname
				// used by safehttp's certificate-verifying integration tests.
				target.Target.Endpoint = "https://upstream.example.com/v1"
				if err := s.db.Model(&TargetRecord{}).Where("id=?", target.Target.ID).UpdateColumn("endpoint", target.Target.Endpoint).Error; err != nil {
					t.Fatal(err)
				}
				plan := compile(tenant.orgID, target)
				run, err := tenant.CreateRun(plan, policy, "backup-real-signed-run")
				if err != nil {
					t.Fatal("create real signed Run", err)
				}
				queue, err := s.OpenJobQueue(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = queue.Close(context.Background()) })
				start := mustClaim(t, queue)
				if err := queue.CompleteWith(tenant.ctx, start, func(tx *TenantTransaction) error { return tx.StartRunWithDerivedSource(run.ID) }); err != nil {
					t.Fatal(err)
				}
				samples, err := tenant.ListExecutionSamples(run.ID)
				if err != nil || len(samples) != 1 {
					t.Fatal("single real sample", err)
				}
				job := mustClaim(t, queue)
				snapshot, send := wire(tenant.ctx, plan)
				if err := queue.WithLease(tenant.ctx, job, func(tx *TenantTransaction) error { _, e := tx.ReserveAttempt(samples[0].ID, snapshot); return e }); err != nil {
					t.Fatal("reserve actual dispatch", err)
				}
				if err := send(); err != nil {
					t.Fatal("actual owned TLS request", err)
				}
				if mode == "pending" {
					if err := queue.Retry(tenant.ctx, job, "JOB_TEST_PROCESS_LOSS", time.Hour); err != nil {
						t.Fatal(err)
					}
				} else if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).UpdateColumn("lease_until", time.Unix(1, 0).UTC()).Error; err != nil {
					t.Fatal(err)
				}
				freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
				candidate, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil || source == nil {
					t.Fatal("real protected source", err)
				}
				if err := s.db.Model(&TargetRecord{}).Where("id=?", run.TargetID).UpdateColumn("status", "disabled").Error; err != nil {
					t.Fatal(err)
				}
				before := reconciliationAtomicRows(t, s)
				prepared, err := prepare(tenant.ctx, source)
				if err != nil || prepared == nil || len(prepared.Items) != 1 {
					t.Fatal("real narrow MAC preparer", err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("preparer changed SQL")
				}
				for _, fault := range []string{"missing", "scope", "outcome", "record"} {
					var bad *AttemptDerivedCandidates
					if fault != "missing" {
						// Copy the explicit public scope/outcome values. The malformed
						// record test replaces its MAC slice, never edits the original.
						copyValue := *prepared
						copyValue.Items = append([]AttemptDerivedCandidate(nil), prepared.Items...)
						bad = &copyValue
						switch fault {
						case "scope":
							bad.Scope.AttemptID++
						case "outcome":
							bad.Items[0].Validity = "NOT_APPLICABLE"
						case "record":
							bad.Items[0].Record.MAC = []byte{1}
						}
					}
					if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, bad); err == nil || got != "" {
						t.Fatal("invalid internal candidate accepted", fault, err)
					}
					if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
						t.Fatal("rejected candidate changed facts", fault)
					}
				}
				if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, prepared); err != nil || got != ReconciliationApplied {
					t.Fatal("actual signed source drain", got, err)
				}
				var record AttemptDerivedRecord
				if err := s.db.Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Take(&record).Error; err != nil {
					t.Fatal(err)
				}
				var data ExecutionReconciliationData
				data.Plan = plan
				if err := s.db.First(&data.Job, job.Job.ID).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.First(&data.Run, run.ID).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.First(&data.Sample, samples[0].ID).Error; err != nil {
					t.Fatal(err)
				}
				data.Attempt = &AttemptRecord{}
				if err := s.db.First(data.Attempt, prepared.Scope.AttemptID).Error; err != nil {
					t.Fatal(err)
				}
				if data.Attempt.Status != "UNCERTAIN" || data.Attempt.DerivedReceipt != DerivedRecovered || data.Run.RequestCount != 1 || data.Run.ReservedTokens != 0 || data.Run.ReservedCostMicros != 0 {
					t.Fatal("real intent/accounting not once")
				}
				verify(tenant.ctx, data, DerivedRecord{Version: record.Version, KeyVersion: record.KeyVersion, Payload: record.Payload, MAC: record.MAC})
				for table, want := range map[string]int64{"integrity_attempt_derived": 1, "integrity_response_evidence": 0, "integrity_display_evidence": 0} {
					var count int64
					if err := s.db.Table(table).Count(&count).Error; err != nil || count != want {
						t.Fatal("unexpected S1/S2 record", table, err)
					}
				}
				if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, prepared); !errors.Is(err, ErrBackupDrainStale) || got != "" {
					t.Fatal("source replay", got, err)
				}
				if err := queue.CompleteWith(tenant.ctx, job, nil); !errors.Is(err, ErrJobLeaseLost) {
					t.Fatal("old request lease regained authority", err)
				}
				if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal("actual dual-chain verification", err)
				}
			})
		})
	}
}
