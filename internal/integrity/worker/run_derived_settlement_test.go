package worker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func verifySettledDerivedAttempt(t *testing.T, f runFixture, p derivedPendingFixture, status, validity, code string) {
	t.Helper()
	sample, err := p.tenant.GetExecutionSampleForWorker(p.lease.Job.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := p.tenant.ListAttempts(sample.ID)
	if err != nil || len(attempts) != 1 {
		t.Fatal("settled attempt unavailable")
	}
	a := attempts[0]
	actualCode := ""
	if a.ErrorCode != nil {
		actualCode = *a.ErrorCode
	}
	if a.Status != status || a.Validity != validity || actualCode != code {
		t.Fatal("wrong actual final outcome", a.Status, a.Validity, actualCode)
	}
	plan, err := p.tenant.GetExecutionPlan(p.run.ID)
	if err != nil {
		t.Fatal(err)
	}
	run := features.RunBinding{OrganizationID: f.orgID, ID: p.run.ID, Plan: plan}
	row := features.SampleBinding{OrganizationID: f.orgID, RunID: p.run.ID, ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: sample.Ordinal, ExecutionOrdinal: sample.ExecutionOrdinal}
	if json.Unmarshal([]byte(sample.RequestPlan), &row.RequestPlan) != nil {
		t.Fatal("decode actual sample plan")
	}
	if sample.PairID != nil {
		row.PairID = *sample.PairID
	}
	attempt := features.AttemptBinding{OrganizationID: f.orgID, RunID: p.run.ID, SampleID: sample.ID, ID: a.ID, JobID: a.JobID, Number: a.AttemptNo, Status: a.Status, Validity: a.Validity, ErrorCode: actualCode, RequestHash: a.RequestHash}
	if json.Unmarshal([]byte(a.RequestSnapshot), &attempt.Snapshot) != nil {
		t.Fatal("decode actual dispatch snapshot")
	}
	var record features.DerivedRecord
	if err := f.db.QueryRowContext(f.ctx, "SELECT version,key_version,payload,mac FROM integrity_attempt_derived WHERE organization_id=$1 AND attempt_id=$2", f.orgID, a.ID).Scan(&record.Version, &record.KeyVersion, &record.Payload, &record.MAC); err != nil {
		t.Fatal("read actual S1")
	}
	if err := p.builder.VerifyDerivedRecord(f.ctx, run, row, attempt, record, p.verifier); err != nil {
		t.Fatal("selected S1 does not authenticate the actual final outcome", err)
	}
	if _, err := p.tenant.VerifyAuditFull(); err != nil {
		t.Fatal("verify final outcome audit", err)
	}
}

func TestDerivedWorkerActualResponseFinalOverrideSelectsAuthenticatedCandidate(t *testing.T) {
	for _, mode := range []string{"cancel", "stale", "budget", "stale_budget", "cancel_stale_budget", "job_cancel"} {
		t.Run(mode, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, 0)
				want := ""
				if strings.Contains(mode, "stale") || mode == "stale" {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_targets SET version=version+1 WHERE organization_id=$1 AND id=$2", f.orgID, p.run.TargetID); err != nil {
						t.Fatal("change actual target version")
					}
					want = "MI_EXECUTION_TARGET_STALE"
				}
				if strings.Contains(mode, "budget") {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_runs SET deadline_at=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, p.run.ID); err != nil {
						t.Fatal("expire actual execution deadline")
					}
					want = "MI_EXECUTION_BUDGET_EXCEEDED"
				}
				if strings.HasPrefix(mode, "cancel") {
					run, err := p.tenant.GetRun(p.run.ID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := p.tenant.CancelRun(run.ID, run.Version); err != nil {
						t.Fatal("cancel actual run after response", err)
					}
					want = "MI_EXECUTION_CANCELLED"
				}
				if mode == "job_cancel" {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET cancel_requested_at=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC(), f.orgID, p.lease.Job.ID); err != nil {
						t.Fatal("cancel current execution job")
					}
					want = "MI_EXECUTION_CANCELLED"
				}
				rejectDerivedBodyInserts(t, f)
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); err != nil {
					t.Fatal("actual final override completion", err)
				}
				derivedCounts(t, f, p.run.ID, 1, 0)
				verifySettledDerivedAttempt(t, f, p, "COMPLETED", "NOT_APPLICABLE", want)
			})
		})
	}
}

func TestDerivedWorkerActualS1FailureRollsBackAttemptBodyAndAudit(t *testing.T) {
	for _, fault := range []string{"derived_insert", "audit_insert", "lease_owner"} {
		t.Run(fault, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, 30)
				if fault == "lease_owner" {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner='replacement-owner' WHERE organization_id=$1 AND id=$2", f.orgID, p.lease.Job.ID); err != nil {
						t.Fatal("replace actual lease")
					}
				} else {
					statement := "ALTER TABLE integrity_attempt_derived ADD CONSTRAINT worker_derived_failure CHECK (false) NOT VALID"
					if fault == "audit_insert" {
						statement = "ALTER TABLE integrity_audit_logs ADD CONSTRAINT worker_derived_failure CHECK (action <> 'run.attempt.finish') NOT VALID"
					}
					if strings.HasSuffix(t.Name(), "/sqlite") {
						statement = "CREATE TRIGGER worker_derived_failure BEFORE INSERT ON integrity_attempt_derived BEGIN SELECT RAISE(ABORT,'synthetic S1 failure'); END"
						if fault == "audit_insert" {
							statement = "CREATE TRIGGER worker_derived_failure BEFORE INSERT ON integrity_audit_logs WHEN NEW.action='run.attempt.finish' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"
						}
					}
					if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
						t.Fatal("install real completion failure")
					}
				}
				err := p.queue.CompleteWith(f.ctx, p.lease, p.completion)
				if err == nil {
					t.Fatal("failed completion committed")
				}
				if fault == "lease_owner" && !errors.Is(err, repository.ErrJobLeaseLost) {
					t.Fatal("wrong lost-lease classification", err)
				}
				derivedCounts(t, f, p.run.ID, 0, 0)
				attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
				if err != nil || len(attempts) != 1 || attempts[0].Status != "DISPATCHED" || attempts[0].DerivedReceipt != repository.DerivedPending || attempts[0].FinishedAt != nil {
					t.Fatal("failed completion changed attempt receipt")
				}
				run, err := p.tenant.GetRun(p.run.ID)
				if err != nil || run.TokenCount != 0 || run.RequestCount != 1 || run.ReservedTokens == 0 {
					t.Fatal("failed completion changed accounting")
				}
				var count int
				if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='run.attempt.finish'", f.orgID).Scan(&count); err != nil || count != 0 {
					t.Fatal("failed completion left success audit")
				}
			})
		})
	}
}

func TestDerivedWorkerReclaimedActualAttemptRecoversWithoutSecretsOrRedispatch(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		p := pendingDerivedTLSAttempt(t, f, 30)
		// The first response existed only in the old handler's memory and its
		// completion is deliberately never committed. The recovery has no source
		// body to authenticate; it must state UNCERTAIN, not a normal response.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET available_at=$1 WHERE organization_id=$2 AND status='pending'", time.Now().UTC().Add(time.Hour), f.orgID); err != nil {
			t.Fatal("isolate actual reclaimed job")
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_until=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, p.lease.Job.ID); err != nil {
			t.Fatal("expire original handler lease")
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_targets SET version=version+1 WHERE organization_id=$1 AND id=$2", f.orgID, p.run.TargetID); err != nil {
			t.Fatal("make target stale before recovery")
		}
		newLease, err := p.queue.Claim(f.ctx)
		if err != nil || newLease == nil || newLease.Job.ID != p.lease.Job.ID || newLease.Generation != p.lease.Generation+1 {
			t.Fatal("did not reclaim exact interrupted attempt", err)
		}
		if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("old actual response completion bypassed fencing", err)
		}
		config := p.config
		config.Secrets, config.EvidenceKeys, config.DisplaySealer = nil, nil, nil
		completion, err := executeRunSample(f.ctx, Execution{Queue: p.queue, Lease: *newLease}, config)
		if err != nil || completion == nil {
			t.Fatal("prepare recovery without any credential/decryption capability", err)
		}
		rejectDerivedBodyInserts(t, f)
		if err := p.queue.CompleteWith(f.ctx, *newLease, completion); err != nil {
			t.Fatal("complete actual reclaimed recovery", err)
		}
		derivedCounts(t, f, p.run.ID, 1, 0)
		verifySettledDerivedAttempt(t, f, p, "UNCERTAIN", "INVALID_RETRYABLE", "MI_UNCERTAIN_ATTEMPT")
		attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != repository.DerivedRecovered || attempts[0].LeaseGeneration != p.lease.Generation {
			t.Fatal("recovery rewrote original attempt generation/receipt")
		}
		run, err := p.tenant.GetRun(p.run.ID)
		if err != nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 || run.RequestCount != 1 || run.TokenCount <= 0 || p.requestCount() != 1 {
			t.Fatal("recovery redispatched or lost conservative accounting")
		}
		if err := p.queue.CompleteWith(f.ctx, *newLease, completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("recovery duplicated terminal completion", err)
		}
		derivedCounts(t, f, p.run.ID, 1, 0)
	})
}
