package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

type derivedPendingFixture struct {
	tenant       *repository.Tenant
	run          repository.RunRecord
	builder      *features.Builder
	verifier     *features.DerivedVerifier
	queue        *repository.JobQueue
	lease        repository.JobLease
	completion   Completion
	config       RunConfig
	expected     int
	requestCount func() int
}

func finishDerivedTLSRun(t *testing.T, f runFixture, p derivedPendingFixture) repository.JobLease {
	t.Helper()
	if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); err != nil {
		t.Fatal("finish initial derived sample", err)
	}
	handlers, err := NewRunHandlers(p.config)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < p.expected+2; i++ {
		lease, err := p.queue.Claim(f.ctx)
		if err != nil || lease == nil {
			t.Fatal("claim remaining derived work", err)
		}
		if repository.JobType(lease.Job.Type) == repository.JobRunAnalyze {
			return *lease
		}
		handler := handlers[repository.JobType(lease.Job.Type)]
		if handler == nil {
			t.Fatal("unexpected remaining job")
		}
		completion, err := handler(f.ctx, Execution{Queue: p.queue, Lease: *lease})
		if err != nil {
			t.Fatal("remaining real TLS execution", err)
		}
		if err := p.queue.CompleteWith(f.ctx, *lease, completion); err != nil {
			t.Fatal("remaining real derived completion", err)
		}
	}
	t.Fatal("derived analysis not queued")
	return repository.JobLease{}
}

// Independent test oracle opens the actual persisted 30-day response envelopes.
// Production derived analysis never receives these keys or response projections.
func actualDerivedResponseReference(t *testing.T, f runFixture, p derivedPendingFixture, lease repository.JobLease) []byte {
	t.Helper()
	source, err := p.queue.LoadRunAnalysis(f.ctx, lease)
	if err != nil {
		t.Fatal("load actual closed source", err)
	}
	var expected []byte
	err = source.Use(func(data repository.AnalysisData) error {
		if len(data.Evidence) != 0 || len(data.Derived) != p.expected {
			t.Fatal("derived loading queried bodies or lost an attempt")
		}
		input, err := analysisInput(f.ctx, data, nil)
		if err != nil {
			return err
		}
		for i := range input.Samples {
			for j := range input.Samples[i].Attempts {
				a := &input.Samples[i].Attempts[j]
				var record secret.EvidenceRecord
				if err := f.db.QueryRowContext(f.ctx, "SELECT key_version,nonce,ciphertext,plaintext_bytes,content_hash FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_id=$4 AND request_hash=$5", f.orgID, p.run.ID, input.Samples[i].ID, a.ID, a.RequestHash).Scan(&record.KeyVersion, &record.Nonce, &record.Ciphertext, &record.PlaintextBytes, &record.ContentHash); err != nil {
					return err
				}
				scope := secret.EvidenceScope{OrganizationID: f.orgID, RunID: p.run.ID, LogicalSampleID: input.Samples[i].ID, AttemptID: a.ID, RequestHash: a.RequestHash}
				if err := f.ring.WithResponseEvidence(scope, record, func(response domain.NormalizedResponse) error {
					var err error
					a.Evidence, err = features.NewEvidence(features.EvidenceScope{OrganizationID: f.orgID, RunID: p.run.ID, SampleID: input.Samples[i].ID, AttemptID: a.ID, RequestHash: a.RequestHash}, response)
					return err
				}); err != nil {
					return err
				}
			}
		}
		records := make([]features.DerivedRecord, 0, len(data.Derived))
		for _, r := range data.Derived {
			records = append(records, features.DerivedRecord{Version: r.Version, KeyVersion: r.KeyVersion, Payload: r.Payload, MAC: r.MAC})
		}
		batch, err := p.builder.BuildResponseReference(f.ctx, input, records, p.verifier)
		if err != nil {
			return err
		}
		document, err := analyzer.Analyze(batch)
		if err != nil {
			return err
		}
		expected, err = json.Marshal(document)
		return err
	})
	if err != nil {
		t.Fatal("actual raw response reference failed", err)
	}
	return expected
}

func TestDerivedWorkerActualTLSZeroAndThirtyDaysPublishRealAnalysis(t *testing.T) {
	for _, days := range []int{0, 30} {
		t.Run(fmt.Sprintf("days_%d", days), func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, days)
				if days == 0 {
					rejectDerivedBodyInserts(t, f)
				}
				lease := finishDerivedTLSRun(t, f, p)
				bodies := 0
				if days > 0 {
					bodies = p.expected
				}
				derivedCounts(t, f, p.run.ID, p.expected, bodies)
				var reference []byte
				if days > 0 {
					reference = actualDerivedResponseReference(t, f, p, lease)
				}
				// Deliberately no EvidenceKeys: this actual production handler must
				// finish using S1 alone, even when raw ciphertext happens to exist.
				handler, err := NewAnalysisHandler(AnalysisConfig{Builder: p.builder, DerivedVerifier: p.verifier})
				if err != nil {
					t.Fatal(err)
				}
				completion, err := handler(f.ctx, Execution{Queue: p.queue, Lease: lease})
				if err != nil {
					t.Fatal("actual bodyless analysis", err)
				}
				if err := p.queue.CompleteWith(f.ctx, lease, completion); err != nil {
					t.Fatal("publish actual bodyless analysis", err)
				}
				published, err := p.tenant.GetPublishedAnalysis(p.run.ID, 1)
				if err != nil {
					t.Fatal("read published derived analysis", err)
				}
				var doc analyzer.Document
				if json.Unmarshal([]byte(published.ConclusionJSON), &doc) != nil || doc.Features.Expected != p.expected || doc.Features.Included == 0 {
					t.Fatal("missing measured bodyless features")
				}
				if days > 0 && !bytes.Equal(reference, []byte(published.ConclusionJSON)) {
					t.Fatal("complete published analyzer JSON differs from independent actual response reference")
				}
				run, err := p.tenant.GetRun(p.run.ID)
				if err != nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 || run.RequestCount != int64(p.expected) {
					t.Fatal("derived run accounting incomplete")
				}
				derivedCounts(t, f, p.run.ID, p.expected, bodies)
				if _, err := p.tenant.VerifyAuditFull(); err != nil {
					t.Fatal("published derived audit chain", err)
				}
			})
		})
	}
}

// This uses a genuinely signed new-mode Run, the actual TLS adapter, real
// credential use and real reserve/capture operations. The returned completion
// has not committed: callers can inject policy/outcome changes at that boundary.
func pendingDerivedTLSAttempt(t *testing.T, f runFixture, days int) derivedPendingFixture {
	t.Helper()
	if _, err := f.db.ExecContext(f.ctx, "UPDATE organizations SET full_response_retention_days=$1 WHERE id=$2", days, f.orgID); err != nil {
		t.Fatal("set synthetic initial retention policy")
	}
	tenant, run, builder, expected := signedAnalysisRunMode(t, f, domain.AnalysisSourceDerivedV1)
	mac, err := f.ring.NewDerivedSourceMAC()
	if err != nil {
		t.Fatal(err)
	}
	sealer, verifier, err := features.NewDerivedCapabilitiesWithMAC("worker-test", mac)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
	if err != nil {
		t.Fatal(err)
	}
	config := runTLSConfig(t, f, upstream)
	config.DerivedBuilder, config.DerivedSealer = builder, sealer
	handlers, err := NewRunHandlers(config)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := f.store.OpenJobQueue(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	planLease, err := queue.Claim(f.ctx)
	if err != nil || planLease == nil || repository.JobType(planLease.Job.Type) != repository.JobRunPlan {
		t.Fatal("claim derived plan", err)
	}
	completion, err := handlers[repository.JobRunPlan](f.ctx, Execution{Queue: queue, Lease: *planLease})
	if err != nil {
		t.Fatal("prepare derived plan", err)
	}
	if err := queue.CompleteWith(f.ctx, *planLease, completion); err != nil {
		t.Fatal("start derived run", err)
	}
	lease, err := queue.Claim(f.ctx)
	if err != nil || lease == nil || repository.JobType(lease.Job.Type) != repository.JobSampleExecute {
		t.Fatal("claim derived sample", err)
	}
	completion, err = handlers[repository.JobSampleExecute](f.ctx, Execution{Queue: queue, Lease: *lease})
	if err != nil || completion == nil {
		t.Fatal("execute actual derived TLS sample", err)
	}
	if len(upstream.Records()) != 1 {
		t.Fatal("wrong actual request count")
	}
	return derivedPendingFixture{tenant, run, builder, verifier, queue, *lease, completion, config, expected, func() int { return len(upstream.Records()) }}
}

func rejectDerivedBodyInserts(t *testing.T, f runFixture) {
	t.Helper()
	for _, ddl := range []struct{ postgres, sqlite string }{
		{"ALTER TABLE integrity_response_evidence ADD CONSTRAINT worker_no_body_insert CHECK (false) NOT VALID", "CREATE TRIGGER worker_no_body_raw BEFORE INSERT ON integrity_response_evidence BEGIN SELECT RAISE(ABORT, 'synthetic body insert forbidden'); END"},
		{"ALTER TABLE integrity_display_evidence ADD CONSTRAINT worker_no_body_insert CHECK (false) NOT VALID", "CREATE TRIGGER worker_no_body_display BEFORE INSERT ON integrity_display_evidence BEGIN SELECT RAISE(ABORT, 'synthetic body insert forbidden'); END"},
	} {
		statement := ddl.postgres
		if strings.HasSuffix(t.Name(), "/sqlite") {
			statement = ddl.sqlite
		}
		if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
			t.Fatal("install actual body INSERT prohibition")
		}
	}
}

func derivedCounts(t *testing.T, f runFixture, runID int64, s1, bodies int) {
	t.Helper()
	for table, want := range map[string]int{"integrity_attempt_derived": s1, "integrity_response_evidence": bodies, "integrity_display_evidence": bodies} {
		var count int
		if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM "+table+" WHERE organization_id=$1 AND run_id=$2", f.orgID, runID).Scan(&count); err != nil || count != want {
			t.Fatalf("wrong %s record count: got=%d want=%d", table, count, want)
		}
	}
}

func TestDerivedWorkerActualTLSRetentionAndAtomicSettlement(t *testing.T) {
	for _, days := range []int{0, 7, 30, 180} {
		t.Run(fmt.Sprintf("days_%d", days), func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, days)
				derivedCounts(t, f, p.run.ID, 0, 0)
				if days == 0 {
					rejectDerivedBodyInserts(t, f)
				}
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); err != nil {
					t.Fatal("settle actual derived response", err)
				}
				bodies := 0
				if days > 0 {
					bodies = 1
				}
				derivedCounts(t, f, p.run.ID, 1, bodies)
				attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
				if err != nil || len(attempts) != 1 {
					t.Fatal("actual attempt unavailable")
				}
				a := attempts[0]
				if a.Status != "COMPLETED" || a.DerivedReceipt != repository.DerivedRecorded || a.FinishedAt == nil {
					t.Fatal("derived completion receipt missing")
				}
				want := repository.BodyNotRetained
				if days > 0 {
					want = repository.BodyRecorded
				}
				if a.ResponseBodyReceipt != want {
					t.Fatal("wrong body receipt", a.ResponseBodyReceipt)
				}
				if days > 0 {
					var captured, expires int64
					var state string
					if err := f.db.QueryRowContext(f.ctx, "SELECT captured_at_micros,expires_at_micros,state FROM integrity_display_evidence WHERE organization_id=$1 AND attempt_id=$2", f.orgID, a.ID).Scan(&captured, &expires, &state); err != nil || state != repository.DisplayCaptured || expires-captured != int64(time.Duration(days)*24*time.Hour/time.Microsecond) {
						t.Fatal("display did not preserve actual configured capture expiry", state)
					}
				}
				if _, err := p.tenant.VerifyAuditFull(); err != nil {
					t.Fatal("atomic settlement audit", err)
				}
			})
		})
	}
}

func TestDerivedWorkerPolicyChangesAfterActualCaptureNeverReviveBodies(t *testing.T) {
	for _, mode := range []string{"disable_after_capture", "enable_after_disabled_capture", "cutoff_then_extend"} {
		t.Run(mode, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				days := 30
				if mode == "enable_after_disabled_capture" {
					days = 0
				}
				p := pendingDerivedTLSAttempt(t, f, days)
				nextDays := 0
				if mode != "disable_after_capture" {
					nextDays = 30
				}
				// Controlled final-policy mutation: the management API itself is
				// covered separately. This verifies the real finishing transaction.
				if mode == "enable_after_disabled_capture" {
					// Isolate the immutable disabled receipt: no cutoff restriction
					// is added to explain why this previously disabled body stays absent.
					if _, err := f.db.ExecContext(f.ctx, "UPDATE organizations SET full_response_retention_days=$1 WHERE id=$2", nextDays, f.orgID); err != nil {
						t.Fatal("enable policy after disabled capture")
					}
				} else {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE organizations SET full_response_retention_days=0,response_evidence_not_before_micros=$1 WHERE id=$2", time.Now().UnixMicro(), f.orgID); err != nil {
						t.Fatal("disable policy after actual response capture")
					}
					if nextDays > 0 {
						if _, err := f.db.ExecContext(f.ctx, "UPDATE organizations SET full_response_retention_days=$1 WHERE id=$2", nextDays, f.orgID); err != nil {
							t.Fatal("extend policy without lowering actual cutoff")
						}
					}
				}
				rejectDerivedBodyInserts(t, f)
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); err != nil {
					t.Fatal("new policy must skip all body INSERTs, not insert then delete", err)
				}
				derivedCounts(t, f, p.run.ID, 1, 0)
			})
		})
	}
}
