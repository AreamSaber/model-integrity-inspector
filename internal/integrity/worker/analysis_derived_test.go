package worker

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func analysisDerivedFixtureRows(t *testing.T, f runFixture, p derivedPendingFixture, lease repository.JobLease) []repository.AttemptDerivedRecord {
	t.Helper()
	source, err := p.queue.LoadRunAnalysis(f.ctx, lease)
	if err != nil {
		t.Fatal("read genuine signed S1 fixture", err)
	}
	var rows []repository.AttemptDerivedRecord
	if err := source.Use(func(data repository.AnalysisData) error {
		for _, row := range data.Derived {
			row.Payload, row.MAC = bytes.Clone(row.Payload), bytes.Clone(row.MAC)
			rows = append(rows, row)
		}
		return nil
	}); err != nil || len(rows) != p.expected || len(rows) < 2 {
		t.Fatal("incomplete actual signed S1 fixture")
	}
	return rows
}

func TestAnalysisDerivedWorkerCorruptionNeverFallsBackToAvailableRaw(t *testing.T) {
	for _, mode := range []string{"missing-final", "missing-all", "payload", "mac", "unknown-key", "wrong-key", "swapped-signed-rows", "missing-verifier", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, 30)
				lease := finishDerivedTLSRun(t, f, p)
				rows := analysisDerivedFixtureRows(t, f, p, lease)
				// Keep genuine exact-AAD raw responses available in every failure
				// case. Their presence never authorizes changing the signed mode.
				derivedCounts(t, f, p.run.ID, p.expected, p.expected)
				cfg := AnalysisConfig{Builder: p.builder, EvidenceKeys: f.ring, DerivedVerifier: p.verifier}
				var err error
				switch mode {
				case "missing-final":
					_, err = f.db.ExecContext(f.ctx, "DELETE FROM integrity_attempt_derived WHERE organization_id=$1 AND attempt_id=$2", f.orgID, rows[0].AttemptID)
				case "missing-all":
					_, err = f.db.ExecContext(f.ctx, "DELETE FROM integrity_attempt_derived WHERE organization_id=$1 AND run_id=$2", f.orgID, p.run.ID)
				case "payload":
					_, err = f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET payload=$1 WHERE organization_id=$2 AND attempt_id=$3", []byte(`{}`), f.orgID, rows[0].AttemptID)
				case "mac":
					_, err = f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET mac=$1 WHERE organization_id=$2 AND attempt_id=$3", bytes.Repeat([]byte{3}, 32), f.orgID, rows[0].AttemptID)
				case "unknown-key":
					_, err = f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET key_version=$1 WHERE organization_id=$2 AND attempt_id=$3", "not.installed", f.orgID, rows[0].AttemptID)
				case "wrong-key":
					cfg.DerivedVerifier, err = features.NewDerivedVerifier(map[string][]byte{"worker-test": bytes.Repeat([]byte{4}, 32)})
				case "swapped-signed-rows":
					for i := range 2 {
						other := rows[1-i]
						if _, err = f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET payload=$1,mac=$2 WHERE organization_id=$3 AND attempt_id=$4", other.Payload, other.MAC, f.orgID, rows[i].AttemptID); err != nil {
							break
						}
					}
				case "missing-verifier":
					cfg.DerivedVerifier = nil
				}
				if err != nil {
					t.Fatal("install isolated actual S1 failure")
				}
				handler, err := NewAnalysisHandler(cfg)
				if err != nil {
					t.Fatal("construct analysis handler", err)
				}
				ctx := f.ctx
				if mode == "canceled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				completion, err := handler(ctx, Execution{Queue: p.queue, Lease: lease})
				if err == nil || completion != nil {
					t.Fatal("invalid S1 produced a completion or fell back to raw")
				}
				if _, err := p.tenant.GetPublishedAnalysis(p.run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
					t.Fatal("invalid S1 published a score")
				}
				var rawCount int
				if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2", f.orgID, p.run.ID).Scan(&rawCount); err != nil || rawCount != p.expected {
					t.Fatal("negative case removed its available raw fallback")
				}
			})
		})
	}
}

func TestAnalysisDerivedWorkerMutationAfterAuthenticationBlocksPublication(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		p := pendingDerivedTLSAttempt(t, f, 0)
		rejectDerivedBodyInserts(t, f)
		lease := finishDerivedTLSRun(t, f, p)
		rows := analysisDerivedFixtureRows(t, f, p, lease)
		handler, err := NewAnalysisHandler(AnalysisConfig{Builder: p.builder, DerivedVerifier: p.verifier})
		if err != nil {
			t.Fatal(err)
		}
		completion, err := handler(f.ctx, Execution{Queue: p.queue, Lease: lease})
		if err != nil || completion == nil {
			t.Fatal("authenticate actual bodyless analysis", err)
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET payload=$1 WHERE organization_id=$2 AND attempt_id=$3", []byte("changed-after-authentication"), f.orgID, rows[0].AttemptID); err != nil {
			t.Fatal("change isolated S1 after authentication")
		}
		if err := p.queue.CompleteWith(f.ctx, lease, completion); !errors.Is(err, repository.ErrAnalysisSource) {
			t.Fatal("changed S1 published after authentication", err)
		}
		for _, table := range []string{"integrity_run_results", "integrity_findings"} {
			var count int
			if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM "+table+" WHERE organization_id=$1 AND run_id=$2", f.orgID, p.run.ID).Scan(&count); err != nil || count != 0 {
				t.Fatal("rejected source change left publication rows")
			}
		}
		var publishedAudit int
		if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action=$2", f.orgID, "run.analysis.publish").Scan(&publishedAudit); err != nil || publishedAudit != 0 {
			t.Fatal("source change left a successful publication audit")
		}
		// Restore exactly the authenticated S1 in this isolated fixture. The
		// same valid fence may complete; retries never update an existing result.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_attempt_derived SET payload=$1 WHERE organization_id=$2 AND attempt_id=$3", rows[0].Payload, f.orgID, rows[0].AttemptID); err != nil {
			t.Fatal("restore exact isolated S1 fixture")
		}
		if err := p.queue.CompleteWith(f.ctx, lease, completion); err != nil {
			t.Fatal("unchanged authenticated source failed to publish", err)
		}
		if err := p.queue.CompleteWith(f.ctx, lease, completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("duplicate authenticated publication accepted")
		}
		derivedCounts(t, f, p.run.ID, p.expected, 0)
		if _, err := p.tenant.VerifyAuditFull(); err != nil {
			t.Fatal("source-receipt publication audit invalid")
		}
	})
}
