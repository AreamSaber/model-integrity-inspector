package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// These fixtures' upstream sends no headers/body before cancellation. The
// actual cancelled WithLease cannot mint a new body capture. Assert the exact
// absence receipt and both tables, not an invented empty response envelope.
func attemptWithoutResponseCapture(t *testing.T, f runFixture, tenant *repository.Tenant, sample repository.LogicalSampleRecord) repository.AttemptRecord {
	t.Helper()
	attempts, err := tenant.ListAttempts(sample.ID)
	if err != nil || len(attempts) != 1 {
		t.Fatal("interrupted legacy attempt was missing or redispatched")
	}
	attempt := attempts[0]
	if attempt.Status != "COMPLETED" || attempt.DerivedReceipt != repository.DerivedLegacy || attempt.ResponseBodyReceipt != repository.BodyNotCaptured {
		t.Fatal("interrupted legacy execution fabricated a capture or derived proof")
	}
	if _, err := tenant.GetResponseEvidenceForAnalysis(sample.RunID, sample.ID, attempt.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("uncaptured legacy response is not explicitly absent")
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM integrity_display_evidence WHERE organization_id=$1 AND attempt_id=$2", f.orgID, attempt.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("interrupted legacy execution fabricated display provenance")
	}
	if _, err := tenant.VerifyAuditFull(); err != nil {
		t.Fatal("interrupted legacy execution damaged audit integrity")
	}
	return attempt
}

func TestLegacyWorkerPolicyChangesAfterActualCaptureNeverReviveBodies(t *testing.T) {
	testWorkerPolicyChangesAfterActualCapture(t, "")
}

func TestLegacyWorkerActualTLSUsesOrganizationRetentionWithoutSourceUpgrade(t *testing.T) {
	for _, days := range []int{0, 7, 30, 180} {
		t.Run(fmt.Sprintf("days_%d", days), func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingModeTLSAttempt(t, f, days, "")
				if days == 0 {
					rejectDerivedBodyInserts(t, f)
				}
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); err != nil {
					t.Fatal("actual legacy policy completion", err)
				}
				bodies, receipt := 1, repository.BodyRecorded
				if days == 0 {
					bodies, receipt = 0, repository.BodyNotRetained
				}
				derivedCounts(t, f, p.run.ID, 0, bodies)
				attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
				if err != nil || len(attempts) != 1 || attempts[0].Status != "COMPLETED" || attempts[0].DerivedReceipt != repository.DerivedLegacy || attempts[0].ResponseBodyReceipt != receipt {
					t.Fatal("legacy completion invented derived proof or incorrect body state")
				}
				if days > 0 {
					var created, expires time.Time
					var capturedMicros, expiryMicros int64
					if err := f.db.QueryRowContext(f.ctx, "SELECT created_at,expires_at FROM integrity_response_evidence WHERE organization_id=$1 AND attempt_id=$2", f.orgID, attempts[0].ID).Scan(&created, &expires); err != nil {
						t.Fatal("read actual legacy response envelope times")
					}
					if err := f.db.QueryRowContext(f.ctx, "SELECT captured_at_micros,expires_at_micros FROM integrity_display_evidence WHERE organization_id=$1 AND attempt_id=$2", f.orgID, attempts[0].ID).Scan(&capturedMicros, &expiryMicros); err != nil {
						t.Fatal("read actual legacy display binding")
					}
					if expires.Sub(created) != time.Duration(days)*24*time.Hour || capturedMicros != created.UnixMicro() || expiryMicros != expires.UnixMicro() {
						t.Fatal("legacy capture still uses fixed thirty days or changed sealed AAD time")
					}
				}
				verifyLegacyRunSourceUnchanged(t, p)
			})
		})
	}
}

func verifyLegacyRunSourceUnchanged(t *testing.T, p derivedPendingFixture) {
	t.Helper()
	run, err := p.tenant.GetRun(p.run.ID)
	if err != nil || run.AnalysisSourceVersion != repository.AnalysisSourceLegacyV1 || run.ManifestHash != p.run.ManifestHash || run.ConfigSnapshot != p.run.ConfigSnapshot {
		t.Fatal("legacy retention re-signed or upgraded the confirmed source")
	}
	plan, err := p.tenant.GetExecutionPlan(p.run.ID)
	if err != nil || plan.AnalysisSourceVersion != "" {
		t.Fatal("old frozen plan acquired a derived source marker")
	}
}

func TestLegacyWorkerZeroDayAnalysisIsExplicitlyInsufficient(t *testing.T) {
	for _, days := range []int{0, 30} {
		t.Run(fmt.Sprintf("days_%d", days), func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingModeTLSAttempt(t, f, days, "")
				if days == 0 {
					rejectDerivedBodyInserts(t, f)
				}
				lease := finishDerivedTLSRun(t, f, p)
				// Both startup capabilities are present, as in the actual app.
				// An old signed source must never manufacture or require new S1.
				handler, err := NewAnalysisHandler(AnalysisConfig{Builder: p.builder, EvidenceKeys: f.ring, DerivedVerifier: p.verifier})
				if err != nil {
					t.Fatal(err)
				}
				completion, err := handler(f.ctx, Execution{Queue: p.queue, Lease: lease})
				if err != nil {
					t.Fatal("legacy analysis with current policy", err)
				}
				if err := p.queue.CompleteWith(f.ctx, lease, completion); err != nil {
					t.Fatal("publish truthful legacy analysis", err)
				}
				published, err := p.tenant.GetPublishedAnalysis(p.run.ID, 1)
				if err != nil {
					t.Fatal(err)
				}
				var document analyzer.Document
				if json.Unmarshal([]byte(published.ConclusionJSON), &document) != nil || document.Features.Expected != p.expected {
					t.Fatal("legacy publication lost the actual signed sample set")
				}
				bodies := p.expected
				if days == 0 {
					bodies = 0
					if document.Features.Included != 0 || published.Completeness != "INSUFFICIENT" || published.EvidenceGrade != "D" || published.OverallRisk != nil {
						t.Fatal("missing legacy responses became fabricated successful analysis")
					}
				} else if document.Features.Included == 0 {
					t.Fatal("retained actual legacy responses no longer contribute evidence")
				}
				derivedCounts(t, f, p.run.ID, 0, bodies)
				verifyLegacyRunSourceUnchanged(t, p)
				if p.requestCount() != p.expected {
					t.Fatal("legacy source preservation repeated an actual TLS request")
				}
				if _, err := p.tenant.VerifyAuditFull(); err != nil {
					t.Fatal("legacy policy analysis damaged audit integrity")
				}
			})
		})
	}
}
