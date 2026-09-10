package repository

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// Human prose must not escape through default diagnostic formatting. Explicit
// authorized HTTP projection and the private request hash remain separate.
func TestReviewDiagnosticFormattingDoesNotExposeHumanProse(t *testing.T) {
	const note = "SYNTHETIC_REVIEW_PROSE_CANARY"
	const key = "SYNTHETIC_REVIEW_REQUEST_KEY"
	for name, value := range map[string]any{
		"record": ReviewRecord{Explanation: note},
		"input":  ReviewInput{Explanation: note, IdempotencyKey: key},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				text := fmt.Sprintf(format, value)
				if strings.Contains(text, note) || strings.Contains(text, key) {
					t.Errorf("%s diagnostic format exposes private review text", format)
				}
			}
			for _, jsonHandler := range []bool{false, true} {
				var output bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&output, nil)
				if jsonHandler {
					handler = slog.NewJSONHandler(&output, nil)
				}
				slog.New(handler).Info("synthetic bounded review diagnostic", "review", value)
				if strings.Contains(output.String(), note) || strings.Contains(output.String(), key) {
					t.Errorf("structured diagnostic exposes private review text (json=%v)", jsonHandler)
				}
			}
		})
	}
}

func TestReviewRecoveryAndNewAppendCompeteWithoutDuplication(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run := reviewFixture(t, store)
		input := ReviewInput{RunID: run.ID, AnalysisRevision: 1, Conclusion: "watch", Explanation: "Synthetic human observation", IdempotencyKey: "review-old-receipt-001"}
		first, err := tenant.AppendReview(input)
		if err != nil {
			t.Fatal(err)
		}
		before, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		type outcome struct {
			row      ReviewRecord
			err      error
			recovery bool
		}
		start := make(chan struct{})
		done := make(chan outcome, 10)
		for index := range 10 {
			go func() {
				copy := input
				recovery := index < 6
				if !recovery {
					copy.PreviousReviewID = first.ID
					copy.IdempotencyKey = fmt.Sprintf("review-new-receipt-%03d", index)
					copy.Conclusion = "false_positive"
				}
				<-start
				row, err := tenant.AppendReview(copy)
				done <- outcome{row, err, recovery}
			}()
		}
		close(start)
		wins := 0
		for range 10 {
			select {
			case result := <-done:
				if result.recovery {
					if result.err != nil || !reflect.DeepEqual(result.row, first) {
						t.Fatal("recovery did not return immutable original", result.err)
					}
				} else if result.err == nil {
					wins++
				} else if !errors.Is(result.err, ErrConflict) {
					t.Fatal("new append returned non-CAS failure", result.err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("bounded mixed review race did not finish")
			}
		}
		if wins != 1 {
			t.Fatal("concurrent new append winner count", wins)
		}
		for _, table := range []string{"integrity_reviews", "integrity_review_receipts"} {
			var count int64
			if err := store.db.Table(table).Where("organization_id=?", tenant.orgID).Count(&count).Error; err != nil || count != 2 {
				t.Fatal("mixed retry created duplicate history or receipt", table, err)
			}
		}
		var auditCount int64
		if err := store.db.Table("integrity_audit_logs").Where("organization_id=? AND action=?", tenant.orgID, "review.append").Count(&auditCount).Error; err != nil || auditCount != 2 {
			t.Fatal("recovered append created a second mutation audit", err)
		}
		after, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("review race changed published machine output", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReviewExistingReceiptDoesNotBypassRevokedAuthority(t *testing.T) {
	for _, kind := range []string{"review.write", "run.read", "session", "user", "member", "organization"} {
		t.Run(kind, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, run := reviewFixture(t, store)
				input := ReviewInput{RunID: run.ID, AnalysisRevision: 1, Conclusion: "watch", Explanation: "Synthetic bounded note", IdempotencyKey: "review-revocation-retry"}
				if _, err := tenant.AppendReview(input); err != nil {
					t.Fatal(err)
				}
				actor, err := audit.ActorFromContext(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				denied := ErrManagementPermission
				switch kind {
				case "review.write", "run.read":
					err = store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, kind).Error
				case "session":
					err = store.db.Model(&Session{}).Where("user_id=?", actor.ActorID).Update("revoked_at", time.Now().UTC()).Error
					denied = ErrManagementSession
				case "user":
					err = store.db.Exec("UPDATE users SET status='disabled' WHERE id=?", actor.ActorID).Error
					denied = ErrManagementSession
				case "member":
					err = store.db.Exec("UPDATE organization_members SET status='disabled' WHERE organization_id=? AND user_id=?", tenant.orgID, actor.ActorID).Error
				case "organization":
					err = store.db.Exec("UPDATE organizations SET status='disabled' WHERE id=?", tenant.orgID).Error
				}
				if err != nil {
					t.Fatal("isolated authority mutation failed", err)
				}
				if _, err := tenant.AppendReview(input); !errors.Is(err, denied) {
					t.Fatal("existing idempotency receipt bypassed current authority", err)
				}
				_, err = tenant.ListReviews(run.ID, 1, ListOptions{Limit: 25})
				if kind == "review.write" {
					if err != nil {
						t.Fatal("read-only history incorrectly required review.write", err)
					}
				} else if !errors.Is(err, denied) {
					t.Fatal("old read capability bypassed current authority", err)
				}
				var count int64
				if err := store.db.Table("integrity_reviews").Where("organization_id=?", tenant.orgID).Count(&count).Error; err != nil || count != 1 {
					t.Fatal("revoked retry mutated review history", err)
				}
			})
		})
	}
}
