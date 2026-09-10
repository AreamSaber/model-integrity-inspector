package repository

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func reviewFixture(t *testing.T, store *Store) (*Tenant, RunRecord) {
	t.Helper()
	tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 1)
	readPermissions(t, tenant)
	var roleID int64
	if err := store.db.Table("roles").Select("id").Where("organization_id=? AND name=?", tenant.orgID, "administrator").Scan(&roleID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO permissions(code) VALUES ('review.write') ON CONFLICT(code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) VALUES (?,?,'review.write')", tenant.orgID, roleID).Error; err != nil {
		t.Fatal(err)
	}
	source, err := queue.LoadRunAnalysis(t.Context(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
		return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
	}); err != nil {
		t.Fatal(err)
	}
	return tenant, run
}

type failReviewAudit struct{}

func (failReviewAudit) ActiveVersion() string { return "test-v1" }
func (failReviewAudit) AuditMAC(version string, raw []byte) ([]byte, error) {
	if bytes.Contains(raw, []byte("review.append")) {
		return nil, audit.ErrUnavailable
	}
	return (testAuditSigner{}).AuditMAC(version, raw)
}

func TestReviewAppendOnlyIdempotentCASAndAuditRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run := reviewFixture(t, store)
		before, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		input := ReviewInput{RunID: run.ID, AnalysisRevision: 1, Conclusion: "watch", Explanation: "Synthetic human review; not a release approval.", IdempotencyKey: "review-request-0001"}
		originalSigner := store.auditSigner
		store.auditSigner = failReviewAudit{}
		if _, err := tenant.AppendReview(input); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure did not abort review", err)
		}
		store.auditSigner = originalSigner
		for _, table := range []string{"integrity_reviews", "integrity_review_receipts"} {
			var count int64
			if err := store.db.Table(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("partial review survived rollback", table, err)
			}
		}
		first, err := tenant.AppendReview(input)
		if err != nil || first.ID <= 0 || first.Conclusion != input.Conclusion {
			t.Fatal("review not created", err)
		}
		retry, err := tenant.AppendReview(input)
		if err != nil || !reflect.DeepEqual(first, retry) {
			t.Fatal("retry did not recover original review", err)
		}
		stale := input
		stale.IdempotencyKey = "review-request-0002"
		if _, err := tenant.AppendReview(stale); !errors.Is(err, ErrConflict) {
			t.Fatal("stale human view overwrote latest", err)
		}
		changed := input
		changed.Explanation = "Same key different human explanation"
		if _, err := tenant.AppendReview(changed); !errors.Is(err, ErrConflict) {
			t.Fatal("incompatible key reuse", err)
		}
		next := stale
		next.PreviousReviewID, next.Conclusion = first.ID, "false_positive"
		second, err := tenant.AppendReview(next)
		if err != nil || second.ID == first.ID || !second.CreatedAt.After(first.CreatedAt) {
			t.Fatal("new review not appended", err)
		}
		if recovered, err := tenant.AppendReview(input); err != nil || recovered.ID != first.ID {
			t.Fatal("late retry changed review history", err)
		}
		page, err := tenant.ListReviews(run.ID, 1, ListOptions{Limit: 1})
		if err != nil || len(page) != 1 || page[0].ID != second.ID {
			t.Fatal("latest review page", err)
		}
		page, err = tenant.ListReviews(run.ID, 1, ListOptions{AfterID: second.ID, Limit: 25})
		if err != nil || len(page) != 1 || page[0].ID != first.ID {
			t.Fatal("immutable history page", err)
		}
		after, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("human decision modified machine result", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
		var audits []string
		if err := store.db.Table("integrity_audit_logs").Pluck("diff_summary", &audits).Error; err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(audits, ""), input.Explanation) {
			t.Fatal("human prose entered audit summary")
		}
	})
}

func TestReviewConcurrentCASScopesPermissionsAndReadBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run := reviewFixture(t, store)
		input := ReviewInput{RunID: run.ID, AnalysisRevision: 1, Conclusion: "confirmed", Explanation: "Synthetic explicit observation; not vendor intent.", IdempotencyKey: "concurrent-review-0000"}
		ready, done := make(chan struct{}), make(chan error, 8)
		for i := range 8 {
			go func() {
				copy := input
				copy.IdempotencyKey = fmt.Sprintf("concurrent-review-%04d", i)
				<-ready
				_, err := tenant.AppendReview(copy)
				done <- err
			}()
		}
		close(ready)
		wins := 0
		for range 8 {
			err := <-done
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		if wins != 1 {
			t.Fatal("concurrent latest check had multiple winners", wins)
		}
		page, err := tenant.ListReviews(run.ID, 1, ListOptions{Limit: 25})
		if err != nil || len(page) != 1 {
			t.Fatal(err)
		}
		input.PreviousReviewID = page[0].ID
		input.IdempotencyKey = "new-after-concurrency"
		foreign, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := foreign.AppendReview(input); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("cross-org review authority", err)
		}
		unbound, _ := store.WithOrganization(t.Context(), tenant.orgID)
		if _, err := unbound.AppendReview(input); !errors.Is(err, ErrManagementSession) {
			t.Fatal("unbound review authority", err)
		}
		if _, err := tenant.ListReviews(run.ID, 2, ListOptions{Limit: 25}); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing analysis revision", err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='review.write'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.AppendReview(input); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked permission reused", err)
		}
		if err := store.db.Exec("UPDATE integrity_reviews SET explanation=? WHERE organization_id=?", strings.Repeat("x", 4097), tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListReviews(run.ID, 1, ListOptions{Limit: 25}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("oversized DB human prose reflected", err)
		}
	})
}

func TestReviewInputBoundaries(t *testing.T) {
	base := ReviewInput{RunID: 1, AnalysisRevision: 1, Conclusion: "not_applicable", Explanation: "Bounded human text\n<script>inert text, not rendered markup</script>", IdempotencyKey: "fixed-human-request"}
	if !ValidReviewInput(base) {
		t.Fatal("valid human text rejected")
	}
	for _, bad := range []string{"", strings.Repeat("x", 4097), "\x00", "\r", "\u202Eforged", "\xff"} {
		copy := base
		copy.Explanation = bad
		if ValidReviewInput(copy) {
			t.Fatal("invalid explanation accepted")
		}
	}
	for _, bad := range []string{"approved", "healthy", "<script>", ""} {
		copy := base
		copy.Conclusion = bad
		if ValidReviewInput(copy) {
			t.Fatal("unrecognized human conclusion")
		}
	}
	for _, bad := range []string{"", "short", "value with spaces----", strings.Repeat("x", 129)} {
		copy := base
		copy.IdempotencyKey = bad
		if ValidReviewInput(copy) {
			t.Fatal("invalid retry identity")
		}
	}
}
