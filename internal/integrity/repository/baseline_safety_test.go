package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestBaselineRepositoryPrivateDiagnostics(t *testing.T) {
	marker := "PRIVATE-BASELINE-REVIEW-CANARY"
	r := BaselineRecord{ReviewExplanation: marker, RetirementReason: marker, SnapshotJSON: marker}
	a := BaselineApproval{Reason: marker, BusinessReview: marker}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	for _, value := range []any{r, &r, a, &a, &BaselineSource{result: PublishedRead{Result: RunResultRecord{ConclusionJSON: marker}}}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), marker) {
				t.Fatal("private value formatted")
			}
		}
		logger.Info("synthetic diagnostics", "value", value)
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatal("private value logged")
	}
	data, err := json.Marshal(a)
	if err != nil || bytes.Contains(data, []byte(marker)) {
		t.Fatal("private approval serialized", err)
	}
	// Redaction must never weaken the separate canonical signing frame.
	canonical, err := baselineCanonical(r)
	if err != nil || !bytes.Contains(canonical, []byte(marker)) {
		t.Fatal("review notes lost canonical MAC binding", err)
	}
}

func TestBaselineRepositoryReadSnapshotAllowsWriters(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		repo, tenant, source, scope, _ := baselineRepositoryFixture(t, store)
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		if cfg.Driver == "sqlite" {
			if err := other.db.Exec("PRAGMA busy_timeout=150").Error; err != nil {
				t.Fatal(err)
			}
		}
		var first, second int64
		err = repo.read(tenant, false, func(tx *gorm.DB) error {
			query := func(out *int64) error {
				return tx.Model(&RunRecord{}).Select("version").Where("organization_id=? AND id=?", tenant.orgID, source.runID).Scan(out).Error
			}
			if err := query(&first); err != nil {
				return err
			}
			// The other connection must commit while the read stays on its
			// initial snapshot, including authorization, in both actual engines.
			if err := other.db.WithContext(t.Context()).Transaction(func(write *gorm.DB) error {
				if err := write.Model(&RunRecord{}).Where("organization_id=? AND id=?", tenant.orgID, source.runID).Update("version", gorm.Expr("version+1")).Error; err != nil {
					return err
				}
				return write.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='baseline.read'", tenant.orgID).Error
			}); err != nil {
				return err
			}
			return query(&second)
		})
		if err != nil || first != source.runVersion || second != first {
			t.Fatal("read blocked writer or mixed snapshots", first, second, err)
		}
		if _, err := repo.Get(tenant.ctx, tenant.orgID, r.ID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("next read retained revoked grant", err)
		}
	})
}

func TestBaselineRepositoryReadCancellationReleasesTransaction(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		repo, tenant, source, scope, _ := baselineRepositoryFixture(t, store)
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(tenant.ctx)
		defer cancel()
		cancelled, err := repo.tenant(ctx, tenant.orgID)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.read(cancelled, false, func(_ *gorm.DB) error {
			cancel()
			return ctx.Err()
		}); err == nil {
			t.Fatal("cancelled read succeeded")
		}
		if _, err := repo.Get(tenant.ctx, tenant.orgID, r.ID); err != nil {
			t.Fatal("cancelled read left transaction open", err)
		}
		name := "write after cancelled read"
		if _, err := repo.Update(tenant.ctx, tenant.orgID, r.ID, 1, &name, nil); err != nil {
			t.Fatal("cancelled read retained lock", err)
		}
	})
}

func TestBaselineRepositoryExpiryAndExplicitRiskReview(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		repo, tenant, source, scope, _ := baselineRepositoryFixture(t, store)
		// Repository policy fixture only: service integration derives this
		// value from the real validated analysis, never from an HTTP risk field.
		risk := 50.0
		scope.OverallRisk = &risk
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, baselineApproval(1)); !errors.Is(err, ErrBaselineInvalid) {
			t.Fatal("risk review omitted", err)
		}
		input := baselineApproval(1)
		input.BusinessReview = "Synthetic elevated-risk reference is knowingly retained for business comparison"
		approved, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, input)
		if err != nil || approved.Status != "approved" || approved.ReviewExplanation != input.Reason+"\n"+input.BusinessReview {
			t.Fatal("explicit risk review not preserved", err)
		}
		r, err = repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		// Advance this signed fixture's expiration without a wall-clock sleep.
		// An unsigned timestamp change is independently rejected by MAC checks.
		r.ExpiresAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		if err := repo.seal(&r); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Session(&gorm.Session{SkipHooks: true}).Model(&BaselineRecord{}).Where("id=?", r.ID).Select("*").Updates(&r).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, input); !errors.Is(err, ErrBaselineExpired) {
			t.Fatal("expired source approved", err)
		}
		rows, err := repo.List(tenant.ctx, tenant.orgID, BaselineList{Limit: 10, Status: "expired"})
		if err != nil || len(rows) != 1 || rows[0].ID != r.ID {
			t.Fatal("expired status filter", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}
