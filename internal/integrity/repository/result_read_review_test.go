package repository

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"
)

// Read-boundary self-checks, not a production evidence/accuracy acceptance run.
func TestResultReadReviewSnapshotDoesNotBlockWriters(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		tenant, _, run, _, _ := analysisReadyFixture(t, store, 1)
		readPermissions(t, tenant)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		if cfg.Driver == "sqlite" {
			// This is only the second connection to this isolated test database.
			// A short busy timeout keeps the regression deterministic/bounded.
			if err := other.db.Exec("PRAGMA busy_timeout=150").Error; err != nil {
				t.Fatal(err)
			}
		}
		var first, second int64
		var writerErr error
		readErr := tenant.resultReadTransaction(false, func(tx *gorm.DB) error {
			query := func(out *int64) error {
				return tx.Model(&RunRecord{}).Select("version").Where("organization_id=? AND id=?", tenant.orgID, run.ID).Scan(out).Error
			}
			if err := query(&first); err != nil {
				return err
			}
			// A Worker update and permission revocation commit on another real
			// connection between this read's SELECTs. The open read must neither
			// block that writer nor assemble fields from two different snapshots.
			writerErr = other.db.WithContext(t.Context()).Transaction(func(write *gorm.DB) error {
				if err := write.Model(&RunRecord{}).Where("organization_id=? AND id=?", tenant.orgID, run.ID).Update("version", gorm.Expr("version+1")).Error; err != nil {
					return err
				}
				return write.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, "run.read").Error
			})
			if err := query(&second); err != nil {
				return err
			}
			return nil
		})
		if readErr != nil {
			t.Fatal("read transaction failed", readErr)
		}
		if writerErr != nil {
			t.Error("read transaction acquired a writer-blocking lock")
		}
		if first != run.Version || second != first {
			t.Errorf("read mixed committed snapshots: before=%d after=%d", first, second)
		}
		if writerErr == nil {
			if _, err := tenant.ListRunHistory(ListOptions{Limit: 1}, RunFilters{}); !errors.Is(err, ErrManagementPermission) {
				t.Fatal("next read retained authority after committed revocation")
			}
		}
	})
}

func TestResultReadReviewLimitsTextBeforeTransfer(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, run, _, _ := analysisReadyFixture(t, store, 1)
		readPermissions(t, tenant)
		large := strings.Repeat("x", 1<<20)
		for _, field := range []string{"manifest_hash", "rule_bundle_version"} {
			t.Run(field, func(t *testing.T) {
				if err := store.db.Model(&RunRecord{}).Where("organization_id=? AND id=?", tenant.orgID, run.ID).Update(field, large).Error; err != nil {
					t.Fatal(err)
				}
				rows, err := tenant.ListRunHistory(ListOptions{Limit: 1}, RunFilters{})
				if err != nil && !errors.Is(err, ErrResultDocument) {
					t.Fatal("unexpected bounds error", err)
				}
				if err == nil && (len(rows) != 1 || len(rows[0].ManifestHash) > 64 || len(rows[0].RuleBundleVersion) > 128) {
					t.Error("history transferred unbounded TEXT before DTO validation")
				}
				original := run.ManifestHash
				if field == "rule_bundle_version" {
					original = run.RuleBundleVersion
				}
				if err := store.db.Model(&RunRecord{}).Where("organization_id=? AND id=?", tenant.orgID, run.ID).Update(field, original).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func TestResultReadReviewHistoryCursorSurvivesAnchorStatusChange(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		readPermissions(t, tenant)
		for _, key := range []string{"cursor-review-a", "cursor-review-b", "cursor-review-c"} {
			if _, err := tenant.CreateRun(plan, policy, key); err != nil {
				t.Fatal(err)
			}
		}
		filter := RunFilters{Status: "QUEUED"}
		first, err := tenant.ListRunHistory(ListOptions{Limit: 1}, filter)
		if err != nil || len(first) != 1 {
			t.Fatal("initial page unavailable", err)
		}
		anchor := first[0]
		if _, err := tenant.CancelRun(anchor.ID, anchor.Version); err != nil {
			t.Fatal("ordinary state transition failed", err)
		}
		// The cursor was issued for this org/filter. A routine state transition
		// should not destroy its immutable created_at/id ordering boundary.
		next, err := tenant.ListRunHistory(ListOptions{AfterID: anchor.ID, Limit: 1}, filter)
		if err != nil || len(next) != 1 || next[0].ID == anchor.ID {
			t.Fatal("normal anchor state change invalidated remaining matching page", err)
		}
	})
}
