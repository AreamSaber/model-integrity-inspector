package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSnapshotInventoryErrorMappingPreservesClosedClassification(t *testing.T) {
	for _, want := range []error{
		errSnapshotJobSource, errSnapshotJobLimit, errSnapshotJobBusy,
		errSnapshotReportInvalid, errSnapshotReportLimit, errSnapshotReportUnsupported,
		errSnapshotArtifactInvalid, errSnapshotArtifactLimit, errSnapshotArtifactUnsupported,
		errSnapshotArtifactCallback, errSnapshotArtifactIncomplete, errSnapshotArtifactConsumed, errSnapshotArtifactClosed,
	} {
		t.Run(want.Error(), func(t *testing.T) {
			for _, input := range []error{want, fmt.Errorf("private-inventory-diagnostic: %w", want)} {
				if got := postgresSnapshotError(t.Context(), input); !errors.Is(got, want) || got.Error() != want.Error() {
					t.Errorf("snapshot lost exact inventory classification: got %v wanted %v", got, want)
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if got := postgresSnapshotError(ctx, input); !errors.Is(got, errPostgresSnapshotCanceled) || got.Error() != errPostgresSnapshotCanceled.Error() {
					t.Error("ordinary inventory error overrode snapshot cancellation")
				}
			}
		})
	}
	if got := postgresSnapshotError(t.Context(), errors.New("private-inventory-diagnostic")); !errors.Is(got, ErrUnavailable) || got.Error() != ErrUnavailable.Error() {
		t.Fatal("arbitrary inventory diagnostic escaped the closed error boundary")
	}
}

// Failures come from the real inventory readers in a server-exported view,
// not from a fake transaction or an injected callback error alone. The outer
// layer must preserve the closed class even if the consumer wraps or swallows
// it, and PostgreSQL itself must confirm the export is no longer importable.
func TestSnapshotInventoryPostgresOuterFailureIsStickyAndClosesExport(t *testing.T) {
	for _, mode := range []string{"job_source", "job_limit", "job_busy", "report_invalid", "report_limit", "report_unsupported"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				if cfg.Driver != "postgres" {
					return // Each reader's dedicated suite exercises actual SQLite.
				}
				read, want := snapshotInventoryTestFailureSource(t, s, mode)
				for _, swallow := range []bool{false, true} {
					t.Run(fmt.Sprintf("swallowed_%t", swallow), func(t *testing.T) {
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						var retained *postgresSnapshot
						var exported string
						var readAgain bool
						err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
							retained = view
							inner := view.use(func(tx *gorm.DB, id string, _ postgresSnapshotMetadata) error {
								exported = id
								failure := read(ctx, tx)
								if !errors.Is(failure, want) || failure.Error() != want.Error() {
									t.Errorf("real inventory failure has wrong class: %v", failure)
								}
								return fmt.Errorf("private-inventory-diagnostic: %w", failure)
							})
							if !errors.Is(inner, want) || inner.Error() != want.Error() {
								t.Error("snapshot use lost exact inventory classification")
							}
							if next := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error {
								readAgain = true
								return nil
							}); !errors.Is(next, want) || next.Error() != want.Error() || readAgain {
								t.Error("failed snapshot allowed a later consumer")
							}
							if swallow {
								return nil
							}
							return fmt.Errorf("private-consumer-diagnostic: %w", inner)
						})
						if !errors.Is(err, want) || err.Error() != want.Error() {
							t.Errorf("outer snapshot lost exact inventory failure: %v", err)
						}
						postgresSnapshotTestClosed(t, retained)
						postgresSnapshotTestExpired(t, s, exported)
					})
				}
			})
		})
	}
}

func snapshotInventoryTestFailureSource(t *testing.T, s *Store, mode string) (func(context.Context, *gorm.DB) error, error) {
	t.Helper()
	if strings.HasPrefix(mode, "job_") {
		limit := 0
		want := errSnapshotJobSource
		if mode == "job_source" {
			requireMigrate(t, s) // No organization: not a complete initialized set.
		} else {
			initial, tenant, queue := queueFixture(t, s)
			if mode == "job_busy" {
				want = errSnapshotJobBusy
				mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "snapshot-inventory-drain"))
				lease := mustClaim(t, queue)
				expireJob(t, s, lease.Job) // Expired lease is still running, not drained.
			} else {
				want, limit = errSnapshotJobLimit, 1
				other := initial.Organization
				id, err := NewID()
				if err != nil {
					t.Fatal("allocate second inventory organization")
				}
				other.ID, other.Name, other.Status = id, "Disabled inventory organization", "disabled"
				if err := s.db.Create(&other).Error; err != nil {
					t.Fatal("create exact second inventory organization")
				}
			}
		}
		return func(ctx context.Context, tx *gorm.DB) error {
			var inventory snapshotJobInventory
			var err error
			if limit > 0 {
				inventory, err = s.snapshotJobInventoryLimited(ctx, tx, limit)
			} else {
				inventory, err = s.snapshotJobInventory(ctx, tx)
			}
			if inventory.organizations != nil || inventory.classification != snapshotJobUnverified {
				t.Error("failed job inventory returned a usable or partial candidate")
			}
			return err
		}, want
	}
	tenant, queue, run := snapshotReportTestFixture(t, s)
	row := snapshotReportTestPublish(t, tenant, queue, run, "csv", 1)
	want := errSnapshotReportInvalid
	if mode == "report_limit" {
		want = errSnapshotReportLimit
		snapshotReportTestPublish(t, tenant, queue, run, "html", 2)
	} else {
		snapshotReportTestCorruptible(t, s)
		column, value := "file_size", any(*row.FileSize+1)
		if mode == "report_unsupported" {
			want, column, value = errSnapshotReportUnsupported, "source_json", nil
		}
		changed := s.db.Table("integrity_reports").Where("id=?", row.ID).Update(column, value)
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("install exact isolated report-inventory fault")
		}
	}
	return func(ctx context.Context, tx *gorm.DB) error {
		var inventory snapshotReportInventory
		var err error
		if mode == "report_limit" {
			inventory, err = s.snapshotReportInventoryLimited(ctx, tx, 1)
		} else {
			inventory, err = s.snapshotReportInventory(ctx, tx)
		}
		if inventory.entries != nil {
			t.Error("failed report inventory returned a partial candidate")
		}
		return err
	}, want
}
