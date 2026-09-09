package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/migrations"
)

func TestSnapshotMigrationErrorMappingPreservesClosedClassification(t *testing.T) {
	for _, want := range []error{ErrSchemaMismatch, errSnapshotMigrationLimit} {
		for _, input := range []error{want, fmt.Errorf("private-migration-diagnostic: %w", want)} {
			if got := postgresSnapshotError(t.Context(), input); !errors.Is(got, want) || got.Error() != want.Error() {
				t.Fatalf("snapshot lost exact migration classification: got %v wanted %v", got, want)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if got := postgresSnapshotError(ctx, input); !errors.Is(got, errPostgresSnapshotCanceled) || got.Error() != errPostgresSnapshotCanceled.Error() {
				t.Fatal("ordinary migration failure overrode actual snapshot cancellation")
			}
		}
	}
}

func TestSnapshotMigrationPostgresOuterFailureIsStickyAndClosesExport(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return // Actual SQLite inventory is covered by the dedicated suite.
		}
		requireMigrate(t, s)
		expected, err := migrations.ForDialect(cfg.Driver)
		if err != nil || len(expected) < 2 {
			t.Fatal("compiled migration chain unavailable")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		if err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
				inventory, err := s.snapshotMigrationInventory(ctx, tx)
				if err == nil && len(inventory.entries) != len(expected) {
					t.Fatal("real exported view omitted compiled migrations")
				}
				return err
			})
		}); err != nil {
			t.Fatal("valid actual PostgreSQL migration inventory failed")
		}
		for _, cause := range []string{"history_mismatch", "tight_limit"} {
			for _, swallowed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/swallowed_%t", cause, swallowed), func(t *testing.T) {
					want := errSnapshotMigrationLimit
					if cause == "history_mismatch" {
						want = ErrSchemaMismatch
						changed := s.db.Table("schema_migrations").Where("version=1").Update("checksum", strings.Repeat("f", 64))
						if changed.Error != nil || changed.RowsAffected != 1 {
							t.Fatal("install exact isolated migration-history fault")
						}
						t.Cleanup(func() {
							restored := s.db.Table("schema_migrations").Where("version=1").Update("checksum", expected[0].Checksum)
							if restored.Error != nil || restored.RowsAffected != 1 {
								t.Error("restore exact isolated migration checksum")
							}
						})
					}
					var retained *postgresSnapshot
					var exported string
					var readAgain bool
					err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
						retained = view
						inner := view.use(func(tx *gorm.DB, id string, _ postgresSnapshotMetadata) error {
							exported = id
							var inventory snapshotMigrationInventory
							var failure error
							if cause == "tight_limit" {
								inventory, failure = s.snapshotMigrationInventoryLimited(ctx, tx, 1)
							} else {
								inventory, failure = s.snapshotMigrationInventory(ctx, tx)
							}
							if !errors.Is(failure, want) || failure.Error() != want.Error() || inventory.entries != nil {
								t.Error("actual inventory did not fail with a zero-result exact classification")
							}
							return fmt.Errorf("private-migration-diagnostic: %w", failure)
						})
						if !errors.Is(inner, want) || inner.Error() != want.Error() {
							t.Error("use lost closed classification")
						}
						if next := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error {
							readAgain = true
							return nil
						}); !errors.Is(next, want) || next.Error() != want.Error() || readAgain {
							t.Error("failure was swallowed or later inventory ran")
						}
						if swallowed {
							return nil
						}
						return fmt.Errorf("private-consumer-diagnostic: %w", inner)
					})
					if !errors.Is(err, want) || err.Error() != want.Error() {
						t.Errorf("outer snapshot lost exact safe classification: %v", err)
					}
					postgresSnapshotTestClosed(t, retained)
					postgresSnapshotTestExpired(t, s, exported)
				})
			}
		}
	})
}
