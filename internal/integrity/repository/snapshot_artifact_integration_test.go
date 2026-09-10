package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSnapshotArtifactPostgresFailuresCloseView(t *testing.T) {
	for _, mode := range []string{"invalid", "limit", "unsupported", "callback", "incomplete", "consumed", "closed"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
				if cfg.Driver != "postgres" {
					return
				}
				s, initial, _, _ := snapshotArtifactTestFixture(t, cfg)
				want := map[string]error{"invalid": errSnapshotArtifactInvalid, "limit": errSnapshotArtifactLimit,
					"unsupported": errSnapshotArtifactUnsupported, "callback": errSnapshotArtifactCallback,
					"incomplete": errSnapshotArtifactIncomplete, "consumed": errSnapshotArtifactConsumed,
					"closed": errSnapshotArtifactClosed}[mode]
				if mode == "invalid" || mode == "unsupported" {
					column, value := "content_hash", strings.Repeat("0", 64)
					if mode == "unsupported" {
						column, value = "version", ""
					}
					changed := s.db.Table("integrity_rule_bundles").Where("organization_id=?", initial.Organization.ID).Update(column, value)
					if changed.Error != nil || changed.RowsAffected != 1 {
						t.Fatal("install exact retained artifact fault")
					}
				}
				for _, swallow := range []bool{false, true} {
					t.Run(fmt.Sprintf("swallow_%t", swallow), func(t *testing.T) {
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						var retained *postgresSnapshot
						var exported string
						var secondCalled bool
						err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
							retained = view
							inner := view.use(func(tx *gorm.DB, id string, _ postgresSnapshotMetadata) error {
								exported = id
								var copyAfterReturn snapshotArtifactCopy
								sink := func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
									copyAfterReturn = copy
									if mode == "incomplete" {
										return nil
									}
									if err := copy(io.Discard); err != nil {
										return err
									}
									if mode == "consumed" {
										_ = copy(io.Discard)
									} // Swallowed inner error is still fatal.
									if mode == "callback" {
										return errors.New("private-stage-path-canary")
									}
									return nil
								}
								limit := snapshotArtifactMaxEntries
								if mode == "limit" {
									limit = 1
								}
								inventory, readErr := s.snapshotArtifactInventoryLimited(ctx, tx, sink, limit, 1<<20)
								if mode == "closed" {
									if readErr != nil || len(inventory.entries) != 2 || copyAfterReturn == nil {
										t.Fatal("real copy did not finish before late-call test")
									}
									// The reader itself succeeded. Reusing its actual borrowed
									// copy after return must still poison this outer view.
									readErr = copyAfterReturn(snapshotArtifactWriterFunc(func([]byte) (int, error) { t.Error("closed copy accessed a writer"); return 0, nil }))
								} else if inventory.entries != nil {
									t.Error("failed artifact copy returned partial inventory")
								}
								if !errors.Is(readErr, want) || readErr.Error() != want.Error() {
									t.Errorf("wrong actual artifact reader failure: %v", readErr)
								}
								return fmt.Errorf("private-artifact-diagnostic: %w", readErr)
							})
							if !errors.Is(inner, want) || inner.Error() != want.Error() {
								t.Error("view lost exact artifact failure")
							}
							next := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { secondCalled = true; return nil })
							if !errors.Is(next, want) || secondCalled {
								t.Error("failed artifact view ran another consumer")
							}
							if swallow {
								return nil
							}
							return fmt.Errorf("private-consumer-diagnostic: %w", inner)
						})
						if !errors.Is(err, want) || err.Error() != want.Error() {
							t.Errorf("outer view lost artifact class: %v", err)
						}
						postgresSnapshotTestClosed(t, retained)
						postgresSnapshotTestExpired(t, s, exported)
					})
				}
			})
		})
	}
}
