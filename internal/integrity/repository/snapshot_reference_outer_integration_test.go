package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestSnapshotArtifactReferencesPureLegacyNativeOrdinal(t *testing.T) {
	row, _ := snapshotReferenceTestPlan(t)
	// The original writer accepts the native nonnegative int range. SQLite
	// INTEGER retains int64; PG's actual INTEGER column has its own int32 cap.
	const maximumSQLiteOrdinal int64 = 9223372036854775807
	raw := snapshotReferenceTestJSON(t, map[string]any{"plan": map[string]any{
		"probes": []any{map[string]any{"template_id": "member", "template_version": "1", "samples": []any{map[string]any{"ordinal": maximumSQLiteOrdinal}}}},
	}})
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil || !got.legacy || len(got.members) != 1 {
		t.Fatal("legal SQLite historical ordinal was rejected", err)
	}
}

func TestSnapshotArtifactReferencesActualLegacyNativeOrdinal(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, plan, policy := executionFixture(t, s, 2)
		maximum := int64(2147483647)
		if cfg.Driver == "sqlite" {
			maximum = 9223372036854775807
		}
		plan.Probes[0].Samples[0].Ordinal = int(maximum)
		run, err := tenant.CreateRun(plan, policy, "reference-original-ordinal")
		if err != nil {
			t.Fatal("original low-level writer rejected the historical fixture", err)
		}
		var saved executionSnapshot
		if json.Unmarshal([]byte(run.ConfigSnapshot), &saved) != nil || int64(saved.Plan.Probes[0].Samples[0].Ordinal) != maximum {
			t.Fatal("original writer changed the ordinal")
		}
		var ordinal int64
		if err := s.db.Model(&LogicalSampleRecord{}).Select("ordinal").Where("organization_id=? AND run_id=? AND execution_ordinal=0", tenant.orgID, run.ID).Scan(&ordinal).Error; err != nil || ordinal != maximum {
			t.Fatal("database did not retain the exact native ordinal", err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.classification != snapshotReferenceLegacyIncomplete || got.observed != [3]int64{1, 0, 0} || got.legacy != [3]int64{1, 0, 0} {
			t.Fatal("legal historical writer data was lost or upgraded")
		}
	})
}

func TestSnapshotArtifactReferencesLastReadRollbackReturnsZero(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, _, _, baselines := snapshotReferenceTestFixture(t, s, nil)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		resultReads := 0
		var rollbackErr error
		if err := tx.Callback().Query().After("gorm:query").Register("reference_last_read_rollback", func(db *gorm.DB) {
			if _, ok := db.Statement.Dest.(*[]struct{ Body []byte }); !ok || !strings.Contains(db.Statement.SQL.String(), "integrity_run_results") {
				return
			}
			resultReads++
			if resultReads == len(baselines) {
				// Every original body has already been read successfully. A prior
				// page-level rollback would be caught by a later body query and
				// would not cover this last-query completion boundary.
				rollbackErr = db.Statement.ConnPool.(*sql.Tx).Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotArtifactReferences(ctx, tx)
		if removeErr := tx.Callback().Query().Remove("reference_last_read_rollback"); removeErr != nil {
			t.Fatal(removeErr)
		}
		if resultReads != len(baselines) || rollbackErr != nil {
			t.Fatal("last successful result read did not trigger actual rollback")
		}
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
			t.Fatal("ended transaction returned a successful root observation", err)
		}
	})
}

// Exercise failures of actual retained source readers inside the exported
// PostgreSQL transaction. The shared outer test checks wrapped/swallowed
// failures, sticky invalidation, and server-side expiration of that export.
func snapshotReferenceInventoryFailureSource(t *testing.T, s *Store, mode string) (func(context.Context, *gorm.DB) error, error) {
	t.Helper()
	_, run, _, _ := snapshotReferenceTestFixture(t, s, nil)
	limit := snapshotReferenceLimit
	want := errSnapshotReferenceInvalid
	changes := map[string]any{}
	switch mode {
	case "reference_invalid":
		changes["manifest_hash"] = strings.Repeat("f", 64)
	case "reference_limit":
		// This fixture has four bundle roots plus one distinct template member.
		limit, want = 4, errSnapshotReferenceLimit
	case "reference_unsupported":
		want = errSnapshotReferenceUnsupported
		var row snapshotReferenceRow
		raw := snapshotReferenceTestMutation(t, []byte(run.ConfigSnapshot), &row, func(_, manifest map[string]any) {
			manifest["generator_version"] = "9.9.9"
		})
		// Keep both hashes consistent with the original mutated manifest so
		// this reaches the unsupported codec rather than hash corruption.
		changes["config_snapshot"], changes["manifest_hash"] = string(raw), row.ManifestHash
	default:
		t.Fatal("unknown reference failure fixture")
	}
	if len(changes) > 0 {
		changed := s.db.Table("integrity_runs").Where("organization_id=? AND id=?", run.OrganizationID, run.ID).Updates(changes)
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("install exact isolated artifact-reference fault")
		}
	}
	return func(ctx context.Context, tx *gorm.DB) error {
		inventory, err := s.snapshotArtifactReferencesLimited(ctx, tx, limit)
		if !reflect.DeepEqual(inventory, snapshotArtifactReferences{}) {
			t.Error("failed reference observation returned partial roots or classification")
		}
		return err
	}, want
}
