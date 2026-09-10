package repository

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// Extend the existing real PostgreSQL outer lifetime/closed-error test with
// actual key readers and actual twenty-column legacy SQL projection failures.
func snapshotAdditionalInventoryFailureSource(t *testing.T, s *Store, mode string) (func(context.Context, *gorm.DB) error, error) {
	t.Helper()
	if strings.HasPrefix(mode, "key_") {
		tenant, run := snapshotKeyTestFixture(t, s)
		limit := snapshotKeyMaxVersions
		want := errSnapshotKeyInvalid
		switch mode {
		case "key_invalid":
			// Original encrypted DEK still refers to old-secret; the observed
			// scalar must not silently choose a different wrapping dependency.
			snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"key_version": "wrong-wrapper"})
		case "key_limit":
			limit, want = 1, errSnapshotKeyLimit
		case "key_unsupported":
			want = errSnapshotKeyUnsupported
			id, err := NewID()
			if err != nil {
				t.Fatal("allocate isolated unknown-carrier identity")
			}
			snapshotJobTestInsert(t, s, "integrity_gateway_evidence", map[string]any{
				"id": id, "organization_id": tenant.orgID, "run_id": run.ID, "inbound_hash": "a", "outbound_hash": "b",
				"changes_json": "{}", "signature": "legacy-opaque-signature", "created_at": time.Now().UTC()})
		default:
			t.Fatal("unknown key failure fixture")
		}
		return func(ctx context.Context, tx *gorm.DB) error {
			inventory, err := s.snapshotKeyInventoryLimited(ctx, tx, limit)
			if !reflect.DeepEqual(inventory, snapshotKeyInventory{}) {
				t.Error("failed key observation returned partial dependencies or classification")
			}
			return err
		}, want
	}
	row, _ := snapshotLegacyReportFixture(t, s)
	id := row["id"].(int64)
	limit := backupmanifest.MaxFileBytes
	want := errSnapshotLegacyReportInvalid
	switch mode {
	case "legacy_invalid":
		id = math.MaxInt64 // A missing original row must never produce a hash.
	case "legacy_limit":
		limit, want = 1, errSnapshotLegacyReportLimit
	case "legacy_unsupported":
		want = errSnapshotLegacyReportUnsupported
		// This is only the isolated test schema. An implicitly convertible TEXT
		// column is not a native timestamp source for the published row protocol.
		if err := s.db.Exec("ALTER TABLE integrity_reports ALTER COLUMN created_at TYPE TEXT USING created_at::text").Error; err != nil {
			t.Fatal("install isolated unsupported timestamp representation")
		}
	default:
		t.Fatal("unknown legacy failure fixture")
	}
	return func(ctx context.Context, tx *gorm.DB) error {
		descriptor, err := s.snapshotLegacyReportRow(ctx, tx, id, limit)
		if descriptor != (snapshotLegacyReportDescriptor{}) {
			t.Error("failed original-row reader returned a usable identity/hash")
		}
		return err
	}, want
}
